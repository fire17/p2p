#!/usr/bin/env node
// P0 spike gate (a) — STUN + UDP hole-punch choreography between two real endpoints.
// Proves: candidate gathering (host/LAN + optional STUN srflx), ICE-lite probe/ack punch,
// bidirectional data over the returned socketLike. Real cross-NAT is task 8; on one host /
// LAN this exercises the full machinery (no NAT to cross, so it validates choreography).
//
// Rendezvous is a shared JSON file (stands in for the rendezvous lane): each role writes its
// own candidates, waits for the peer's, then both punch simultaneously.
//
//   Terminal 1:  node spikes/punch-spike.js --role a --rv /tmp/p2p-spike.json [--stun]
//   Terminal 2:  node spikes/punch-spike.js --role b --rv /tmp/p2p-spike.json [--stun]
//
// Exit 0 = both directions delivered (PASS). Exit 1 = timeout/failure.

import fs from 'node:fs';
import { createEndpoint } from '../src/transport.js';

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

const role = arg('role');
const rv = arg('rv', '/tmp/p2p-spike.json');
const useStun = !!arg('stun', false);
const token = String(arg('token', 'p2p-spike-token'));
const peer = role === 'a' ? 'b' : 'a';
if (role !== 'a' && role !== 'b') { console.error('need --role a|b'); process.exit(2); }

const log = (...m) => console.log(`[${role}]`, ...m);

function readRv() { try { return JSON.parse(fs.readFileSync(rv, 'utf8')); } catch { return {}; } }
function writeMine(cands) {
  // best-effort merge (two processes writing one file — small race, retried by pollers)
  const cur = readRv();
  cur[role] = cands;
  fs.writeFileSync(rv, JSON.stringify(cur));
}

async function waitPeer(timeoutMs = 15000) {
  const t0 = Date.now();
  for (;;) {
    const cur = readRv();
    if (cur[peer]?.length) return cur[peer];
    if (Date.now() - t0 > timeoutMs) throw new Error('peer candidates never appeared');
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function main() {
  if (role === 'a') { try { fs.unlinkSync(rv); } catch { /* fresh */ } }

  const ep = await createEndpoint({});
  log('bound udp4', ep.port4, 'udp6', ep.port6);

  if (useStun) {
    try { const s = await ep.stun(); log('STUN srflx', `${s.ip}:${s.port}`); }
    catch (e) { log('STUN failed (continuing with host/LAN):', e.message); }
  }

  const mine = ep.candidates();
  log('candidates', JSON.stringify(mine));
  writeMine(mine);

  const peerCands = await waitPeer();
  log('peer candidates', JSON.stringify(peerCands));

  const t0 = Date.now();
  const sock = await ep.punch(peerCands, { token, timeout: 12000 });
  log(`PUNCHED via ${sock.proto} ${sock.remote.address}:${sock.remote.port} in ${Date.now() - t0}ms`);

  let gotPeer = false;
  sock.onMessage((buf) => {
    const s = buf.toString();
    log('recv:', s);
    if (s.startsWith('hello-from-')) gotPeer = true;
  });

  // send a few times (UDP is lossy); succeed once both directions confirmed.
  const done = new Promise((resolve, reject) => {
    const iv = setInterval(() => sock.send(Buffer.from(`hello-from-${role}`)), 200);
    const check = setInterval(() => { if (gotPeer) { clearInterval(iv); clearInterval(check); clearTimeout(to); resolve(); } }, 100);
    const to = setTimeout(() => { clearInterval(iv); clearInterval(check); reject(new Error('no peer data within 8s')); }, 8000);
  });

  await done;
  log('PASS — bidirectional data confirmed');
  sock.close(); ep.close();
  if (role === 'a') { try { fs.unlinkSync(rv); } catch { /* ignore */ } }
  process.exit(0);
}

main().catch((e) => { log('FAIL:', e.message); process.exit(1); });
