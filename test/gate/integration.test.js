// test/gate/integration.test.js — THE KEYSTONE.
// First-contact end-to-end proof + the adversarial cases that earn the security claim
// (DESIGN §3 protocol, D2/D4 gate, D5 Noise IK). Coded against docs/INTERFACES.md, driving
// the REAL lower modules (key.js, noise.js, wire.js, transport.js). node.js (lane-wire) is
// not landed yet — the public-API e2e below auto-lights when src/node.js appears (disk poll).
//
// The chain under test, exactly as the mission headline states it:
//   B decodes A's 26-char key -> (rendezvous) -> transport.punch -> A's HELLO (full pubkeys)
//   -> COMMITMENT GATE -> Noise IK (msg1 e,es,s,ss / msg2 e,ee,se) -> decrypt(msg2) = THE
//   FIRST ACK == provably no MITM -> wire channel -> exact-bytes message both directions.
//
// Security claim proven by construction: an attacker who knows A's PUBLIC string but not A's
// X25519 STATIC PRIVATE key cannot produce the first ack. That is the whole ballgame.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

import { generateIdentity, decodeKey, verifyCommitment } from '../../src/key.js';
import { initiator, responder, HandshakeError } from '../../src/noise.js';
import { createChannel } from '../../src/wire.js';
import { createEndpoint } from '../../src/transport.js';

// ---- pre-wire message framing (HELLO / HS1 / HS2 ride raw datagrams; DATA rides wire) ----
const T = { HELLO: 0x10, HS1: 0x11, HS2: 0x12 };
const helloPkt = (id) => Buffer.concat([Buffer.from([T.HELLO, 0 /*version*/]), id.edPub, id.xPub]);
const parseHello = (b) => ({ version: b[1], edPub: b.subarray(2, 34), xPub: b.subarray(34, 66) });
const tag = (t, body) => Buffer.concat([Buffer.from([t]), body]);

// In-memory socketLike pair (deterministic; stands in for a punched transport). Mimics the
// transport contract: .send(buf) / .onMessage(cb) / .close(). Async delivery via microtask.
function memPair() {
  let ca = null, cb = null, open = true;
  const mk = (getPeerCb) => ({
    send: (buf) => { if (open) { const copy = Buffer.from(buf); queueMicrotask(() => open && getPeerCb() && getPeerCb()(copy, { address: 'mem', port: 0, family: 'IPv4' })); } },
    onMessage: (cb2) => { /* set below */ },
    close: () => { open = false; },
  });
  const a = { proto: 'mem', send: (buf) => { const c = Buffer.from(buf); queueMicrotask(() => open && cb && cb(c, { address: 'B', port: 0, family: 'IPv4' })); }, onMessage: (fn) => { ca = fn; }, close: () => { open = false; } };
  const b = { proto: 'mem', send: (buf) => { const c = Buffer.from(buf); queueMicrotask(() => open && ca && ca(c, { address: 'A', port: 0, family: 'IPv4' })); }, onMessage: (fn) => { cb = fn; }, close: () => { open = false; } };
  return [a, b];
}

/**
 * Drive one first-contact attempt over two socketLikes and report exactly what happened.
 * @param {object} o
 *   sockL, sockD          listener + dialer transports (socketLike)
 *   S                     the 26-char string the DIALER trusts (A's, or a wrong one for adv2)
 *   listenerId            identity the LISTENER actually runs (real A, or a doctored attacker)
 *   dialerId              dialer identity
 *   tamperHelloXPub       flip a byte in the HELLO xPub after gate-relevant encoding (adv1)
 * @returns {Promise<{gate:boolean|null, firstAck:boolean, ackBytes?:Buffer, error?:string,
 *                     send:(pt)=>void, recv:Promise<Buffer>, stop:()=>void}>}
 */
function firstContact(o) {
  const { sockL, sockD, S, listenerId, dialerId, tamperHelloXPub = false, timeout = 1500 } = o;
  return new Promise((resolve) => {
    const result = { gate: null, firstAck: false };
    let settled = false, aWire = null, bWire = null, ticker = null;
    let recvResolveL, recvResolveD;
    const recvL = new Promise((r) => (recvResolveL = r)); // listener receives dialer's msg
    const recvD = new Promise((r) => (recvResolveD = r)); // dialer receives listener's msg
    const stop = () => { clearInterval(ticker); try { aWire?.close(); bWire?.close(); } catch { /**/ } try { sockL.close(); sockD.close(); } catch { /**/ } };
    const settle = () => { if (settled) return; settled = true; resolve({ ...result, ackBytes: result.ackBytes, recvL, recvD, sendD: (pt) => bWire?.send(pt), sendL: (pt) => aWire?.send(pt), stop }); };
    const to = setTimeout(settle, timeout);

    // --- Noise handshake state ---
    let commitment;
    try { commitment = decodeKey(S).commitment; } // checksum-validated locally (typo guard)
    catch (e) { result.gate = false; result.error = 'TypoError: ' + e.message; clearTimeout(to); return settle(); }

    const hsB = initiator({ localX: { pub: dialerId.xPub, priv: dialerId.xPriv }, remoteXPub: null }); // remoteXPub set after HELLO
    let hsA = null;

    const attachWire = (sock, split, onPlain, dir) => {
      const connId = split.handshakeHash.subarray(0, 8); // both sides derive the SAME id
      const ch = createChannel({ send: (frame) => sock.send(frame), connId });
      ch.onReliable((ct) => { try { onPlain(split.rx.decrypt(ct)); } catch { /* AEAD fail = drop */ } });
      sock.onMessage((buf) => ch.onDatagram(buf, { address: dir, port: 0, family: 'IPv4' }));
      return { ch, send: (pt) => ch.sendReliable(split.tx.encrypt(pt)), close: () => ch.close() };
    };

    // --- LISTENER (A): send HELLO, answer HS1 with HS2 (the ack), then go to wire ---
    sockL.onMessage((buf) => {
      try {
        if (buf[0] === T.HS1) {
          hsA = responder({ localX: { pub: listenerId.xPub, priv: listenerId.xPriv } });
          hsA.readMessage(buf.subarray(1)); // learns B static (TOFU); throws if MITM lacks A's key
          const hs2 = hsA.writeMessage(Buffer.from('ack')); // msg2 payload = the ack
          sockL.send(tag(T.HS2, hs2));
          const split = hsA.split();
          aWire = attachWire(sockL, split, (pt) => recvResolveL(pt), 'B');
        }
      } catch (e) { result.error = 'listener: ' + e.message; /* dialer will time out with no ack */ }
    });

    // --- DIALER (B): gate A's HELLO, run IK, decrypt(msg2) = first ack ---
    sockD.onMessage((buf) => {
      try {
        if (buf[0] === T.HELLO) {
          const h = parseHello(buf);
          result.gate = verifyCommitment(commitment, h.edPub, h.xPub);
          if (!result.gate) { clearTimeout(to); return settle(); } // DROP — no session (headline gate)
          // gate passed -> initiate IK pinning A's advertised static
          const hs1 = initiator({ localX: { pub: dialerId.xPub, priv: dialerId.xPriv }, remoteXPub: Buffer.from(h.xPub) });
          firstContact._hsB = hs1; // keep alive
          const m1 = hs1.writeMessage(Buffer.alloc(0));
          sockD._hs1 = hs1;
          sockD.send(tag(T.HS1, m1));
        } else if (buf[0] === T.HS2) {
          const ack = sockD._hs1.readMessage(buf.subarray(1)); // SUCCESS == provably no MITM
          result.firstAck = true; result.ackBytes = ack;
          const split = sockD._hs1.split();
          bWire = attachWire(sockD, split, (pt) => recvResolveD(pt), 'A');
          clearTimeout(to); settle();
        }
      } catch (e) { result.error = 'dialer: ' + e.message; result.firstAck = false; }
    });

    ticker = setInterval(() => { aWire?.ch.tick(Date.now()); bWire?.ch.tick(Date.now()); }, 40);
    ticker.unref?.();

    // kick off: A announces itself (HELLO carries full pubkeys; optionally tampered for adv1)
    const hello = helloPkt(listenerId);
    if (tamperHelloXPub) hello[34] ^= 0xff; // corrupt first xPub byte -> commitment gate must catch it
    queueMicrotask(() => sockL.send(hello));
  });
}

// ============================ HAPPY PATH ============================

test('e2e first-contact over IN-MEMORY transport: gate + first-ack + exact bytes both ways', async () => {
  const A = generateIdentity();
  const B = generateIdentity();
  const [sL, sD] = memPair();
  const r = await firstContact({ sockL: sL, sockD: sD, S: A.S, listenerId: A, dialerId: B });

  assert.equal(r.gate, true, 'commitment gate must accept A\'s real pubkeys');
  assert.equal(r.firstAck, true, 'msg2 must decrypt = the first ack = MITM-free proof');
  assert.equal(r.ackBytes.toString(), 'ack', 'the ack payload the owner specified');

  const msgBtoA = Buffer.from('marco 🎯');
  const msgAtoB = Buffer.from('polo ✅');
  r.sendD(msgBtoA);
  r.sendL(msgAtoB);
  const [gotAtL, gotBatD] = await Promise.all([r.recvL, r.recvD]);
  assert.deepEqual(gotAtL, msgBtoA, 'listener received dialer bytes EXACTLY (E2E encrypted)');
  assert.deepEqual(gotBatD, msgAtoB, 'dialer received listener bytes EXACTLY (E2E encrypted)');
  r.stop();
});

test('e2e first-contact over REAL transport.punch (loopback): full stack incl. NAT machinery', async () => {
  const A = generateIdentity();
  const B = generateIdentity();
  const epL = await createEndpoint({});
  const epD = await createEndpoint({});
  const token = 'gate-e2e';
  // in-process rendezvous: hand each side the other's loopback candidate (candidates() skips
  // internal addrs). Real DHT/mDNS/tracker resolve is the rendezvous lane; punch is real.
  const [sL, sD] = await Promise.all([
    epL.punch([{ proto: 'udp4', ip: '127.0.0.1', port: epD.port4, kind: 'host' }], { token, timeout: 4000 }),
    epD.punch([{ proto: 'udp4', ip: '127.0.0.1', port: epL.port4, kind: 'host' }], { token, timeout: 4000 }),
  ]);
  assert.equal(sL.proto, 'udp4');

  const r = await firstContact({ sockL: sL, sockD: sD, S: A.S, listenerId: A, dialerId: B, timeout: 4000 });
  assert.equal(r.gate, true);
  assert.equal(r.firstAck, true, 'first ack over real punched UDP path');

  const ping = Buffer.from('over-the-wire');
  r.sendD(ping);
  const got = await r.recvL;
  assert.deepEqual(got, ping, 'exact bytes across real transport + wire ARQ');
  r.stop(); epL.close(); epD.close();
});

// ============================ ADVERSARIAL (the claim) ============================

test('adversarial #1 — TAMPERED pubkey in HELLO: commitment gate DROPS, no handshake', async () => {
  const A = generateIdentity();
  const B = generateIdentity();
  const [sL, sD] = memPair();
  const r = await firstContact({ sockL: sL, sockD: sD, S: A.S, listenerId: A, dialerId: B, tamperHelloXPub: true, timeout: 800 });
  assert.equal(r.gate, false, 'a flipped xPub byte fails first110(SHA256(...)) == commitment');
  assert.equal(r.firstAck, false, 'gate drop => zero Noise, zero session');
  r.stop();
});

test('adversarial #2 — WRONG key entirely: connect fails at the gate, zero handshake', async () => {
  const A = generateIdentity();
  const B = generateIdentity();
  const C = generateIdentity(); // dialer trusts C's string but is actually talking to A
  const [sL, sD] = memPair();
  const r = await firstContact({ sockL: sL, sockD: sD, S: C.S, listenerId: A, dialerId: B, timeout: 800 });
  assert.equal(r.gate, false, 'A\'s real pubkeys do not match C\'s commitment');
  assert.equal(r.firstAck, false);
  r.stop();
});

test('adversarial #3 — MITM: attacker has A\'s PUBLIC string but not A\'s static PRIVATE key => NO first ack', async () => {
  const A = generateIdentity();
  const B = generateIdentity();
  const M = generateIdentity();
  // Mallory impersonates A: advertises A's REAL pubkeys (so the gate PASSES) but can only run
  // Noise with her OWN x25519 private key. IK msg1's es/ss bind A's static — Mallory's key
  // can't decrypt them. This is the owner's headline claim, proven.
  const attacker = { edPub: A.edPub, xPub: A.xPub, edPriv: M.edPriv, xPriv: M.xPriv };
  const [sL, sD] = memPair();
  const r = await firstContact({ sockL: sL, sockD: sD, S: A.S, listenerId: attacker, dialerId: B, timeout: 1000 });
  assert.equal(r.gate, true, 'gate PASSES — Mallory relayed A\'s genuine public keys');
  assert.equal(r.firstAck, false, 'but msg2 never validates: no A private key => no key confirmation => no MITM');
  r.stop();
});

// ============================ PUBLIC API (auto-lights when node.js lands) ============================

test('e2e via public node.js API (node.listen / node.connect)', { skip: !existsSync(new URL('../../src/node.js', import.meta.url)) }, async () => {
  const { default: mod } = await import('../../src/node.js').then((m) => ({ default: m })).catch(() => ({ default: null }));
  assert.ok(mod, 'src/node.js present but not importable');
  // Contract (docs/INTERFACES.md): identity() / listen(identity,opts) -> node ; node.connect(S) -> peer
  // peer.send(data) -> Promise<ack> ; node.on('peer'|'message'|'ack'|'disconnect'|'divergence')
  const A = mod.identity ? mod.identity() : generateIdentity();
  const nodeA = await mod.listen(A, {});
  const gotMsg = new Promise((res) => nodeA.on('message', (m) => res(m)));
  const nodeB = await mod.listen(mod.identity ? mod.identity() : generateIdentity(), {});
  const peer = await nodeB.connect(A.S);
  const payload = Buffer.from('node-api-e2e');
  await peer.send(payload);
  const got = await gotMsg;
  assert.deepEqual(Buffer.from(got.data ?? got), payload);
  await nodeA.close?.(); await nodeB.close?.();
});
