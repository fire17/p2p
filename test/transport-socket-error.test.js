// test/transport-socket-error.test.js — SOCKERR-1: a UDP endpoint survives a dgram 'error'.
//
// The defect (Debian VPS, Bun 1.4.2, 2026-09-13): the join daemon died at startup with
//   `error: recvmsg ENETUNREACH at emitError (node:events:50:13) at error (node:dgram:406:90)`.
// createEndpoint() bound udp6 + udp4 and never installed an 'error' listener on either socket
// (bindSock's once('error') is removed on bind success; _attach() registers only 'message'), so a
// post-bind socket error was an UNHANDLED EventEmitter 'error' — process death. Node hid the same
// broken-v6 condition because _sendRaw() called send() with no callback and node drops send errors
// silently there.
//
// These tests EXECUTE the rule (they emit the real event); they do not grep for a handler.
// Zero network beyond 127.0.0.1. Every endpoint is closed in a finally so a FAILING leg still
// drains the event loop (an un-closed dgram socket keeps `node --test` alive forever).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createEndpoint } from '../src/transport.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, 'fixtures', 'udp-error-survive.mjs');

const netErr = (msg = 'recvmsg ENETUNREACH') =>
  Object.assign(new Error(msg), { code: 'ENETUNREACH', syscall: 'recvmsg' });

const shut = (...eps) => { for (const e of eps) { try { e?.close(); } catch { /* ignore */ } } };

/** One loopback datagram each way between two endpoints (pattern of transport.test.js:78-100). */
async function loopbackPunch(a, b) {
  const token = 'sockerr';
  const [sa, sb] = await Promise.all([
    a.punch([{ proto: 'udp4', ip: '127.0.0.1', port: b.port4, kind: 'host' }], { token, timeout: 6000 }),
    b.punch([{ proto: 'udp4', ip: '127.0.0.1', port: a.port4, kind: 'host' }], { token, timeout: 6000 }),
  ]);
  const gotA = new Promise((res) => { sa.onMessage = (m) => m.toString() === 'ping-b' && res(); });
  const gotB = new Promise((res) => { sb.onMessage = (m) => m.toString() === 'ping-a' && res(); });
  const iv = setInterval(() => { sa.send(Buffer.from('ping-a')); sb.send(Buffer.from('ping-b')); }, 100);
  try { await Promise.all([gotA, gotB]); } finally { clearInterval(iv); sa.close(); sb.close(); }
  return [sa.proto, sb.proto];
}

// (a) udp6 'error' -> that family is dropped, the endpoint keeps working on udp4.
test('SOCKERR-1 (a): a udp6 socket error drops udp6 and keeps udp4 usable', async () => {
  const ep = await createEndpoint({});
  let other = null;
  try {
    if (!ep.sock6) { console.error('SKIP (a): this box bound no udp6 socket'); return; }
    const port4 = ep.port4;
    const events = [];
    ep.on('socketerror', (e) => events.push(e));

    ep.sock6.emit('error', netErr());

    assert.equal(ep.sock6, null, 'sock6 dropped');
    assert.equal(ep.port6, 0, 'port6 zeroed');
    assert.equal(ep.port, ep.port4, 'port follows the surviving family');
    assert.equal(ep.port4, port4, 'udp4 port untouched');
    assert.ok(ep.sock4, 'udp4 survives');
    assert.equal(events.length, 1, 'one socketerror event');
    assert.equal(events[0].family, 6);
    assert.equal(events[0].error.code, 'ENETUNREACH');
    assert.ok(!ep.candidates().some((c) => c.proto === 'udp6'), 'no udp6 candidate advertised');
    assert.deepEqual(ep.stats(), { sendErrs: { 4: 0, 6: 0 }, sock4: true, sock6: false });

    // and the endpoint still really punches + carries a datagram over udp4
    other = await createEndpoint({});
    const [pa, pb] = await loopbackPunch(ep, other);
    assert.equal(pa, 'udp4');
    assert.equal(pb, 'udp4');
  } finally { shut(ep, other); }
});

// (b) udp4 'error' -> STUN refuses cleanly, no udp4 candidate, close() stays safe.
test('SOCKERR-1 (b): a udp4 socket error drops udp4; stun() rejects instead of crashing', async () => {
  const ep = await createEndpoint({});
  try {
    if (!ep.sock4) { console.error('SKIP (b): this box bound no udp4 socket'); return; }
    ep.sock4.emit('error', netErr('sendto ENETUNREACH'));

    assert.equal(ep.sock4, null, 'sock4 dropped');
    assert.equal(ep.port4, 0, 'port4 zeroed');
    assert.equal(ep.port, ep.port6, 'port falls back to udp6');
    await assert.rejects(ep.stun({ servers: [{ host: '127.0.0.1', port: 1 }], timeout: 200 }), /udp4/);
    assert.ok(!ep.candidates().some((c) => c.proto === 'udp4'), 'no udp4 candidate advertised');
    assert.equal(ep.stats().sock4, false);
  } finally { shut(ep); } // must not throw on an already-closed family
});

// (c) both families dead -> punch REJECTS, never crashes.
test('SOCKERR-1 (c): both sockets errored -> punch rejects with an Error, process lives', async () => {
  const ep = await createEndpoint({});
  try {
    if (ep.sock6) ep.sock6.emit('error', netErr());
    if (ep.sock4) ep.sock4.emit('error', netErr());
    const st = ep.stats();
    assert.equal(st.sock4, false);
    assert.equal(st.sock6, false);
    await assert.rejects(
      ep.punch([{ proto: 'udp4', ip: '127.0.0.1', port: 1 }], { token: 'dead', timeout: 300 }),
      (e) => e instanceof Error,
    );
  } finally { shut(ep); }
});

// (d) clean case: no error emitted -> candidates() and a loopback punch behave exactly as before.
// Asserts NOTHING the patch adds, so it is green on base too — a leg that cannot pass on base
// cannot tell a regression from the patch's own additions.
test('SOCKERR-1 (d): clean case — an untouched endpoint punches and advertises as before', async () => {
  const a = await createEndpoint({});
  const b = await createEndpoint({});
  try {
    for (const c of a.candidates()) assert.ok(['udp4', 'udp6', 'tcp'].includes(c.proto));
    const [pa, pb] = await loopbackPunch(a, b);
    assert.equal(pa, 'udp4');
    assert.equal(pb, 'udp4');
  } finally { shut(a, b); }
});

// (e) RUNTIME leg: the same event in a real child process, under node AND under bun.
test('SOCKERR-1 (e): a child process survives the socket error under node', () => {
  const r = spawnSync(process.execPath, [FIXTURE], { encoding: 'utf8' });
  assert.equal(r.status, 0, 'node child exited 0; stderr=' + r.stderr);
  assert.match(r.stderr, /socket error/);
});

// A real node:test skip (counted in `skipped`, never in `pass`) — a bun leg that did not run must
// never be reported as a passing bun leg.
test('SOCKERR-1 (e-bun): a child process survives the socket error under bun', {
  skip: process.env.P2P_TEST_BUN ? false : 'set P2P_TEST_BUN=<path to bun> to run the bun runtime leg',
}, () => {
  const bun = process.env.P2P_TEST_BUN;
  const r = spawnSync(bun, ['run', FIXTURE], { encoding: 'utf8' });
  assert.equal(r.status, 0, 'bun child exited 0; stderr=' + r.stderr);
  assert.match(r.stderr, /socket error/);
});

// (f) send errors are COUNTED and LOGGED — and never kill the family.
test('SOCKERR-1 (f): a send error is counted, the socket survives', async () => {
  const ep = await createEndpoint({});
  try {
    if (!ep.sock4) { console.error('SKIP (f): this box bound no udp4 socket'); return; }
    ep.sock4.send = (buf, port, ip, cb) => cb(Object.assign(new Error('sendto ENETUNREACH'), { code: 'ENETUNREACH' }));
    ep._sendRaw(Buffer.from('x'), '10.255.255.1', 9, false);
    assert.equal(ep.stats().sendErrs[4], 1, 'one send error counted');
    assert.equal(ep.stats().sock4, true, 'one unreachable destination is not a dead family');
  } finally { shut(ep); }
});
