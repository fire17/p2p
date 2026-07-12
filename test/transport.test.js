// test/transport.test.js — dual-stack UDP core, in-house STUN client, ICE-lite punch.
// node --test, zero dev deps. Network-free: STUN is tested against a local fake server;
// punch is tested over loopback. No public internet needed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { createEndpoint, stun, STUN_SERVERS } from '../src/transport.js';

const MAGIC = 0x2112a442;

/** Build a STUN Binding Success Response with an XOR-MAPPED-ADDRESS (IPv4). */
function stunResponse(txid, ip, port) {
  const parts = ip.split('.').map(Number);
  const val = Buffer.alloc(8);
  val[0] = 0; val[1] = 0x01; // reserved, family IPv4
  val.writeUInt16BE(port ^ (MAGIC >>> 16), 2);
  const xip = Buffer.from(parts);
  const mb = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
  for (let i = 0; i < 4; i++) xip[i] ^= mb[i];
  xip.copy(val, 4);
  const attr = Buffer.alloc(12);
  attr.writeUInt16BE(0x0020, 0); attr.writeUInt16BE(8, 2); val.copy(attr, 4);
  const hdr = Buffer.alloc(20);
  hdr.writeUInt16BE(0x0101, 0); hdr.writeUInt16BE(attr.length, 2); hdr.writeUInt32BE(MAGIC, 4); txid.copy(hdr, 8);
  return Buffer.concat([hdr, attr]);
}

/** Spin up a fake STUN server that reflects a fixed address. */
function fakeStun(ip, port) {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.on('message', (msg, rinfo) => {
      const txid = msg.subarray(8, 20);
      s.send(stunResponse(txid, ip, port), rinfo.port, rinfo.address);
    });
    s.bind(0, () => resolve({ sock: s, port: s.address().port }));
  });
}

test('STUN server list drops the defunct stun.stunprotocol.org', () => {
  assert.ok(!STUN_SERVERS.some((s) => s.host.includes('stunprotocol')));
  assert.ok(STUN_SERVERS.length >= 2, 'need >=2 servers for parallel retry');
});

test('createEndpoint binds dual-stack and reports a port', async () => {
  const ep = await createEndpoint({});
  assert.ok(ep.port > 0);
  assert.ok(ep.sock4 || ep.sock6, 'at least one family bound');
  const cands = ep.candidates();
  assert.ok(Array.isArray(cands));
  for (const c of cands) {
    assert.ok(['udp4', 'udp6', 'tcp'].includes(c.proto));
    assert.ok(['host', 'lan', 'srflx'].includes(c.kind));
    assert.equal(typeof c.port, 'number');
  }
  ep.close();
});

test('ep.stun() parses XOR-MAPPED-ADDRESS and caches a srflx candidate', async () => {
  const srv = await fakeStun('9.8.7.6', 4444);
  const ep = await createEndpoint({});
  const r = await ep.stun({ servers: [{ host: '127.0.0.1', port: srv.port }], timeout: 2000 });
  assert.deepEqual(r, { ip: '9.8.7.6', port: 4444 });
  const srflx = ep.candidates().find((c) => c.kind === 'srflx');
  assert.ok(srflx && srflx.ip === '9.8.7.6' && srflx.port === 4444);
  ep.close(); srv.sock.close();
});

test('standalone stun() helper decodes a fake server response', async () => {
  const srv = await fakeStun('5.4.3.2', 1234);
  const r = await stun('127.0.0.1', srv.port, { timeoutMs: 2000 });
  assert.equal(r.ip, '5.4.3.2');
  assert.equal(r.port, 1234);
  srv.sock.close();
});

test('punch: two endpoints validate a 4-tuple and exchange data (loopback)', async () => {
  const a = await createEndpoint({});
  const b = await createEndpoint({});
  const token = 'test-token';
  // loopback candidates (candidates() skips internal addrs, so craft them explicitly)
  const toB = [{ proto: 'udp4', ip: '127.0.0.1', port: b.port4, kind: 'host' }];
  const toA = [{ proto: 'udp4', ip: '127.0.0.1', port: a.port4, kind: 'host' }];

  const [sa, sb] = await Promise.all([
    a.punch(toB, { token, timeout: 4000 }),
    b.punch(toA, { token, timeout: 4000 }),
  ]);
  assert.equal(sa.proto, 'udp4');
  assert.equal(sb.proto, 'udp4');

  const gotA = new Promise((res) => { sa.onMessage = (m) => m.toString() === 'ping-b' && res(); });
  const gotB = new Promise((res) => { sb.onMessage = (m) => m.toString() === 'ping-a' && res(); });
  const iv = setInterval(() => { sa.send(Buffer.from('ping-a')); sb.send(Buffer.from('ping-b')); }, 100);
  await Promise.all([gotA, gotB]);
  clearInterval(iv);

  sa.close(); sb.close(); a.close(); b.close();
});

test('onConnection: listener accepts an UNSOLICITED inbound punch (node.listen path)', async () => {
  const listener = await createEndpoint({});
  const dialer = await createEndpoint({});
  const token = 'inbound';
  const accepted = new Promise((res) => listener.onConnection((sock) => res(sock)));
  // dialer punches; listener is NOT punching — only accepting via onConnection.
  const dialerSockP = dialer.punch([{ proto: 'udp4', ip: '127.0.0.1', port: listener.port4, kind: 'host' }], { token, timeout: 4000 });
  const [lSock, dSock] = await Promise.all([accepted, dialerSockP]);
  assert.equal(lSock.proto, 'udp4');
  assert.equal(dSock.proto, 'udp4');

  const gotAtL = new Promise((res) => { lSock.onMessage = (m) => m.toString() === 'hi-listener' && res(); });
  const gotAtD = new Promise((res) => { dSock.onMessage = (m) => m.toString() === 'hi-dialer' && res(); });
  const iv = setInterval(() => { dSock.send(Buffer.from('hi-listener')); lSock.send(Buffer.from('hi-dialer')); }, 80);
  await Promise.all([gotAtL, gotAtD]);
  clearInterval(iv);
  lSock.close(); dSock.close(); listener.close(); dialer.close();
});

// Raw PROBE builder (mirrors transport's internal punch wire: magic|type|token|nonce).
const PUNCH_MAGIC = 0x50327050;
function rawProbe(token, nonce) {
  const b = Buffer.alloc(21);
  b.writeUInt32BE(PUNCH_MAGIC, 0); b[4] = 0x01; token.copy(b, 5); nonce.copy(b, 13);
  return b;
}
const bindP = (s) => new Promise((r) => s.bind(0, r));

test('onConnection dedups multi-path accepts by SESSION TOKEN (fires once, both tuples routed)', async () => {
  const listener = await createEndpoint({});
  let fires = 0; const socks = [];
  listener.onConnection((s) => { fires++; socks.push(s); });
  const token = Buffer.from('tok12345'); // non-zero 8-byte session token
  // two distinct source sockets on loopback = two rinfo tuples (same address, different port),
  // both carrying the SAME token — models one dialer's v4+v6 multi-path burst.
  const s1 = dgram.createSocket('udp4'); const s2 = dgram.createSocket('udp4');
  await Promise.all([bindP(s1), bindP(s2)]);
  s1.send(rawProbe(token, Buffer.alloc(8, 1)), listener.port4, '127.0.0.1');
  s2.send(rawProbe(token, Buffer.alloc(8, 2)), listener.port4, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(fires, 1, 'one logical dialer -> exactly one onConnection');

  // both source tuples must route to the SAME accepted socketLike
  const seen = [];
  socks[0].onMessage = (m) => seen.push(m.toString());
  s1.send(Buffer.from('from-s1'), listener.port4, '127.0.0.1');
  s2.send(Buffer.from('from-s2'), listener.port4, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 150));
  assert.ok(seen.includes('from-s1') && seen.includes('from-s2'), 'both tuples deliver to the one sock');
  s1.close(); s2.close(); socks[0].close(); listener.close();
});

test('token-accepted socket FANS OUT send to all tuples until the path is locked by inbound', async () => {
  const listener = await createEndpoint({});
  let sock = null;
  listener.onConnection((s) => { sock = s; });
  const token = Buffer.from('fanotok1');
  const s1 = dgram.createSocket('udp4'); const s2 = dgram.createSocket('udp4');
  await Promise.all([bindP(s1), bindP(s2)]);
  const r1 = []; const r2 = [];
  s1.on('message', (m) => r1.push(m.toString()));
  s2.on('message', (m) => r2.push(m.toString()));
  // two source tuples, same token -> one accepted sock correlating both
  s1.send(rawProbe(token, Buffer.alloc(8, 1)), listener.port4, '127.0.0.1');
  s2.send(rawProbe(token, Buffer.alloc(8, 2)), listener.port4, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(sock, 'accepted');

  // PRE-LOCK: send must reach BOTH source tuples (dialer's validated path is still unknown)
  sock.send(Buffer.from('pre-lock'));
  await new Promise((r) => setTimeout(r, 120));
  assert.ok(r1.includes('pre-lock') && r2.includes('pre-lock'), 'fan-out reaches every tuple before lock');

  // s1 delivers inbound app data -> locks cur to s1's tuple
  s1.send(Buffer.from('lock-me'), listener.port4, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 120));
  r1.length = 0; r2.length = 0;
  sock.send(Buffer.from('post-lock'));
  await new Promise((r) => setTimeout(r, 120));
  assert.ok(r1.includes('post-lock'), 'after lock, send goes to the delivering path');
  assert.ok(!r2.includes('post-lock'), 'after lock, send no longer fans out to dead paths');
  s1.close(); s2.close(); sock.close(); listener.close();
});

test('onConnection with ZERO token accepts per-4-tuple (ICE-style; node.js converges)', async () => {
  const listener = await createEndpoint({});
  let fires = 0;
  listener.onConnection(() => { fires++; });
  const zero = Buffer.alloc(8);
  const s1 = dgram.createSocket('udp4'); const s2 = dgram.createSocket('udp4');
  await Promise.all([bindP(s1), bindP(s2)]);
  s1.send(rawProbe(zero, Buffer.alloc(8, 1)), listener.port4, '127.0.0.1');
  s2.send(rawProbe(zero, Buffer.alloc(8, 2)), listener.port4, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(fires, 2, 'no token correlation -> one accept per distinct 4-tuple');
  s1.close(); s2.close(); listener.close();
});

test('punch rejects when there are no candidates', async () => {
  const ep = await createEndpoint({});
  await assert.rejects(() => ep.punch([], { timeout: 500 }), /no candidates/i);
  ep.close();
});

test('punch falls back and rejects on an unreachable candidate within timeout', async () => {
  const ep = await createEndpoint({});
  // A CLOSED LOOPBACK PORT, not a TEST-NET-3 address. 203.0.113.0/24 is unroutable on the INTERNET,
  // which is not the same as "no packet leaves this machine": the OS still pushed the ICE-lite UDP
  // burst and a TCP-fallback SYN out the default gateway (observed live — a SYN_SENT to
  // 203.0.113.1:9 from a plain `node --test`). The owner runs live p2p sessions on this box, so the
  // suite must put NOTHING on the wire. 127.0.0.1:1 exercises the identical path — nothing validates,
  // UDP times out, TCP fallback is refused, punch rejects — without emitting a single external byte.
  const dead = [{ proto: 'udp4', ip: '127.0.0.1', port: 1, kind: 'host' }];
  await assert.rejects(() => ep.punch(dead, { token: 'x', timeout: 1200 }));
  ep.close();
});

test('endpoint emits netchange from an EventEmitter surface', async () => {
  const ep = await createEndpoint({});
  assert.equal(typeof ep.on, 'function');
  assert.equal(typeof ep.emit, 'function');
  let fired = false;
  ep.on('netchange', () => { fired = true; });
  ep.emit('netchange');
  assert.ok(fired);
  ep.close();
});
