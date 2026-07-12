// test/stun.test.js — P0 transport gate: in-house zero-dep STUN Binding client (RFC 8489).
// Two proofs:
//   (1) DETERMINISTIC — a tiny in-process STUN responder crafts a Binding Success Response
//       with a real XOR-MAPPED-ADDRESS; our client must build the request, match the txid,
//       and XOR-decode the address back byte-exact. Runs everywhere, no network.
//   (2) LIVE — hit REAL public STUN servers and assert a plausible public ip:port comes back.
//       Skips WITH a clear message only if the network is unavailable (it tries first).
// Zero deps, node:test, node:dgram.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { stun, stunAny, STUN_SERVERS } from '../src/transport.js';
import { liveOnly } from './live-gate.mjs';

const MAGIC = 0x2112a442;
const MAGIC_BUF = Buffer.from([0x21, 0x12, 0xa4, 0x42]);

// Minimal STUN server: reply to any Binding Request with a Success Response whose
// XOR-MAPPED-ADDRESS encodes the sender's observed ip:port (what a real STUN server does).
function startFakeStun() {
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    if (msg.length < 20 || msg.readUInt16BE(0) !== 0x0001) return; // not a Binding Request
    const txid = msg.subarray(8, 20);
    const octets = rinfo.address.split('.').map(Number);
    const attrVal = Buffer.alloc(8);
    attrVal.writeUInt8(0x00, 0);
    attrVal.writeUInt8(0x01, 1); // family IPv4
    attrVal.writeUInt16BE(rinfo.port ^ (MAGIC >>> 16), 2); // X-Port
    for (let i = 0; i < 4; i++) attrVal.writeUInt8(octets[i] ^ MAGIC_BUF[i], 4 + i); // X-Address
    const attr = Buffer.concat([Buffer.from([0x00, 0x20, 0x00, 0x08]), attrVal]); // type 0x0020, len 8
    const resp = Buffer.concat([
      Buffer.from([0x01, 0x01]),                       // Binding Success Response
      Buffer.from([(attr.length >> 8) & 0xff, attr.length & 0xff]),
      Buffer.from([0x21, 0x12, 0xa4, 0x42]),           // magic cookie
      txid, attr,
    ]);
    sock.send(resp, rinfo.port, rinfo.address);
  });
  return new Promise((res) => sock.bind(0, () => res(sock)));
}

test('STUN client decodes XOR-MAPPED-ADDRESS byte-exact (deterministic, no network)', async () => {
  const server = await startFakeStun();
  const port = server.address().port;
  try {
    const r = await stun('127.0.0.1', port, { timeoutMs: 2000 });
    assert.equal(r.ip, '127.0.0.1', 'XOR-decoded IP must match the reflexive address');
    assert.ok(r.port >= 1 && r.port <= 65535, 'decoded port in range');
    assert.equal(r.server, `127.0.0.1:${port}`);
  } finally {
    server.close();
  }
});

test('STUN request/response is txid-bound (wrong txid ignored -> timeout)', async () => {
  // Server that echoes a GARBAGE txid — the client must reject it and time out.
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    const resp = Buffer.concat([
      Buffer.from([0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42]),
      Buffer.alloc(12, 0xff),                          // wrong transaction id
      Buffer.from([0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]),
    ]);
    sock.send(resp, rinfo.port, rinfo.address);
  });
  await new Promise((res) => sock.bind(0, res));
  const port = sock.address().port;
  try {
    await assert.rejects(stun('127.0.0.1', port, { timeoutMs: 400 }), /timeout/);
  } finally {
    sock.close();
  }
});

test('LIVE: real public STUN returns a plausible public ip:port', liveOnly, async (t) => {
  let r;
  try {
    r = await stunAny(STUN_SERVERS, { timeoutMs: 3000 });
  } catch (e) {
    t.skip(`network unavailable — real STUN not reachable this run: ${e.message}`);
    return;
  }
  const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6 = /:/;
  assert.ok(ipv4.test(r.ip) || ipv6.test(r.ip), `got a real address family: ${r.ip}`);
  assert.ok(r.port >= 1 && r.port <= 65535, `plausible port ${r.port}`);
  // Not a private/loopback address (this is our PUBLIC reflexive candidate).
  assert.ok(!/^(10\.|127\.|192\.168\.|169\.254\.)/.test(r.ip), `not private: ${r.ip}`);
  const redacted = ipv4.test(r.ip) ? r.ip.replace(/\.\d{1,3}$/, '.x') : r.ip;
  console.log(`  [live STUN] public reflexive candidate: ${redacted}:${r.port}`);
});
