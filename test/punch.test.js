// test/punch.test.js — P0 transport gate: UDP hole-punch choreography over node:dgram.
// Two real endpoints exchange each other's candidate through an IN-PROCESS coordinator stub
// (the rendezvous handoff, simulated for the spike), then run the simultaneous-open punch:
// both fire PROBEs at once, we DROP the first probes on each side to force the documented
// "first packets are lost" race (research/transport-nat.md §1.1), and the burst-retry must
// still establish a bidirectionally-validated path. 10/10 required.
// Real cross-NAT punch is verified later (task 8); this proves the machinery + retry.
// Zero deps, node:test, real UDP sockets on loopback.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createEndpoint } from '../src/transport.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Force early packet loss: swallow the first `n` outbound datagrams on a socket, so the
// punch must rely on its retransmit bursts (proves the retry choreography, not just a
// zero-loss localhost happy path).
function dropFirst(sock, n) {
  if (!sock) return;
  const orig = sock.send.bind(sock);
  let dropped = 0;
  sock.send = (...args) => {
    if (dropped < n) { dropped++; return; } // simulate loss of the first probes
    return orig(...args);
  };
}

async function onePunchRound() {
  const A = await createEndpoint({ port: 0 });
  const B = await createEndpoint({ port: 0 });
  // Coordinator stub: each side learns the other's reflexive candidate out-of-band.
  const candForA = [{ proto: 'udp4', ip: '127.0.0.1', port: B.port4, kind: 'srflx' }];
  const candForB = [{ proto: 'udp4', ip: '127.0.0.1', port: A.port4, kind: 'srflx' }];
  const token = randomBytes(8); // shared rendezvous nonce binds the two punch sessions

  dropFirst(A.sock4, 2);
  dropFirst(B.sock4, 2);

  try {
    // Both fire simultaneously (the crux of hole punching).
    const [sA, sB] = await Promise.all([
      A.punch(candForA, { token, timeout: 6000 }),
      B.punch(candForB, { token, timeout: 6000 }),
    ]);
    assert.ok(sA && typeof sA.send === 'function' && typeof sA.onMessage === 'function');
    assert.ok(sB && typeof sB.send === 'function' && typeof sB.onMessage === 'function');

    // Prove real bidirectional datagram flow over the punched path.
    let gotAtB = null, gotAtA = null;
    sB.onMessage((m) => { gotAtB = m.toString(); });
    sA.onMessage((m) => { gotAtA = m.toString(); });
    sA.send(Buffer.from('hello-from-A'));
    sB.send(Buffer.from('hello-from-B'));
    for (let i = 0; i < 40 && (!gotAtB || !gotAtA); i++) await sleep(10);

    assert.equal(gotAtB, 'hello-from-A', 'A->B datagram delivered over punched path');
    assert.equal(gotAtA, 'hello-from-B', 'B->A datagram delivered over punched path');
    return true;
  } finally {
    A.close();
    B.close();
  }
}

test('UDP hole-punch establishes bidirectional flow 10/10 (with forced early loss)', { timeout: 90000 }, async () => {
  let ok = 0;
  for (let i = 0; i < 10; i++) {
    const pass = await onePunchRound();
    if (pass) ok++;
    console.log(`  punch round ${i + 1}/10: ${pass ? 'OK' : 'FAIL'}`);
  }
  assert.equal(ok, 10, `punch succeeded ${ok}/10`);
});
