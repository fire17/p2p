// THE GATE (premortem kill-criteria): live round-trip on the REAL public Mainline DHT.
// Process A announces itself under a random infohash; independent client B does get_peers
// on the same infohash and must RECEIVE A's ip:port. Run multiple times, report honest
// success rate + latency. Public-network dependent — flake is logged, not hidden.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DHT, BOOTSTRAP, deriveRid } from '../../src/rendezvous/dht.js';

test('deriveRid: deterministic, correct length, channel-separated', () => {
  const S = 'ABCDEFGHJKMNPQRSTVWXYZ0123'; // 26-char sample
  const a = deriveRid(S, 'dht', '2026-07-11', 20);
  const b = deriveRid(S, 'dht', '2026-07-11', 20);
  const c = deriveRid(S, 'tracker', '2026-07-11', 20);
  assert.equal(a.length, 20);
  assert.deepEqual(a, b);              // deterministic
  assert.notDeepEqual(a, c);          // channel domain-separated
  assert.notDeepEqual(a, deriveRid(S, 'dht', '2026-07-12', 20)); // epoch-separated
});

test('bootstrap nodes are live (ping)', { timeout: 20000 }, async () => {
  const dht = new DHT();
  await dht.ready();
  let up = 0;
  for (const b of BOOTSTRAP) {
    try { await dht.query(b, 'ping', {}, 4000); up++; console.log(`  ping OK  ${b.host}`); }
    catch (e) { console.log(`  ping ERR ${b.host}: ${e.message}`); }
  }
  dht.close();
  console.log(`  bootstrap reachable: ${up}/${BOOTSTRAP.length}`);
  assert.ok(up >= 1, 'no DHT bootstrap node reachable — network/UDP blocked');
});

test('GATE: live announce -> get_peers round-trip on public Mainline DHT', { timeout: 300000 }, async () => {
  const TRIALS = 5;
  const A_RETRY = 2;  // owner re-announces (design: re-announce until it lands)
  const B_RETRY = 3;  // reader races/retries the read (design D6/§10)
  let singleShot = 0, effective = 0, announceOk = 0;
  const rtLatencies = [];

  for (let i = 0; i < TRIALS; i++) {
    const infohash = crypto.randomBytes(20);        // fresh random target per trial
    const markerPort = 1025 + crypto.randomBytes(2).readUInt16BE(0) % 60000;
    const A = new DHT(); const B = new DHT();
    try {
      const t0 = performance.now();
      // A: announce, retry until it reaches at least one node
      let aAnn = 0;
      for (let r = 0; r < A_RETRY && aAnn === 0; r++) {
        const aRes = await A.getPeers(infohash, { announce: true, port: markerPort });
        aAnn = aRes.announced;
      }
      if (aAnn > 0) announceOk++;

      await new Promise((r) => setTimeout(r, 1500)); // let value settle on closest nodes

      // B: read, retry (reader race). Record first attempt separately (single-shot truth).
      let hit = false, attempts = 0, peersSeen = 0;
      for (let r = 0; r < B_RETRY && !hit; r++) {
        attempts++;
        const bRes = await B.getPeers(infohash, {});
        peersSeen = bRes.peers.length;
        hit = bRes.peers.some((p) => p.endsWith(`:${markerPort}`));
        if (r === 0 && hit) singleShot++;
      }
      const dtMs = Math.round(performance.now() - t0);
      if (hit) { effective++; rtLatencies.push(dtMs); }

      console.log(`  trial ${i + 1}/${TRIALS}: A announced=${aAnn}, B attempts=${attempts} peers=${peersSeen} ` +
        `roundtrip=${hit ? `YES ${dtMs}ms` : 'no'}`);
    } finally { A.close(); B.close(); }
  }

  const eRate = ((effective / TRIALS) * 100).toFixed(0);
  const sRate = ((singleShot / TRIALS) * 100).toFixed(0);
  const avg = rtLatencies.length ? Math.round(rtLatencies.reduce((a, b) => a + b, 0) / rtLatencies.length) : 0;
  console.log(`\n  === GATE RESULT: round-trip ${effective}/${TRIALS} (${eRate}%, single-shot ${sRate}%)  ` +
    `announce-reached ${announceOk}/${TRIALS}  avg-latency ${avg}ms ===\n`);

  // GATE-FAIL only if the public DHT is entirely unusable (no announce AND no round-trip).
  assert.ok(announceOk > 0, 'GATE-FAIL: could not announce to any DHT node (infra unreachable)');
  assert.ok(effective > 0, `GATE-FAIL: 0/${TRIALS} value round-trips — free-infra rendezvous unproven`);
});
