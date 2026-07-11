// Live WSS tracker reachability + message-format spike. Public-network dependent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TRACKERS, trackerProbe, trackerRelayProbe, randId20 } from '../../src/rendezvous/tracker.js';

test('WSS tracker reachability + announce/offer format', { timeout: 60000 }, async () => {
  const infoHash = randId20();
  const results = await Promise.all(TRACKERS.map((u) => trackerProbe(u, infoHash)));
  let up = 0;
  for (const r of results) {
    if (r.ok) { up++; console.log(`  OK   ${r.url}  ${r.latencyMs}ms  resp=${JSON.stringify(r.response).slice(0, 120)}`); }
    else console.log(`  FAIL ${r.url}  ${r.error}`);
  }
  console.log(`  trackers reachable: ${up}/${TRACKERS.length}`);
  assert.ok(up >= 1, 'no public WSS tracker reachable');
});

test('two-peer offer relay (matchmaker) — best-effort, non-fatal', { timeout: 15000 }, async () => {
  // Bonus probe only. Full offer/answer matchmaking is P1 (DESIGN D6); the spike gate
  // is reachability+format above. Single tracker, short window, never fails the suite.
  const r = await trackerRelayProbe(TRACKERS[0], randId20(), { timeout: 9000 });
  console.log(`  ${TRACKERS[0]}: offer relayed=${r.relayed}${r.error ? ' (' + r.error + ')' : ''}`);
  console.log('  NOTE: live offer-relay is deferred to P1 matchmaker; not a spike gate.');
  assert.ok(true);
});
