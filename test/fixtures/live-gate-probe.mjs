// test/fixtures/live-gate-probe.mjs — a NO-OP stand-in for a real-network test.
//
// It carries the exact gate the live tests carry (`liveOnly`), but touches nothing: no socket, no
// packet. test/live-gate.test.js runs this file twice — with and without P2P_LIVE — to prove the gate
// actually flips, WITHOUT putting a single real byte on the wire. Proving the flag by running the
// real mDNS/STUN/DHT/tracker tests would mean committing the very sin the gate exists to prevent.

import test from 'node:test'
import { liveOnly } from '../live-gate.mjs'

test('PROBE: gated like a live test, but does nothing at all', liveOnly, () => {
  // deliberately empty — the POINT is whether this ran or was skipped
})
