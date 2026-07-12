// test/live-gate.mjs — the opt-in gate for every test that touches a REAL network.
//
// THE RULE: `node --test` must emit ZERO real LAN or internet traffic. The owner routinely
// feel-tests a live tui↔tui session on the same machine, and a stray mDNS announce, STUN burst or
// tracker announce from a test run pollutes his discovery. This already bit us once: a LIVE mDNS
// test multicast on the LAN, by default, mid-session.
//
// It is easy to trip because `node --test` executes EVERY .js/.mjs under test/ — not just
// *.test.js — so the standalone harnesses (werift-tui-e2e.mjs, the playwright drivers) are auto-run
// too, in their default mode. That is exactly how a "manual gate tool" ends up on the wire.
//
// Two shapes, because there are two kinds of live code here:
//
//   • node:test tests        →  test('LIVE: …', liveOnly, fn)      — skipped unless P2P_LIVE=1
//   • standalone harnesses   →  if (skipLiveScript('name')) process.exit(0)   at the top
//
// The harnesses stay runnable BY HAND exactly as before — that is what NODE_TEST_CONTEXT
// distinguishes (node's runner sets it to 'child-v8'; a direct `node test/foo.mjs` does not). Only
// the AUTOMATIC runner path is gated, so the owner's manual gating workflow is untouched.
//
//   node --test                # zero real traffic — every live test/harness skipped
//   P2P_LIVE=1 node --test     # everything, live gates included
//   node test/werift-tui-e2e.mjs selftest    # by hand: works as before, no flag needed

/** Opt-in: the user explicitly asked for real network traffic. */
export const LIVE = !!process.env.P2P_LIVE

/**
 * node:test options object — skips a real-network test unless P2P_LIVE=1.
 * Usage: `test('LIVE: real STUN …', liveOnly, async (t) => { … })`
 */
export const liveOnly = LIVE ? {} : { skip: 'real-network test — set P2P_LIVE=1 to run it' }

/**
 * For standalone harnesses that `node --test` would otherwise auto-run in their default mode.
 * @param {string} name  the harness, for the skip line
 * @returns {boolean} true ⇒ the caller should exit immediately (auto-run, no opt-in)
 */
export function skipLiveScript(name) {
  if (LIVE || !process.env.NODE_TEST_CONTEXT) return false   // opted in, or launched by hand
  console.log(`SKIP ${name} — real-network harness; not run by \`node --test\`.`)
  console.log(`  To run it:  P2P_LIVE=1 node --test   (or directly: node test/${name})`)
  return true
}

export default { LIVE, liveOnly, skipLiveScript }
