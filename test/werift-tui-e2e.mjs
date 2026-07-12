// test/werift-tui-e2e.mjs — the Node/werift side of the browser↔TUI DIRECT WebRTC gate.
//
// SELF-SKIPS when werift is absent, so the zero-dep core + CI stay green (werift is an OPTIONAL
// dep: `npm i --no-save werift`). Same convention as test/browser-e2e.mjs, which skips without
// PLAYWRIGHT. Nothing here is auto-asserted in CI — it is a manual/paired gate.
//
// It runs src/browser/webrtc.js (browser-research's tracker-signaled DataChannel transport) with
// werift's RTCPeerConnection INJECTED — that module already takes opts.RTCPeerConnection, so the
// SAME signaling code and the SAME public trackers serve both runtimes. Nothing browser-specific is
// simulated: real WSS trackers, real ICE, a real DataChannel, and node.js's real Noise IK on top.
//
//   node test/werift-tui-e2e.mjs listen            → prints its 26-char key, waits
//   node test/werift-tui-e2e.mjs dial <KEY>         → dials that key
//   node test/werift-tui-e2e.mjs selftest           → two Node peers over the real trackers
//
// Requires: npm i --no-save werift   (OPTIONAL dep — core package.json stays deps:{})

import { identity, listen } from '../src/node.js'
import { createBrowserTransport } from '../src/browser/webrtc.js'

const werift = await import('werift').catch(() => null)
if (!werift) {
  // Not an error: werift is OPTIONAL by design (core package.json stays deps:{}). Skip cleanly.
  console.log('SKIP werift-tui-e2e — werift not installed. To run this gate:')
  console.log('  npm i --no-save werift && node test/werift-tui-e2e.mjs selftest')
  process.exit(0)
}
const { RTCPeerConnection } = werift

const t0 = Date.now()
const log = (...a) => console.log(`[${String(Date.now() - t0).padStart(6)}ms]`, ...a)

/** A Node peer whose WebRTC comes from werift and whose signaling is the public WSS trackers. */
async function peer(id, label) {
  const tp = createBrowserTransport({ RTCPeerConnection })     // werift PC, native global WebSocket
  const node = await listen(id, {
    endpoint: tp.endpoint ?? tp,                               // the transport exposes the seam
    deps: { publishAll: tp.publishAll, resolve: tp.resolve },  // tracker rendezvous, unchanged
  })
  node.on('message', (p, m) => log(`${label} RECV:`, JSON.stringify(m.toString()), 'from', (p.key || '?').slice(0, 8) + '…'))
  node.on('peer', (p) => log(`${label}: peer established, key =`, p.key))
  node.on('divergence', (_p, d) => log(`${label} divergence:`, d.reason, d.error?.message || ''))
  return { node, tp }
}

const mode = process.argv[2] || 'selftest'

if (mode === 'listen') {
  const id = await identity()
  const { node } = await peer(id, 'NODE')
  console.log('\n  NODE/werift peer is LISTENING on the public trackers.')
  console.log('  KEY (give this to the browser):', id.S, '\n')
  node.on('peer', async (p) => {
    await p.send('hello from the TUI — werift DataChannel, Noise IK on top')
    log('NODE: greeting ACKed by the browser')
  })
  setInterval(() => {}, 1 << 30)                               // stay alive for the browser
} else if (mode === 'dial') {
  const S = String(process.argv[3] || '').toUpperCase()
  if (S.length !== 26) { console.error('usage: dial <26-char KEY>'); process.exit(1) }
  const id = await identity()
  const { node } = await peer(id, 'NODE')
  log('NODE dialing', S, 'over the public trackers…')
  const p = await node.connect(S)                              // resolves ONLY after the IK first-ack
  log('NODE CONNECTED — Noise IK first-ack decrypted. peer.key =', p.key)
  await p.send('hello from the TUI over a real RTCDataChannel')
  log('NODE: message ACKed by the browser')
  setInterval(() => {}, 1 << 30)
} else {
  // selftest: two Node/werift peers meeting on the REAL public trackers (proves the Node side of
  // the gate end-to-end before a browser is involved).
  const A = await identity(), B = await identity()
  log('A', A.S)
  log('B', B.S)
  const pa = await peer(A, 'A')
  const pb = await peer(B, 'B')
  const got = []
  pa.node.on('message', (_p, m) => got.push('A:' + m))
  pb.node.on('message', (_p, m) => got.push('B:' + m))

  log('B dialing A over the public WSS trackers (real ICE, real DataChannel)…')
  const peerA = await pb.node.connect(A.S)
  log('B CONNECTED — IK first-ack. peer.key === A.S ?', peerA.key === A.S)
  await peerA.send('hi A — werift DataChannel')
  const back = pa.node.peers()[0]
  await back.send('hi B — Noise on top of DTLS')
  await new Promise((r) => setTimeout(r, 800))

  const ok = got.length === 2 && peerA.key === A.S
  console.log('\n' + (ok
    ? '✅ NODE↔NODE over REAL trackers + werift DataChannel: PASS — ' + JSON.stringify(got)
    : '❌ FAIL — ' + JSON.stringify(got)))
  pa.node.close(); pb.node.close(); pa.tp.close?.(); pb.tp.close?.()
  process.exit(ok ? 0 : 1)
}
