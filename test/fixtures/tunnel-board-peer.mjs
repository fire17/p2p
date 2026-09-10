// test/fixtures/tunnel-board-peer.mjs — one REAL p2p node in its own PROCESS, meeting its partner
// over a file-carried rendezvous board (src/tunnel-board.js). Two of these prove what the
// in-process test cannot: discovery across process boundaries, over real UDP, with nothing shared
// but a directory. No public infra, no mDNS, no P2P_LIVE.
//
// usage:
//   node tunnel-board-peer.mjs host <dir> <secretHex> <nowMs> [--no-loopback]
//   node tunnel-board-peer.mjs join <dir> <share>     <nowMs> [--no-loopback]
//
// Every line on stdout is one JSON object (jsonl); the parent reads `ready`/`connected`/`recv`.

import { listen } from '../../src/node.js'
import { generateIdentity, encodeKey } from '../../src/key.js'
import { INVITE_FLAG, formatShare, createInvite } from '../../src/invite.js'
import { fileRendezvousDeps } from '../../src/tunnel-board.js'

const [role, dir, arg3, nowArg, ...flags] = process.argv.slice(2)
const nowMs = Number(nowArg)
const loopback = !flags.includes('--no-loopback')
const HARD_STOP_MS = 20_000

const out = (o) => process.stdout.write(JSON.stringify(o) + '\n')
const die = (why, err) => { out({ ev: 'error', why, msg: String((err && err.message) || err || '') }); process.exit(3) }

// A hard stop so a stuck fixture is a FAILING test, never a hung suite.
const bail = setTimeout(() => { out({ ev: 'timeout' }); process.exit(4) }, HARD_STOP_MS)

const depsFor = (announce, invite = null) => fileRendezvousDeps(dir, {
  loopback, announce, invite, now: () => nowMs, lookupTimeoutMs: 2500, pollMs: 25,
})

try {
  const id = generateIdentity()
  if (role === 'host') {
    const secret = Buffer.from(arg3, 'hex')
    const deps = depsFor(true, createInvite(secret))
    const node = await listen(id, { invite: secret, wss: false, deps, tickMs: 25 })
    node.on('message', (peer, buf) => {
      const text = buf.toString()
      out({ ev: 'recv', text })
      Promise.resolve(peer.send('pong:' + text)).catch((e) => out({ ev: 'sendfail', msg: String(e.message) }))
    })
    // the invite-flagged S plus the one-time secret = the share string the joiner pastes
    const share = formatShare(encodeKey(id.edPub, id.xPub, INVITE_FLAG), secret)
    out({ ev: 'ready', role, share, realChannels: node._channels.length })
  } else if (role === 'join') {
    const share = arg3
    const deps = depsFor(false)                        // a joiner seeks; it publishes nothing
    const node = await listen(id, { wss: false, deps, tickMs: 25 })
    out({ ev: 'ready', role, realChannels: node._channels.length })
    node.on('message', (_p, buf) => {
      out({ ev: 'recv', text: buf.toString() })
      clearTimeout(bail)
      try { node.close() } catch { /* */ }
      setTimeout(() => process.exit(0), 50)
    })
    const t0 = Date.now()
    const peer = await node.connect(share)
    out({ ev: 'connected', ms: Date.now() - t0, key: peer.key })
    await peer.send('ping from joiner')
  } else {
    die('usage', 'role must be host|join')
  }
} catch (err) {
  clearTimeout(bail)
  die('threw', err)
}
