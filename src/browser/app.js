// src/browser/app.js — the demo chat UI. All the interesting work is in p2p.js / webrtc.js;
// this is just wiring. ponytail: no framework, no state library, no build step.

import { identity, listen } from './p2p.js'

const $ = (id) => document.getElementById(id)
const log = $('log')
let node = null
let cleared = false

function say(text, cls = 'sys') {
  if (!cleared) {
    log.innerHTML = ''
    cleared = true
  }
  const li = document.createElement('li')
  li.className = cls
  li.textContent = text
  log.append(li)
  log.scrollTop = log.scrollHeight
}

function chat(who, text, mine = false) {
  if (!cleared) {
    log.innerHTML = ''
    cleared = true
  }
  const li = document.createElement('li')
  if (mine) li.className = 'me'
  const w = document.createElement('span')
  w.className = 'who'
  w.textContent = mine ? 'you' : who
  li.append(w, document.createTextNode(text))
  log.append(li)
  log.scrollTop = log.scrollHeight
}

function status(text, on = false) {
  $('statusText').textContent = text
  $('dot').classList.toggle('on', on)
}

/** The peer we're actively typing at (last one connected). Groups fan out separately. */
let current = null

function wirePeer(peer) {
  current = peer
  $('msg').disabled = false
  $('send').disabled = false
  $('msg').focus()
}

async function main() {
  try {
    const id = await identity()
    $('mykey').textContent = id.S
    status('going online…')

    node = await listen(id)

    node.on('peer', (peer) => {
      // We only get here AFTER the Noise IK first-ack — i.e. after the handshake has PROVEN
      // there is no man in the middle. That's why this line is a real claim, not a hopeful label.
      say(`✅ secure channel established with ${peer.key} — verified, no MITM`, 'sys ok')
      wirePeer(peer)
    })
    node.on('message', (peer, data) => chat(peer.key.slice(0, 8), Buffer.from(data).toString('utf8')))
    node.on('disconnect', (peer) => say(`peer ${String(peer.key).slice(0, 8)} disconnected`))
    node.on('divergence', (_peer, info) => say(`handshake failed (${info.reason}) — refusing to continue`, 'sys err'))

    status('online — reachable via public trackers', true)
    say('Online. Share your key, or paste someone else\'s and hit Connect.')

    // Group fan-out hook (src/group.js): group(keys).send(text). Exposed for the group e2e and
    // for a future group UI. Pairwise fan-out — one authenticated Noise link per member.
    window.__p2pGroupSend = (keys, text) => node.group(keys).send(text)

    // Deep link: #KEY (e.g. from a shared link) auto-fills the dial box.
    const hash = location.hash.replace('#', '').trim().toUpperCase()
    if (hash.length === 26) $('peerkey').value = hash
  } catch (err) {
    status('failed to start', false)
    say(err.message, 'sys err')
    throw err
  }
}

$('copy').onclick = async () => {
  await navigator.clipboard.writeText($('mykey').textContent)
  $('copy').textContent = 'Copied'
  setTimeout(() => ($('copy').textContent = 'Copy'), 1200)
}

$('connect').onclick = async () => {
  const S = $('peerkey').value.trim().toUpperCase()
  if (!S) return
  $('connect').disabled = true
  say(`dialing ${S}… (deriving the rendezvous id, then WebRTC over the public trackers)`)
  try {
    const peer = await node.connect(S)
    wirePeer(peer) // the 'peer' event already announced the verified channel
  } catch (err) {
    say(`could not connect: ${err.message}`, 'sys err')
  } finally {
    $('connect').disabled = false
  }
}

const send = async () => {
  const text = $('msg').value
  if (!text || !current) return
  $('msg').value = ''
  chat('you', text, true)
  try {
    await current.send(text) // resolves on the peer's ACK
  } catch (err) {
    say(`send failed: ${err.message}`, 'sys err')
  }
}
$('send').onclick = send
$('msg').onkeydown = (e) => e.key === 'Enter' && send()

main()
