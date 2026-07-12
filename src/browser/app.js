// src/browser/app.js — the browser chat UI (served at /app/). All the protocol work is in p2p.js /
// webrtc.js / group.js; this is just wiring. ponytail: no framework, no state library, no build step.
// One copy of this file runs everywhere — /app/index.html loads it by absolute path and its relative
// imports resolve against /src/browser/.

import { identity, listen } from './p2p.js'

const $ = (id) => document.getElementById(id)
let node = null
let pendingInviteNote = false

// ── tiny log helpers (shared shape for the pair log #log and the group log #grouplog) ──
function line(ul, text, cls = 'sys') {
  if (ul.dataset.fresh !== '1') { ul.innerHTML = ''; ul.dataset.fresh = '1' }
  const li = document.createElement('li')
  li.className = cls
  li.textContent = text
  ul.append(li)
  ul.scrollTop = ul.scrollHeight
}
function chatLine(ul, who, text, { mine = false, cls = '' } = {}) {
  if (ul.dataset.fresh !== '1') { ul.innerHTML = ''; ul.dataset.fresh = '1' }
  const li = document.createElement('li')
  li.className = (mine ? 'me ' : '') + cls
  const w = document.createElement('span')
  w.className = 'who'
  w.textContent = mine ? 'you' : who
  li.append(w, document.createTextNode(text))
  ul.append(li)
  ul.scrollTop = ul.scrollHeight
}
const say = (text, cls) => line($('log'), text, cls)
const gsay = (text, cls) => line($('grouplog'), text, cls)

function status(text, on = false) {
  $('statusText').textContent = text
  $('dot').classList.toggle('on', on)
}

// ── tabs ──
function showTab(which) {
  const pair = which === 'pair'
  $('viewPair').hidden = !pair
  $('viewGroup').hidden = pair
  $('tabPair').setAttribute('aria-selected', String(pair))
  $('tabGroup').setAttribute('aria-selected', String(!pair))
}
$('tabPair').onclick = () => showTab('pair')
$('tabGroup').onclick = () => showTab('group')

// ── 1-to-1 ──
let current = null // the peer we're actively typing at
function wirePeer(peer) {
  current = peer
  $('msg').disabled = false
  $('send').disabled = false
}

// ── group state ──
let group = null
function updateMembers() {
  if (!group) return
  const n = group.members().length
  $('groupMembers').textContent = n + (n === 1 ? ' member' : ' members')
}
function enableGroupChat(isAdmin) {
  $('groupCode').textContent = group.secret
  $('groupCopy').disabled = false
  $('groupMsg').disabled = false
  $('groupSend').disabled = false
  $('addRow').hidden = !isAdmin // only the admin can grow the group later
  updateMembers()
}
async function startGroup(secret, { create = false, memberKeys = [] } = {}) {
  if (!secret) return
  group = node.secureGroup({ secret, members: memberKeys, create })
  group.on('message', (from, data) => chatLine($('grouplog'), String(from).slice(0, 8), Buffer.from(data).toString('utf8'), { cls: 'grpmsg' }))
  group.on('membership', updateMembers)
  gsay(create ? 'Group created — you are the admin. Share the code with the members you listed.' : 'Joined. If the creator included your key, you\'re in.', 'sys ok')
  await group.join()
  enableGroupChat(create)
  // Bounded ADMIN re-sync for the "create first, share the code, members join later" flow. The
  // catch: keydistTo succeeds at the NODE level as soon as a member's process is online — even if
  // their GROUP isn't created yet — so the membership chain is dropped and keyedTo still marks them
  // "done", and plain join() never retries. rotate() force-redelivers: it clears keyedTo and pushes
  // the chain + a fresh sender key to every currently-listening member. A few spaced attempts catch
  // members who join within ~20 s. (No messages exist yet at setup, so re-keying is free; a member
  // who already has it just receives the newer key.) Members don't self-sync — they can't reach the
  // admin until the chain (which carries the admin's pubkeys) arrives. This is a UI-level
  // reliability layer over a real protocol limitation flagged to the group's owner.
  if (create) {
    let n = 0
    const resync = setInterval(async () => {
      if (!group || ++n > 4) return clearInterval(resync)
      try { await group.rotate() } catch { /* a member still offline — next attempt */ }
      updateMembers()
    }, 5000)
    if (resync.unref) resync.unref()
  }
}

function newGroupSecret() {
  const b = new Uint8Array(32)
  globalThis.crypto.getRandomValues(b)
  return Buffer.from(b).toString('base64')
}

async function main() {
  try {
    // Deep link FIRST (needs only the DOM, not the network): /app/#<26-CHAR-KEY> pre-fills the dial
    // box; /app/#<group-code> pre-fills the group Join box. A share string (`S-<tail>`, one-time
    // invite) is DETECTED and reported honestly — invite dialing isn't wired in the browser yet
    // (fast-follow), so we don't silently misroute it to the group box. Done before going online.
    const frag = decodeURIComponent(location.hash.replace('#', '')).trim()
    const isShareString = /^[0-9A-Za-z]{26}-\S+$/.test(frag) // 26-char S + '-' + invite tail
    if (isShareString) {
      showTab('pair')
      pendingInviteNote = true // one-time invite — surfaced once we're online (say() needs the log)
    } else if (frag.length === 26) { $('peerkey').value = frag.toUpperCase(); showTab('pair') }
    else if (frag.length > 26) { $('groupSecret').value = frag; showTab('group') }

    const id = await identity()
    $('mykey').textContent = id.S
    status('going online…')

    node = await listen(id)

    node.on('peer', (peer) => {
      // We only reach here AFTER the Noise IK first-ack — the handshake has PROVEN there is no
      // man in the middle. That is why this line is a real claim, not a hopeful label.
      say(`✅ secure channel established with ${peer.key} — verified, no MITM`, 'sys ok')
      wirePeer(peer)
    })
    node.on('message', (peer, data) => chatLine($('log'), String(peer.key).slice(0, 8), Buffer.from(data).toString('utf8')))
    node.on('disconnect', (peer) => say(`peer ${String(peer.key).slice(0, 8)} disconnected`))
    node.on('divergence', (_peer, info) => say(`handshake failed (${info.reason}) — refusing to continue`, 'sys err'))

    status('online — reachable via public infrastructure', true)
    say('Online. Share your key, or paste someone else\'s and hit Connect.')
    if (pendingInviteNote) {
      say('This is a one-time invite link (S-…). Invite dialing isn\'t supported in the browser yet — use the CLI for the invite, or ask them for their plain 26-char key to connect here.', 'sys err')
    }

    // ── programmatic hooks (used by the e2e harnesses; humans use the UI above) ──
    window.__p2pGroupSend = (keys, text) => node.group(keys).send(text)
    let secureGroup = null
    window.__secureRx = []
    window.__secureGroupCreate = (secretB64, opts = {}) => {
      secureGroup = node.secureGroup({ secret: secretB64, ...opts })
      secureGroup.on('message', (from, data) => window.__secureRx.push({ from, text: Buffer.from(data).toString('utf8') }))
      return secureGroup.groupId
    }
    window.__secureGroupJoin = async () => { await secureGroup.join(); return secureGroup.members() }
    window.__secureGroupSend = (text) => secureGroup && secureGroup.send(text)
    window.__secureGroupMembers = () => (secureGroup ? secureGroup.members() : [])
  } catch (err) {
    status('failed to start', false)
    say(err.message, 'sys err')
    throw err
  }
}

// ── pair handlers ──
$('copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('mykey').textContent) } catch { /* clipboard blocked */ }
  $('copy').textContent = 'Copied'
  setTimeout(() => ($('copy').textContent = 'Copy'), 1200)
}
$('connect').onclick = async () => {
  const S = $('peerkey').value.trim().toUpperCase()
  if (!S) return
  $('connect').disabled = true
  say(`dialing ${S}… (deriving the rendezvous id, then connecting over public infrastructure)`)
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
  if (!text) return
  if (!current) { say('Not connected yet — paste a peer\'s 26-char key above and hit Connect, then send.', 'sys err'); return }
  $('msg').value = ''
  chatLine($('log'), 'you', text, { mine: true })
  try { await current.send(text) } catch (err) { say(`send failed: ${err.message}`, 'sys err') }
}
$('send').onclick = send
$('msg').onkeydown = (e) => e.key === 'Enter' && send()

// ── group handlers ──
$('groupNew').onclick = async () => {
  // Members are set at creation (the proven, reliable path): the admin lists everyone's keys, they
  // join with the code. (add() after creation is a best-effort extra, below.)
  const memberKeys = $('groupSeed').value.trim().toUpperCase().split(/[\s,]+/).filter((k) => k.length === 26)
  $('groupNew').disabled = true
  try {
    await startGroup(newGroupSecret(), { create: true, memberKeys })
    if (memberKeys.length) gsay(`${memberKeys.length} member(s) listed — share the code so they can join.`)
    else gsay('Empty group created. Paste member keys before creating, or add them below once they\'re online.', 'sys')
  } catch (err) { gsay(`could not create the group: ${err.message}`, 'sys err'); $('groupNew').disabled = false }
}
$('groupJoin').onclick = async () => {
  const secret = $('groupSecret').value.trim()
  if (!secret) return
  $('groupJoin').disabled = true
  try { await startGroup(secret, { create: false }) }
  catch (err) { gsay(`could not join: ${err.message}`, 'sys err') }
  finally { $('groupJoin').disabled = false }
}
$('groupCopy').onclick = async () => {
  try { await navigator.clipboard.writeText($('groupCode').textContent) } catch { /* */ }
  $('groupCopy').textContent = 'Copied'
  setTimeout(() => ($('groupCopy').textContent = 'Copy'), 1200)
}
$('groupAddBtn').onclick = async () => {
  const k = $('groupAdd').value.trim().toUpperCase()
  if (!group || k.length !== 26) return
  $('groupAdd').value = ''
  gsay(`adding ${k.slice(0, 8)}… — they must open the app and Join with the group code`)
  try { await group.add(k); updateMembers() } catch (err) { gsay(`add failed: ${err.message}`, 'sys err') }
}
const groupSend = async () => {
  const text = $('groupMsg').value
  if (!text) return
  if (!group) { gsay('No group yet — create one (paste members\' keys → Create) or Join with a code above, then send.', 'sys err'); return }
  $('groupMsg').value = ''
  chatLine($('grouplog'), 'you', text, { mine: true })
  try { await group.send(text) } catch (err) { gsay(`send failed: ${err.message}`, 'sys err') }
}
$('groupSend').onclick = groupSend
$('groupMsg').onkeydown = (e) => e.key === 'Enter' && groupSend()

main()
