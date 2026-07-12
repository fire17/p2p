// src/browser/app.js — the browser chat UI (served at /app/). All the protocol work is in p2p.js /
// webrtc.js / group.js; this is just wiring. ponytail: no framework, no state library, no build step.
// One copy of this file runs everywhere — /app/index.html loads it by absolute path and its relative
// imports resolve against /src/browser/.

import { createHash } from 'node:crypto' // import-mapped to shim/node-crypto.js (app/index.html)
import { identity, listIdentities, listen } from './p2p.js'

const $ = (id) => document.getElementById(id)
let node = null
let pendingInviteNote = false
let myKey = null // this tab's own 26-char key — used to refuse dialing yourself

// A slot name from the URL is user-controllable, so clamp it to a safe, short shape.
const sanitizeSlot = (s) => (s || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 32) || 'default'

// The identity switcher — list every identity this browser holds; switching reloads THIS tab onto it.
async function refreshIdSwitcher(activeSlot) {
  const sel = $('idswitch')
  if (!sel) return
  const ids = await listIdentities().catch(() => [])
  sel.innerHTML = ''
  for (const it of ids) {
    const o = document.createElement('option')
    o.value = it.slot
    o.textContent = `${it.name} · ${it.S.slice(0, 6)}…`
    if (it.slot === activeSlot) o.selected = true
    sel.append(o)
  }
  if (!ids.some((i) => i.slot === activeSlot)) { // brand-new slot not yet persisted — still show it
    const o = document.createElement('option'); o.value = activeSlot; o.textContent = activeSlot; o.selected = true; sel.append(o)
  }
}

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
let groupCode = null // the SHAREABLE code (G ‖ checksum) — NOT group.secret, which is the raw G
function updateMembers() {
  if (!group) return
  const n = group.members().length
  $('groupMembers').textContent = n + (n === 1 ? ' member' : ' members')
}
function enableGroupChat(isAdmin) {
  $('groupCode').textContent = groupCode
  $('groupCopy').disabled = false
  $('groupMsg').disabled = false
  $('groupSend').disabled = false
  $('addRow').hidden = !isAdmin // only the admin can grow the group later
  updateMembers()
}
async function startGroup(code, { create = false, memberKeys = [] } = {}) {
  if (!code) return
  const secret = parseGroupCode(code) // throws on a typo — the caller reports it, never a ghost group
  groupCode = code
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

// ── the group CODE ──
//
//   CODE = base64( G(32B) ‖ SHA256(G)[0..3) )        — 35 bytes, 48 chars
//
// The 3-byte checksum kills the GHOST GROUP: raw base64(G) carries no redundancy, so one mistyped
// character that stays valid base64 decodes to a DIFFERENT G — a different groupId — and the victim
// gets a cheerful "Joined" while sitting alone in a group nobody else is in, forever, with no error.
// A typo must fail LOUDLY here instead. G itself is unchanged (still the 32-byte group secret), so
// group.js is untouched — this is only the human-facing encoding.
//
// bin/p2p-group.js mints and parses the SAME bytes (same sync SHA-256: node:crypto there, the
// node-crypto shim here), so a code minted in the terminal joins here and vice-versa.
const codeSum = (G) => createHash('sha256').update(G).digest().subarray(0, 3)

function newGroupCode() {
  const b = new Uint8Array(32)
  globalThis.crypto.getRandomValues(b)
  const G = Buffer.from(b)
  return Buffer.concat([G, codeSum(G)]).toString('base64')
}

/** Validate a pasted code → the raw 32-byte G. Throws (loudly) on anything but an exact code. */
function parseGroupCode(code) {
  const s = String(code || '').trim()
  if (!s) throw new Error('no group code given')
  const raw = Buffer.from(s, 'base64')
  if (raw.length !== 35) throw new Error(`bad group code (decodes to ${raw.length} bytes, expected 35) — paste the whole code`)
  if (raw.toString('base64') !== s) throw new Error('bad group code (not valid base64) — paste it exactly, no spaces')
  const G = raw.subarray(0, 32)
  if (!codeSum(G).equals(raw.subarray(32))) {
    throw new Error('bad group code (checksum failed) — you likely mistyped or truncated it. Ask for the code again and paste it whole.')
  }
  return Buffer.from(G)
}

async function main() {
  try {
    // Deep link FIRST (needs only the DOM, not the network): /app/#<26-CHAR-KEY> pre-fills the dial
    // box; /app/#<group-code> pre-fills the group Join box. A share string (`S-<tail>`, one-time
    // invite) is DETECTED and reported honestly — invite dialing isn't wired in the browser yet
    // (fast-follow), so we don't silently misroute it to the group box. Done before going online.
    // The hash carries TWO things now: an optional identity slot (`id=<name>`) that picks WHICH of
    // this browser's identities this tab uses (so two normal windows can be two different peers), and
    // the existing deep link (a 26-char key / group code / share string). Parse the slot out first,
    // then treat whatever remains exactly as before.
    const rawHash = decodeURIComponent(location.hash.replace(/^#/, ''))
    let slot = 'default'
    const fragParts = []
    for (const seg of rawHash.split('&')) {
      const m = /^id=(.+)$/.exec(seg)
      if (m) slot = sanitizeSlot(m[1])
      else if (seg) fragParts.push(seg)
    }
    const frag = fragParts.join('&').trim()

    const isShareString = /^[0-9A-Za-z]{26}-\S+$/.test(frag) // 26-char S + '-' + invite tail
    if (isShareString) {
      showTab('pair')
      pendingInviteNote = true // one-time invite — surfaced once we're online (say() needs the log)
    } else if (frag.length === 26) { $('peerkey').value = frag.toUpperCase(); showTab('pair') }
    else if (frag.length > 26) { $('groupSecret').value = frag; showTab('group') }

    const id = await identity({ slot })
    myKey = id.S
    $('mykey').textContent = id.S
    $('idname').textContent = slot
    await refreshIdSwitcher(slot)
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

// ── identity handlers ──
// Switch this tab to another identity — reload onto its slot (the slot is read at boot).
$('idswitch').onchange = () => {
  const next = $('idswitch').value
  location.hash = 'id=' + next
  location.reload()
}
// Mint a brand-new identity and open it in a NEW window — so you instantly have a second peer to chat
// with. The new window boots on a fresh slot, which first-runs a new keypair (BRW-2-safe).
$('newId').onclick = async () => {
  const ids = await listIdentities().catch(() => [])
  const used = new Set(ids.map((i) => i.slot))
  let n = ids.length + 1
  let next = 'id-' + n
  while (used.has(next)) next = 'id-' + (++n)
  window.open(location.pathname + '#id=' + next, '_blank')
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
  if (myKey && S === myKey) {
    // Dialing your own key connects you to yourself — the exact "message went to myself" trap. Refuse
    // it and point at the fix: a second identity in this browser, or an incognito window.
    say('That\'s your OWN key — you can\'t chat with yourself. Click “＋ New identity” (top) to open a second identity in another window, or use an incognito window, then dial THAT window\'s key.', 'sys err')
    return
  }
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
// NB: a DOM0 onkeydown that RETURNS false calls preventDefault — cancelling the keystroke. The old
// `(e) => e.key === 'Enter' && send()` returned false for every non-Enter key, so nothing could be
// typed. Use a statement body that returns undefined so normal typing is never cancelled.
$('msg').onkeydown = (e) => { if (e.key === 'Enter') send() }

// ── group handlers ──
$('groupNew').onclick = async () => {
  // Members are set at creation (the proven, reliable path): the admin lists everyone's keys, they
  // join with the code. (add() after creation is a best-effort extra, below.)
  const memberKeys = $('groupSeed').value.trim().toUpperCase().split(/[\s,]+/).filter((k) => k.length === 26)
  $('groupNew').disabled = true
  try {
    await startGroup(newGroupCode(), { create: true, memberKeys })
    if (memberKeys.length) gsay(`${memberKeys.length} member(s) listed — share the code so they can join.`)
    else gsay('Empty group created. Paste member keys before creating, or add them below once they\'re online.', 'sys')
  } catch (err) { gsay(`could not create the group: ${err.message}`, 'sys err'); $('groupNew').disabled = false }
}
$('groupJoin').onclick = async () => {
  const code = $('groupSecret').value.trim()
  if (!code) return
  $('groupJoin').disabled = true
  // A mistyped code now THROWS in startGroup (checksum) and lands here — loudly — instead of quietly
  // "joining" a groupId nobody else shares.
  try { await startGroup(code, { create: false }) }
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
$('groupMsg').onkeydown = (e) => { if (e.key === 'Enter') groupSend() }

main()
