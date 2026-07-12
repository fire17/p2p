// test/leak-monitor.test.js — the STANDING LEAK-MONITOR (always-on, deterministic, offline).
//
// The owner's law (research/surface-hardening.md §0): "always map/analyze/observe/monitor." §7 made
// that executable: generalize privacy.test.js's observer-capture into a reusable Observer + a fixed
// no-leak battery that FAILS if any privacy invariant regresses. This is that battery — CAG check-6
// (surface-hardening §6): every hardening ships a monitor assertion that fires on regression.
//
// It OBSERVES the REAL modules (invite.js, rendezvous/tracker.js, rendezvous/dht.js, rendezvous/
// mdns.js, wire.js, transport.js) over INJECTED / LOOPBACK backends — never live mDNS/DHT (the owner
// is live-testing this machine). It does NOT modify any module internals.
//
// Invariants asserted (each a real RED-if-violated test; RED-when-broken proofs at the bottom):
//   1. no plaintext IP / port / marker on any PUBLIC surface (tracker SDP, DHT BEP44 value)   [A,B,C]
//   2. every sealed blob is the fixed 544 B — no length side-channel                            [D]
//   3. rid unlinkability: deriveRid(S) ≠ deriveInviteRid(K_inv); cross-invite & cross-epoch differ [E]
//   4. an S-holder WITHOUT K_inv can neither LOCATE nor OPEN an invite record                    [F]
//   5. the wire control-plane header is authenticated — a forged ack/close/DATA is rejected  [WIRE-1/2/3]
//   6. no pre-auth unbounded allocation — the accept table stays bounded under a PROBE flood      [DOS-1]
//   7. mDNS invite-mode surface: PINNED as the KNOWN LAN leak (MDNS-1) — see the note on that test.
//
// Companion deep proofs (not duplicated here): dos-meta-harden.test.js (full DOS-1/META-1 RED/GREEN,
// node-layer caps, rate-limit, eviction), wire.test.js (full ARQ), privacy.test.js (invite claim §10).

import test from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'node:dgram'
import { randomBytes } from 'node:crypto'
import { createTracker } from '../src/rendezvous/tracker.js'
import { createDht } from '../src/rendezvous/dht.js'
import { createMdns, _internals as mdnsInternals } from '../src/rendezvous/mdns.js'
import { createInvite, generateInviteSecret, openBlob, deriveInviteRid, SEALED_LEN } from '../src/invite.js'
import { generateIdentity, deriveRid } from '../src/key.js'
import { createChannel, encodeFrame, decodeFrame, TYPE } from '../src/wire.js'
import { createEndpoint } from '../src/transport.js'
import { Observer, CAND_SETS, assertNoLeak, trackerSurface, dhtSurface, mdnsBus, settle } from './observer.js'

const EPOCH = '2026-07-12'
const { decode: decodeDns } = mdnsInternals   // read the raw multicast frames as a LAN listener would

// ── surface drivers: seal `cands` onto a REAL surface, return the operator's captured view ─────────

/** Publish `cands` in invite mode over the REAL tracker; capture the relayed SDP. */
async function publishTracker(inv, cands) {
  const { observer, WebSocket } = trackerSurface('tracker')
  const rid = inv.rid('tracker', EPOCH, 20)
  const alice = createTracker({ trackers: ['wss://spy'], WebSocket, codec: inv.codec })
  const bob = createTracker({ trackers: ['wss://spy'], WebSocket, codec: inv.codec })
  alice.announce(rid, { candidates: cands })
  await settle()
  const got = []
  for await (const r of bob.lookup(rid, { timeout: 120 })) got.push(r)
  alice.close(); bob.close()
  return { observer, got, rid }
}

/** Publish `cands` in invite mode over the REAL DHT; capture the stored BEP44 value. */
async function publishDht(inv, cands) {
  const { observer, backend } = dhtSurface('dht')
  const rid = inv.rid('dht', EPOCH, 20)
  const dht = createDht({ dht: backend, invite: inv, now: () => 1720000000000 })
  dht.announce(rid, { candidates: cands })
  await settle()
  const got = []
  for await (const r of dht.lookup(rid, {})) got.push(r)
  dht.close()
  return { observer, got, rid, backend }
}

// ══ 1–2. no IP / port / marker + fixed 544 B, across the whole candidate battery ══════════════════

for (const [name, cands] of Object.entries(CAND_SETS)) {
  test(`leak-monitor: TRACKER invite surface leaks nothing for ${name} candidates (A,B,C,D)`, async () => {
    const inv = createInvite(generateInviteSecret())
    const { observer, got } = await publishTracker(inv, cands)
    assertNoLeak(observer, cands)                                 // A,B,C,D — throws RED on any leak
    assert.deepEqual(got[0]?.candidates, cands, 'the K_inv holder still reads the real candidates')
  })

  test(`leak-monitor: DHT invite surface leaks nothing for ${name} candidates (A,B,C,D)`, async () => {
    const inv = createInvite(generateInviteSecret())
    const { observer, got, backend, rid } = await publishDht(inv, cands)
    assertNoLeak(observer, cands)
    assert.equal(backend.puts[0].v.length, SEALED_LEN, 'BEP44 value is the fixed 544 B')
    assert.equal(inv.bep44Verify(rid, backend.puts[0].seq, backend.puts[0].v, backend.puts[0].sig), true, 'value is K_inv-signed')
    assert.deepEqual(got[0]?.candidates, cands, 'the K_inv holder still reads the real candidates')
  })
}

// ══ 3. rid unlinkability (E) ══════════════════════════════════════════════════════════════════════

test('leak-monitor: rid is unlinkable — deriveRid(S) ≠ deriveInviteRid(K_inv), cross-invite & cross-epoch differ', () => {
  const id = generateIdentity()
  const inv = createInvite(generateInviteSecret())
  const inv2 = createInvite(generateInviteSecret())
  for (const ch of ['tracker', 'dht', 'mdns']) {
    const len = ch === 'mdns' ? 32 : 20
    const ridS = deriveRid(id.S, ch, EPOCH, len)                 // everything an S-holder can compute
    const ridInv = inv.rid(ch, EPOCH, len)                       // where the invite actually lives
    assert.notEqual(ridInv.toString('hex'), ridS.toString('hex'), `${ch}: S-rid and invite-rid must differ`)
    assert.notEqual(ridInv.toString('hex'), inv2.rid(ch, EPOCH, len).toString('hex'), `${ch}: two invites must not collide`)
    assert.notEqual(ridInv.toString('hex'), inv.rid(ch, '2026-07-13', len).toString('hex'), `${ch}: rid must rotate per epoch`)
  }
})

// ══ 4. an S-holder WITHOUT K_inv can neither LOCATE nor OPEN (F) ═══════════════════════════════════

test('leak-monitor: an S-holder without K_inv cannot LOCATE the tracker record', async () => {
  const inv = createInvite(generateInviteSecret())
  const { observer, WebSocket } = trackerSurface('tracker-locate')
  const ridInv = inv.rid('tracker', EPOCH, 20)
  const alice = createTracker({ trackers: ['wss://spy'], WebSocket, codec: inv.codec })
  alice.announce(ridInv, { candidates: CAND_SETS.ipv4 })
  await settle()
  const id = generateIdentity()
  const ridS = deriveRid(id.S, 'tracker', EPOCH, 20)             // the only rid an S-holder can compute
  assert.notEqual(ridS.toString('hex'), ridInv.toString('hex'))
  const mallory = createTracker({ trackers: ['wss://spy'], WebSocket })  // no codec, no K_inv
  const got = []
  for await (const r of mallory.lookup(ridS, { timeout: 120 })) got.push(r)
  alice.close(); mallory.close()
  assert.equal(got.length, 0, 'an S-holder without K_inv finds nothing — she cannot compute rid_inv')
  assert.equal(observer.wire().includes(CAND_SETS.ipv4[0].ip), false, 'and the operator never saw the IP either')
})

test('leak-monitor: even AT the right rid, no non-K_inv key OPENS the sealed blob', () => {
  const id = generateIdentity()
  const inv = createInvite(generateInviteSecret())
  const wrong = createInvite(generateInviteSecret())
  const rid = inv.rid('tracker', EPOCH, 20)
  const sealed = inv.codec.seal({ v: 1, ts: 1, candidates: CAND_SETS.ipv4 }, rid)
  assert.equal(sealed.length, SEALED_LEN)
  for (const guess of [wrong.kIp, deriveRid(id.S, 'ip', EPOCH, 32), Buffer.alloc(32), Buffer.alloc(32, 0xff)]) {
    assert.equal(openBlob(guess, sealed, rid), null, 'a non-K_inv key decrypts nothing (AEAD tag fails)')
  }
  assert.deepEqual(openBlob(inv.kIp, sealed, rid).candidates, CAND_SETS.ipv4, 'only the invitee opens it')
})

// ══ 5. the wire control-plane header is authenticated (WIRE-1/2/3) ═════════════════════════════════
// A forged ack/close/DATA (crafted by an on-path observer / hostile relay who read the cleartext
// connId) must move NO channel state. Attacker holds neither directional MAC key.

test('leak-monitor: wire control plane is authenticated — forged ack/close/DATA are all rejected (WIRE-1/2/3)', () => {
  const connId = Buffer.alloc(8, 0xab)
  const macTx = Buffer.alloc(16, 0x11)                          // our send key
  const macRx = Buffer.alloc(16, 0x22)                          // our receive key == the real peer's send key
  const attacker = Buffer.alloc(16, 0x99)                       // the on-path forger knows NEITHER real key
  const sent = []
  const delivered = []
  const ch = createChannel({ send: (d) => sent.push(d), mac: { tx: macTx, rx: macRx }, connId, now: () => 1000 })
  ch.onReliable((p) => delivered.push(p.toString()))

  // three in-flight DATA segments waiting to be acked
  ch.sendReliable(Buffer.from('m0')); ch.sendReliable(Buffer.from('m1')); ch.sendReliable(Buffer.from('m2'))
  assert.equal(ch.stats().inflight, 3, 'precondition: 3 segments in flight')

  // WIRE-1: forged PING carrying an inflated cumulative ack — must NOT drain the send window.
  ch.onDatagram(encodeFrame(TYPE.PING, connId, 0, 0xfffffff0, null, attacker))
  assert.equal(ch.stats().inflight, 3, 'WIRE-1: forged ack did NOT drain the send window')
  assert.equal(ch.stats().authFails, 1, 'the forged frame was counted as an auth failure')

  // WIRE-2: forged CLOSE — must NOT tear the channel down.
  ch.onDatagram(encodeFrame(TYPE.CLOSE, connId, 0, 0, null, attacker))
  assert.equal(ch.closed, false, 'WIRE-2: forged CLOSE did NOT close the channel')
  assert.equal(ch.stats().authFails, 2)

  // WIRE-3: forged DATA at the predictable next seq — must NOT advance rcvNext or burn the message.
  ch.onDatagram(encodeFrame(TYPE.DATA, connId, 0, 0, Buffer.from('POISON'), attacker))
  assert.equal(ch._rcvNext, 0, 'WIRE-3: forged DATA did NOT advance the receive cursor')
  assert.deepEqual(delivered, [], 'forged DATA delivered nothing')

  // the REAL peer frame for seq 0 (MAC'd with our rx key) still lands — proof the forgery did not burn it.
  ch.onDatagram(encodeFrame(TYPE.DATA, connId, 0, 0, Buffer.from('real'), macRx))
  assert.equal(ch._rcvNext, 1, 'the authentic frame advanced the cursor')
  assert.deepEqual(delivered, ['real'], 'the authentic message for seq 0 was delivered, unharmed by the forgery')

  // and the guard is the MAC: the same forged bytes decode fine UNauthenticated (the cleartext header
  // IS forgeable) but are REJECTED under the receive key — that rejection is the whole defense.
  const forged = encodeFrame(TYPE.PING, connId, 0, 0xfffffff0, null, attacker)
  assert.equal(decodeFrame(forged)?.ack, 0xfffffff0, 'the cleartext header is readable/forgeable (pre-fix reality)')
  assert.equal(decodeFrame(forged, macRx), null, 'but the authenticated decode REJECTS it (the fix)')
})

// ══ 6. no pre-auth unbounded allocation (DOS-1 tripwire) ═══════════════════════════════════════════
// Compact monitor tripwire: a forged-PROBE flood at a REAL endpoint must leave the accept table
// bounded by the pending cap. (Full RED/GREEN + node-layer + rate-limit + eviction: dos-meta-harden.)

const PUNCH_MAGIC = 0x50327050
const PROBE = 0x01
function probePkt(tok8, nonce8) {
  const b = Buffer.alloc(21)
  b.writeUInt32BE(PUNCH_MAGIC, 0); b[4] = PROBE
  tok8.copy(b, 5); nonce8.copy(b, 13)
  return b
}
function forgeProbe(port) {
  const s = dgram.createSocket('udp4')
  return new Promise((res) => s.bind(0, () => s.send(probePkt(randomBytes(8), randomBytes(8)), port, '127.0.0.1', () => res(s))))
}

test('leak-monitor: no pre-auth unbounded allocation — accept table stays bounded under a PROBE flood (DOS-1)', async () => {
  const clock = 3_000_000
  const ep = await createEndpoint({ now: () => clock, maxPending: 8, maxAccepted: 8, acceptBurst: 1e9, probeBurst: 1e9 })
  ep.onConnection(() => {})                                     // accept inbound first-contact
  const socks = []
  for (let i = 0; i < 40; i++) socks.push(await forgeProbe(ep.port4))   // 40 fresh-source/token PROBEs
  await new Promise((r) => setTimeout(r, 150))
  assert.ok(ep._accepted.size <= 8, `_accepted bounded by the pending cap (${ep._accepted.size} <= 8)`)
  assert.ok(ep._peers.size <= 8, `_peers bounded too (${ep._peers.size} <= 8)`)
  socks.forEach((s) => s.close()); ep.close()
})

// ══ 7. mDNS invite-mode surface — MDNS-1 FIXED: the LAN blob is now SEALED ═════════════════════════
//
// This test used to PIN the leak: createMdns had no codec seam, node.js wired it without one, and so
// invite-mode mDNS broadcast the FULL plaintext candidate blob — IP and port in the clear — to every
// device on the LAN, while the tracker and DHT surfaces for the SAME invite were already sealed. It
// was a tripwire, written to flip the day mdns.js gained a codec. That day came: mdns.js now takes the
// same `codec` seam as createTracker, and node.js passes `inv.codec` to it in invite mode.
//
// WHAT WE OBSERVE MATTERS. The old pinned test watched the DECODED lookup record — which can never be
// sealed, because the invitee is precisely the party entitled to read it. A privacy claim has to be
// made against what a PASSIVE LAN LISTENER sees, so we wiretap the RAW multicast bytes leaving the
// socket. That is the surface an attacker on the coffee-shop wifi actually has.
//
// Both properties are asserted together, because sealing is only a win if discovery still works:
//   • a passive LAN listener learns NOTHING (assertNoLeak: no IP, no port, no structure, fixed size);
//   • a K_inv holder still finds and reads the record (discovery reliability is UNCHANGED).

/** A mock mDNS socket bus that also TAPS every multicast frame — a passive listener on the LAN. */
function mdnsWiretap(observer) {
  const { factory } = mdnsBus()
  return () => {
    const sock = factory()
    const send = sock.send.bind(sock)
    sock.send = (buf, port, addr, cb) => {
      observer.text(Buffer.from(buf).toString('latin1'))          // everything on the wire, verbatim
      try {
        for (const t of decodeDns(Buffer.from(buf)).txt) {        // and the sealed value itself, for the
          if (!t.strings.length || !t.strings[0].startsWith('rid=')) continue   // fixed-length check (D)
          observer.bytes(Buffer.from(t.strings.slice(1).join(''), 'base64'))
        }
      } catch { /* not a TXT answer (a query) — nothing sealed to capture */ }
      return send(buf, port, addr, cb)
    }
    return sock
  }
}

test('leak-monitor: mDNS invite-mode TXT is SEALED (MDNS-1 FIXED) — nothing leaks to the LAN', async () => {
  const inv = createInvite(generateInviteSecret())
  const observer = new Observer('mdns')
  const factory = mdnsWiretap(observer)
  const cands = CAND_SETS.ipv4
  const rid = inv.rid('mdns', EPOCH, 32)                          // where the invite actually lives

  const responder = createMdns({ socketFactory: factory, codec: inv.codec, now: () => 1000 })
  const seeker = createMdns({ socketFactory: factory, codec: inv.codec, now: () => 2000 })
  responder.announce(rid, { candidates: cands })
  const got = []
  for await (const rec of seeker.lookup(rid, { timeout: 200 })) got.push(rec)
  responder.close(); seeker.close()

  // A: no plaintext IP · B: no plaintext port · C: no marker/structure · D: every sealed value is
  // exactly SEALED_LEN, so the candidate COUNT does not leak through the length either.
  assertNoLeak(observer, cands)

  // …and discovery still works for the party that is supposed to find it. Sealing a channel that no
  // longer discovers anything would be a regression dressed up as a fix.
  assert.deepEqual(got[0]?.candidates, cands, 'a K_inv holder still resolves the record — discovery intact')
})

test('leak-monitor: a NON-holder on the same LAN cannot open the sealed mDNS record', async () => {
  const inv = createInvite(generateInviteSecret())
  const eavesdropper = createInvite(generateInviteSecret())        // same LAN, different (or no) invite
  const observer = new Observer('mdns')
  const factory = mdnsWiretap(observer)
  const rid = inv.rid('mdns', EPOCH, 32)

  const responder = createMdns({ socketFactory: factory, codec: inv.codec, now: () => 1000 })
  const spy = createMdns({ socketFactory: factory, codec: eavesdropper.codec, now: () => 2000 })
  responder.announce(rid, { candidates: CAND_SETS.ipv4 })
  const got = []
  for await (const rec of spy.lookup(rid, { timeout: 200 })) got.push(rec)   // knows WHERE, not WHAT
  responder.close(); spy.close()

  assert.deepEqual(got, [], 'a wrong-key listener opens nothing — the record is fail-closed, not just obscured')
})
