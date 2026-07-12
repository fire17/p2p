// test/invite.test.js — the per-invite secret K_inv: derivations (KAT), share-string codec,
// sealed candidate blob, BEP44 key agreement, and Noise IKpsk2.
// Deterministic, offline. Design: research/metadata-privacy.md §3–§5.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  createInvite, generateInviteSecret, encodeInvite, decodeInvite, formatShare, parseShare,
  deriveInviteRid, sealBlob, openBlob, bep44SignInput, INVITE_FLAG, hasInvite, SEALED_LEN, TypoError,
} from '../src/invite.js'
import { generateIdentity, encodeKey, decodeKey, verifyCommitment } from '../src/key.js'
import { initiator, responder, HandshakeError } from '../src/noise.js'
import { createPublicKey, createPrivateKey } from 'node:crypto'

const X_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex')
const xPubFromPriv = (raw) => Buffer.from(
  createPublicKey(createPrivateKey({ key: Buffer.concat([X_PKCS8, raw]), format: 'der', type: 'pkcs8' }))
    .export({ type: 'spki', format: 'der' }).subarray(-32))

// ── KAT vectors ───────────────────────────────────────────────────────────────
// Frozen against the implementation on 2026-07-12. They pin the four domain-separated derivations
// of §3.2: any change to a salt/info/length is a wire break and MUST fail these.
const K = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex') // the 128-bit K_inv under test
const EPOCH = '2026-07-12'
const KAT = {
  token: '000G40R40M30E209185GR38E1ZPD',
  ridDht: '413e0861b8114bfd4f105e82f06937d39beaecd2',
  ridTracker: '60e834cb9c4851f451a059cf7b092aecd81fc265',
  kIp: 'fbb639f001303c5600fa7ab86c539e2a45a53e96fee2561a5d42bd87879c6cd3',
  psk: '0b8e9ee5b9017df3a8b1ac40b46703b702e370bb4a26c5f7875f86ac3a62bf89',
  bepPub: '88bc3d2e51c407227dd9b6290dc87c2bec95abad044e918aef2ee347c4cc87eb',
  target: '4fbe7e7398bee0413cfc8c3dbdca4ae9768d23e2',
}

test('KAT: the four K_inv derivations are stable and domain-separated', () => {
  const inv = createInvite(K)
  assert.equal(inv.rid('dht', EPOCH, 20).toString('hex'), KAT.ridDht)
  assert.equal(inv.rid('tracker', EPOCH, 20).toString('hex'), KAT.ridTracker)
  assert.equal(inv.kIp.toString('hex'), KAT.kIp)
  assert.equal(inv.psk.toString('hex'), KAT.psk)
  assert.equal(inv.bepPub.toString('hex'), KAT.bepPub)
  assert.equal(inv.bep44Target(inv.rid('dht', EPOCH, 20)).toString('hex'), KAT.target)
  // domain separation: no two derivations ever collide, and the epoch/channel actually move the rid
  const all = [inv.kIp, inv.psk, inv.rid('dht', EPOCH, 32), inv.rid('tracker', EPOCH, 32)].map((b) => b.toString('hex'))
  assert.equal(new Set(all).size, all.length)
  assert.notEqual(inv.rid('dht', EPOCH, 20).toString('hex'), inv.rid('dht', '2026-07-13', 20).toString('hex'))
})

test('rid_inv lives in the p2p-rvk namespace (never collides with an S-derived rid)', () => {
  // The salt namespace is what keeps invite-mode rids unlinkable from public-mode rids (§3.2).
  const a = deriveInviteRid(K, 'dht', EPOCH, 20)
  const b = deriveInviteRid(K, 'tracker', EPOCH, 20)
  assert.notEqual(a.toString('hex'), b.toString('hex'))
  assert.equal(a.length, 20)
})

// ── share string ──────────────────────────────────────────────────────────────

test('invite token: encode/decode round-trips at 128 and 256 bits', () => {
  assert.equal(encodeInvite(K), KAT.token)
  assert.equal(KAT.token.length, 28)
  assert.ok(decodeInvite(KAT.token).equals(K))
  const k256 = generateInviteSecret(256)
  const t = encodeInvite(k256)
  assert.equal(t.length, 54) // strict Noise-§14 psk entropy option
  assert.ok(decodeInvite(t).equals(k256))
  for (let i = 0; i < 20; i++) {
    const k = generateInviteSecret()
    assert.ok(decodeInvite(encodeInvite(k)).equals(k))
  }
})

test('invite token: typo checksum rejects before any network work', () => {
  const t = encodeInvite(K)
  const bad = (t[0] === '0' ? '1' : '0') + t.slice(1) // flip one char
  assert.throws(() => decodeInvite(bad), TypoError)
  assert.throws(() => decodeInvite(t.slice(0, 27)), TypoError)   // truncated
  assert.throws(() => decodeInvite(t + 'X'), TypoError)          // over-long
  assert.throws(() => decodeInvite('!'.repeat(28)), TypoError)   // non-alphabet
  // case-insensitive + Crockford ambiguity mapping (I/L→1, O→0) still validate
  assert.ok(decodeInvite(t.toLowerCase()).equals(K))
})

test('share string: S-INV parses; bare S stays reusable mode', () => {
  const id = generateIdentity()
  const share = formatShare(id.S, K)
  assert.equal(share, id.S + '-' + KAT.token)
  const p = parseShare(share)
  assert.equal(p.invite, true)
  assert.equal(p.S, id.S)
  assert.ok(p.secret.equals(K))

  const bare = parseShare(id.S)
  assert.equal(bare.invite, false)
  assert.equal(bare.secret, null)
  assert.equal(bare.S, id.S)

  assert.ok(parseShare(share.toLowerCase()).secret.equals(K))   // case-insensitive as one unit
  assert.throws(() => parseShare(id.S + '-' + 'X'.repeat(28)), TypoError) // bad invite half
})

test('the reserved version/flags bit selects invite mode inside S (no key.js change)', () => {
  const id = generateIdentity()
  assert.equal(hasInvite(decodeKey(id.S).version), false)          // default S: reusable mode
  const sInv = encodeKey(id.edPub, id.xPub, INVITE_FLAG)           // stamp the reserved bit
  const dec = decodeKey(sInv)
  assert.equal(hasInvite(dec.version), true)
  assert.ok(dec.commitment.equals(decodeKey(id.S).commitment))     // same identity, same commitment
})

// ── the sealed candidate blob ─────────────────────────────────────────────────

const BLOB = { v: 1, ts: 1720000000000, candidates: [{ proto: 'udp4', ip: '203.0.113.7', port: 41234, kind: 'srflx' }] }

test('sealed blob: round-trips, is fixed-length, and never contains the IP', () => {
  const inv = createInvite(K)
  const rid = inv.rid('tracker', EPOCH, 20)
  const sealed = sealBlob(inv.kIp, BLOB, rid)
  assert.equal(sealed.length, SEALED_LEN)
  assert.equal(SEALED_LEN, 544)
  assert.equal(sealed.includes(Buffer.from('203.0.113.7', 'utf8')), false) // no plaintext IP anywhere
  assert.deepEqual(openBlob(inv.kIp, sealed, rid), BLOB)
})

test('sealed blob: padding hides the candidate count (all seals are the same length)', () => {
  const inv = createInvite(K)
  const rid = inv.rid('tracker', EPOCH, 20)
  const one = sealBlob(inv.kIp, BLOB, rid)
  const many = sealBlob(inv.kIp, {
    v: 1, ts: 1, candidates: Array.from({ length: 4 }, (_, i) => ({ proto: 'udp4', ip: '10.0.0.' + i, port: 5000 + i, kind: 'host' })),
  }, rid)
  const empty = sealBlob(inv.kIp, { v: 1, ts: 1, candidates: [] }, rid)
  assert.equal(one.length, many.length)
  assert.equal(one.length, empty.length)
})

test('sealed blob: fresh salt per seal (no nonce reuse), same plaintext ⇒ different ciphertext', () => {
  const inv = createInvite(K)
  const rid = inv.rid('tracker', EPOCH, 20)
  const a = sealBlob(inv.kIp, BLOB, rid)
  const b = sealBlob(inv.kIp, BLOB, rid)
  assert.notEqual(a.toString('hex'), b.toString('hex'))
  assert.notEqual(a.subarray(0, 16).toString('hex'), b.subarray(0, 16).toString('hex')) // the 16-byte seal salt
  assert.deepEqual(openBlob(inv.kIp, a, rid), openBlob(inv.kIp, b, rid))
})

test('sealed blob: tamper, wrong key, wrong rid (AD), and truncation all fail closed to null', () => {
  const inv = createInvite(K)
  const rid = inv.rid('tracker', EPOCH, 20)
  const sealed = sealBlob(inv.kIp, BLOB, rid)

  for (const i of [0, 20, 100, sealed.length - 1]) {           // salt byte, ct byte, ct byte, tag byte
    const t = Buffer.from(sealed)
    t[i] ^= 0x01
    assert.equal(openBlob(inv.kIp, t, rid), null, 'tampered byte ' + i + ' must not open')
  }
  const other = createInvite(generateInviteSecret())
  assert.equal(openBlob(other.kIp, sealed, rid), null)                       // wrong K_inv
  assert.equal(openBlob(inv.kIp, sealed, inv.rid('dht', EPOCH, 20)), null)   // wrong rid ⇒ AD mismatch (anti-replay)
  assert.equal(openBlob(inv.kIp, sealed.subarray(0, 200), rid), null)        // truncated
  assert.equal(openBlob(inv.kIp, Buffer.alloc(SEALED_LEN), rid), null)       // all-zero garbage
})

// ── BEP44 (§4.2) ──────────────────────────────────────────────────────────────

test('BEP44: both sides derive the SAME keypair/target from K_inv; a different K_inv never does', () => {
  const alice = createInvite(K)
  const bob = createInvite(decodeInvite(encodeInvite(K)))   // Bob only ever had the share string
  const rid = alice.rid('dht', EPOCH, 20)
  assert.ok(alice.bepPub.equals(bob.bepPub))
  assert.ok(alice.bep44Target(rid).equals(bob.bep44Target(rid)))
  assert.equal(alice.bep44Target(rid).length, 20)           // SHA1(pubkey ‖ salt)

  const mallory = createInvite(generateInviteSecret())
  assert.equal(mallory.bepPub.equals(alice.bepPub), false)
  assert.equal(mallory.bep44Target(rid).equals(alice.bep44Target(rid)), false)
})

test('BEP44: signature verifies for the invitee, fails on tamper or a foreign key', () => {
  const alice = createInvite(K)
  const bob = createInvite(K)
  const rid = alice.rid('dht', EPOCH, 20)
  const v = alice.codec.seal(BLOB, rid)
  const seq = 1720000000
  const sig = alice.bep44Sign(rid, seq, v)
  assert.equal(sig.length, 64)
  assert.equal(bob.bep44Verify(rid, seq, v, sig), true)

  const bad = Buffer.from(v); bad[5] ^= 0xff
  assert.equal(bob.bep44Verify(rid, seq, bad, sig), false)         // value tampered
  assert.equal(bob.bep44Verify(rid, seq + 1, v, sig), false)       // seq tampered
  assert.equal(createInvite(generateInviteSecret()).bep44Verify(rid, seq, v, sig), false) // foreign key
  // the signed bytes are BEP44's exact form: "4:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>"
  const inputStr = bep44SignInput(rid, seq, v).toString('binary')
  assert.ok(inputStr.startsWith('4:salt20:'))
  assert.ok(inputStr.includes('3:seqi' + seq + 'e1:v544:'))
})

// ── Noise IKpsk2 (§5) ─────────────────────────────────────────────────────────

const hs = (psk) => {
  const a = generateIdentity() // responder (the inviter)
  const b = generateIdentity() // initiator (the invitee)
  return {
    ini: (p) => initiator({ localX: { pub: b.xPub, priv: b.xPriv }, remoteXPub: a.xPub, ...(p ? { psk: p } : {}) }),
    res: (p) => responder({ localX: { pub: a.xPub, priv: a.xPriv }, ...(p ? { psk: p } : {}) }),
    psk,
  }
}

test('IKpsk2: handshake succeeds when BOTH sides hold the K_inv-derived psk', () => {
  const inv = createInvite(K)
  const h = hs(inv.psk)
  const i = h.ini(inv.psk), r = h.res(inv.psk)
  const msg1 = i.writeMessage(Buffer.from('hello'))
  assert.equal(r.readMessage(msg1).toString(), 'hello')
  const msg2 = r.writeMessage(Buffer.from('ack'))
  assert.equal(i.readMessage(msg2).toString(), 'ack')          // msg2 decrypt == the first-ack == MITM proof
  const si = i.split(), sr = r.split()
  assert.ok(si.handshakeHash.equals(sr.handshakeHash))
  assert.equal(sr.rx.decrypt(si.tx.encrypt(Buffer.from('data'))).toString(), 'data')
})

test('IKpsk2: the handshake FAILS with a wrong psk (a different invite)', () => {
  const inv = createInvite(K)
  const wrong = createInvite(generateInviteSecret())
  const h = hs(inv.psk)
  const i = h.ini(wrong.psk), r = h.res(inv.psk)
  const msg1 = i.writeMessage()                                 // msg1 has no psk token yet → readable
  r.readMessage(msg1)
  const msg2 = r.writeMessage()                                 // psk is mixed at the END of msg2
  assert.throws(() => i.readMessage(msg2), HandshakeError)      // wrong psk ⇒ different ck/h ⇒ tag fails
})

test('IKpsk2: the handshake FAILS when one side has NO psk (pattern mismatch, fail-closed)', () => {
  const inv = createInvite(K)
  const h = hs(inv.psk)
  // invitee has K_inv, responder doesn't (or vice versa): protocol names differ ⇒ h/ck differ from msg1
  const i1 = h.ini(inv.psk), r1 = h.res(null)
  assert.throws(() => r1.readMessage(i1.writeMessage()), HandshakeError)

  const i2 = h.ini(null), r2 = h.res(inv.psk)
  assert.throws(() => r2.readMessage(i2.writeMessage()), HandshakeError)
})

test('psk is additive: with no psk the handshake is plain IK, unchanged', () => {
  const h = hs(null)
  const i = h.ini(null), r = h.res(null)
  const msg1 = i.writeMessage(Buffer.from('x'))
  assert.equal(r.readMessage(msg1).toString(), 'x')
  const msg2 = r.writeMessage()
  i.readMessage(msg2)
  assert.equal(i.split().handshakeHash.equals(r.split().handshakeHash), true)
  // msg2 carries no psk material: e(32) + payload tag(16) — the exact v0.1.0 IK msg2 shape
  assert.equal(msg2.length, 32 + 16)
})

test('psk must be 32 bytes (fail-closed on a malformed psk)', () => {
  const id = generateIdentity()
  assert.throws(() => responder({ localX: { pub: id.xPub, priv: id.xPriv }, psk: Buffer.alloc(16) }), HandshakeError)
  assert.throws(() => responder({ localX: { pub: id.xPub, priv: id.xPriv }, psk: 'not-a-buffer' }), HandshakeError)
})

test('handshakePrologue: a FIXED invite-scoped value both sides derive from K_inv alone', () => {
  const a = createInvite(K)
  const b = createInvite(decodeInvite(encodeInvite(K)))     // Bob, from the share string only
  const pa = a.handshakePrologue()
  // independent of channel, epoch, and rid (that is the whole point — it MixHashes before msg1)
  assert.ok(pa.equals(b.handshakePrologue()))
  assert.ok(pa.equals(a.handshakePrologue()))               // stable across calls
  assert.equal(pa.subarray(0, 10).toString('ascii'), 'p2p-inv-v1')
  assert.equal(pa.length, 10 + 32)
  // a different invite yields a different prologue (invite-scoped)
  assert.equal(createInvite(generateInviteSecret()).handshakePrologue().equals(pa), false)
  // and it drives a real IKpsk2 handshake to completion end-to-end
  const alice = generateIdentity(), bob = generateIdentity()
  const i = initiator({ localX: { pub: bob.xPub, priv: bob.xPriv }, remoteXPub: alice.xPub, psk: a.psk, prologue: a.handshakePrologue() })
  const r = responder({ localX: { pub: alice.xPub, priv: alice.xPriv }, psk: b.psk, prologue: b.handshakePrologue() })
  r.readMessage(i.writeMessage())
  i.readMessage(r.writeMessage())
  assert.ok(i.split().handshakeHash.equals(r.split().handshakeHash))
})

// ── frozen IKpsk2 transcript KAT (Noise §9.2 conformance canary) ────────────────
// Fixed statics + ephemerals + psk ⇒ a deterministic wire transcript. This pins the §9.2 rule that
// every MixHash(e) is followed by MixKey(e) in PSK mode: drop either MixKey(e) call and these bytes
// change and the test fails. The plain-IK KAT (test/vectors, cross-checked byte-exact vs snow AND
// cacophony in noise.test.js) is untouched by this change.
// D-INT-1 gap (documented, honest): these bytes are SELF-CONSISTENT, not cross-checked against an
// external IKpsk2 implementation — no offline snow/cacophony IKpsk2 vector was obtainable in-tree.
// The §9.2 arithmetic is verified by construction here; an external cross-check stays an open gap.
const PSK_KAT = {
  iStatic: Buffer.alloc(32, 0x11), rStatic: Buffer.alloc(32, 0x22),
  iEph: Buffer.alloc(32, 0x33), rEph: Buffer.alloc(32, 0x44), psk: Buffer.alloc(32, 0x55),
  prologue: Buffer.from('p2p-inv-kat-v1', 'ascii'),
  msg1: '7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b144b3944efabe6dbf0bbf813c9a6b1fd373da6585a9d41e0f4d219fb69bd0be935e96c0d71be1e166376ade348312ea05df38805151ca7280a8d862f485ce8132a85f615645466e429',
  msg2: 'ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b23ffba215f19ad24752396197126548b8650024c78a6daf4',
  handshakeHash: 'bcc49c7f9decc382bceae8abbaada37d1085dea47ec5a834b46c3d362a969bd4',
  t1: 'ea3ece904ffd6892104b66770a1a400d8368bfbd6cca',
  t2: 'c38763ce75f434021493bd57a2e613991df8df0b63bf',
}

test('KAT: IKpsk2 transcript is byte-frozen (locks in the §9.2 MixKey(e) fix)', () => {
  const k = PSK_KAT
  const rStaticPub = xPubFromPriv(k.rStatic)
  const hi = initiator({ localX: { priv: k.iStatic, pub: xPubFromPriv(k.iStatic) }, remoteXPub: rStaticPub, prologue: k.prologue, psk: k.psk, _ephemeral: k.iEph })
  const hr = responder({ localX: { priv: k.rStatic, pub: rStaticPub }, prologue: k.prologue, psk: k.psk, _ephemeral: k.rEph })

  const msg1 = hi.writeMessage(Buffer.from('psk-msg1'))
  assert.equal(msg1.toString('hex'), k.msg1)
  assert.equal(hr.readMessage(msg1).toString(), 'psk-msg1')
  const msg2 = hr.writeMessage(Buffer.from('psk-msg2'))
  assert.equal(msg2.toString('hex'), k.msg2)
  assert.equal(hi.readMessage(msg2).toString(), 'psk-msg2')

  const si = hi.split(), sr = hr.split()
  assert.equal(si.handshakeHash.toString('hex'), k.handshakeHash)
  assert.ok(si.handshakeHash.equals(sr.handshakeHash))
  assert.equal(si.tx.encrypt(Buffer.from('t-init')).toString('hex'), k.t1)
  assert.equal(sr.tx.encrypt(Buffer.from('t-resp')).toString('hex'), k.t2)
})

// ── composed full-MITM (threat table row 7): commitment gate + IKpsk2 together ──────────────────

test('row 7 full MITM: a substituted static is caught by the gate AND by IKpsk2 (no K_inv, no priv key)', () => {
  // Alice mints an invite; her S commits to (edPub,xPub). Mallory sits in the middle with her OWN
  // static keypair and no K_inv. Two independent defenses must each reject her, composed:
  const alice = generateIdentity()
  const inv = createInvite(K)
  const dec = decodeKey(encodeKey(alice.edPub, alice.xPub, INVITE_FLAG))
  const mallory = generateIdentity()

  // (1) COMMITMENT GATE: Mallory sends her own pubkeys in HELLO; the gate binds them to Alice's S.
  assert.equal(verifyCommitment(dec.commitment, mallory.edPub, mallory.xPub), false, 'gate rejects a substituted static')
  assert.equal(verifyCommitment(dec.commitment, alice.edPub, alice.xPub), true, 'the real owner passes the gate')

  // (2) IKpsk2: even if Mallory bypassed the (cheap, non-auth) gate, she lacks K_inv. Bob (the
  // invitee) runs the responder with the real psk; Mallory initiates against Bob with her own static
  // AND no/garbage psk. The handshake fails closed — she cannot derive Bob's ck/h.
  const bob = generateIdentity() // the invitee (initiator side in this direction)
  const responderHs = responder({ localX: { pub: bob.xPub, priv: bob.xPriv }, psk: inv.psk })
  const malloryHs = initiator({ localX: { pub: mallory.xPub, priv: mallory.xPriv }, remoteXPub: bob.xPub, psk: createInvite(generateInviteSecret()).psk })
  responderHs.readMessage(malloryHs.writeMessage())               // msg1 carries no psk token yet
  const msg2 = responderHs.writeMessage()                          // psk mixed at end of msg2
  assert.throws(() => malloryHs.readMessage(msg2), HandshakeError, 'IKpsk2 fails without the real K_inv')

  // and the legitimate invitee (real psk, gate passes) completes end to end
  const okRes = responder({ localX: { pub: bob.xPub, priv: bob.xPriv }, psk: inv.psk })
  const okIni = initiator({ localX: { pub: mallory.xPub, priv: mallory.xPriv }, remoteXPub: bob.xPub, psk: inv.psk })
  okRes.readMessage(okIni.writeMessage())
  okIni.readMessage(okRes.writeMessage())
  assert.ok(okIni.split().handshakeHash.equals(okRes.split().handshakeHash))
})
