// src/group.js — groups (DESIGN D10 → research/browser-client.md §7 / BC-7).
//
// TWO layers live here, and the second is built ON the first:
//
//   createGroup(node, keys)        — v1 pairwise fan-out. A group is a named set of contact keys;
//                                    send() loops the members and does an ordinary peer.send() to
//                                    each over its existing Noise link. Unchanged, still exported,
//                                    still the right answer for "just fan these bytes out".
//
//   createSecureGroup(node, id, …) — the real group (BC-7): SENDER KEYS + a SIGNED MEMBERSHIP
//                                    HASH-CHAIN + causal (DAG) ordering + BLIND PEER-RELAY, all
//                                    riding the SAME pairwise Noise links. No new transport, no
//                                    new infra, no server, and the rendezvous still sees nothing.
//
// WHY (what pairwise fan-out cannot do): n encryptions per message; no agreed membership (Alice's
// "group" and Bob's are unrelated local lists); no per-sender authentication *to the group* (over a
// 1:1 link a receiver learns who sent it, but a message RELAYED through a third member carries no
// proof of authorship — and a plain shared group key would let ANY member forge ANY other's
// messages); no ordering; and removal is "stop sending" rather than a cryptographic ejection.
//
// HOW (three thin layers, ~all of it plain JS above the transport, so browser and TUI run the SAME
// code and group interop follows automatically from 1:1 interop):
//
//   (a) identity      groupId = SHA256("p2p-grp-v1" ‖ G) for a 32-byte group secret G.
//   (b) content       Each member holds a SENDER KEY: a 32-byte chain key ratcheted one-way per
//                     message (mk_i = HMAC(ck_i,0x01); ck_{i+1} = HMAC(ck_i,0x02) — the same shape
//                     as noise.js's hkdf2). One ChaCha20-Poly1305 encryption per message (not n),
//                     plus an Ed25519 signature by the AUTHOR: no member can impersonate another,
//                     and a relayed message is still provably authentic. Chain keys are handed out
//                     over the existing pairwise Noise links, which is what makes distribution both
//                     confidential AND authenticated — zero new key-exchange crypto.
//                     Forward secrecy: yes (one-way ratchet). Post-compromise security: NOT until a
//                     rotation — the known sender-keys gap (arXiv 2301.07045), stated honestly. It
//                     is the same FS posture the 1:1 chat already has (session-granular, D4), so the
//                     group is not weaker than the chat it is built from.
//   (c) membership    Every op (create/add/remove/rotate) is SIGNED by its author and HASH-LINKS to
//                     the ops it saw → an append-only tamper-evident DAG. Membership = a
//                     deterministic fold over that chain, so every member computes the same answer
//                     with no server. Authorship is bound to the 26-char key by the SAME commitment
//                     the handshake gate uses (verifyCommitment(S, edPub, xPub)) — a forged author
//                     would need a 2^110 second-preimage.
//                     Removal = the survivors rotate their sender keys and redistribute to
//                     survivors only ⇒ the removed member is cryptographically ejected from all
//                     FUTURE traffic (it keeps, as it must, what it could already read).
//                     Fork honesty: two partitioned admins can produce divergent chains. Hash-links
//                     make that DETECTABLE (different heads), never silent — same posture as Matrix
//                     state-res. Not prevented; surfaced.
//
// Ordering: each message names the heads it saw (parents) → causal DAG, reconstructed locally.
// Relaying: a member that cannot be reached directly is served by asking a member who CAN reach it
// to forward the byte-identical signed ciphertext. The relay is BLIND — it holds no sender key it
// wasn't given, cannot forge the signature, and is exactly as untrusted as a TURN box.
//
// The infra sees: an opaque rid and ciphertext. Unchanged from 1:1.
//
// Zero deps.

import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { signEd, verifyEd } from './sign.js'
import { decodeKey, verifyCommitment } from './key.js'

// ── v1: pairwise fan-out (unchanged) ─────────────────────────────────────────────────────────

/**
 * @param {object} node   a node from node.listen()
 * @param {string[]} keys contact strings (S) of the members
 * @returns {{keys:string[], send:(data:(Buffer|string))=>Promise<any[]>, members:()=>string[], size:number}}
 */
export function createGroup(node, keys) {
  const members = [...new Set((keys || []).map((k) => String(k).toUpperCase()))]

  return {
    keys: members,
    get size() { return members.length },
    members() { return [...members] },

    /**
     * Fan `data` to every member over its existing Noise link. A member that fails to connect/send
     * yields an {error} entry instead of rejecting the whole fan-out (partial delivery is honest).
     * @param {Buffer|string} data
     * @returns {Promise<Array<{key:string, ack?:any, error?:Error}>>}
     */
    async send(data) {
      return Promise.all(members.map(async (key) => {
        try {
          const peer = await node.connect(key)
          const ack = await peer.send(data)
          return { key, ack }
        } catch (error) {
          return { key, error }
        }
      }))
    },
  }
}

// ── secure groups: wire ──────────────────────────────────────────────────────────────────────

const GMAGIC = 0x67 // 'g' — first byte of every group envelope, inside the pairwise Noise plaintext
const T = Object.freeze({ KEYDIST: 1, MSG: 2, OP: 3, RELAY: 4, KEYREQ: 5 })
const TAGLEN = 16
const MAX_SKIP = 1000 // ratchet skip-ahead bound (a lost message must not strand the chain)

const sha256 = (...p) => { const h = createHash('sha256'); for (const x of p) h.update(x); return h.digest() }
const utf8 = (s) => Buffer.from(s, 'utf8')
const b64 = (b) => Buffer.from(b).toString('base64')
const unb64 = (s) => Buffer.from(String(s), 'base64')

/** groupId = SHA256("p2p-grp-v1" ‖ G) — an opaque 32-byte label; G itself never leaves the client. */
export function groupIdFor(G) {
  return sha256(utf8('p2p-grp-v1'), Buffer.from(G))
}

/** Envelope: [1B GMAGIC][1B type][32B groupId][JSON body]. Rides INSIDE the pairwise Noise link. */
function encodeEnv(type, groupId, body) {
  const j = utf8(JSON.stringify(body))
  const b = Buffer.allocUnsafe(2 + 32 + j.length)
  b[0] = GMAGIC; b[1] = type
  Buffer.from(groupId).copy(b, 2)
  j.copy(b, 34)
  return b
}
function decodeEnv(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 35 || buf[0] !== GMAGIC) return null
  try {
    return { type: buf[1], groupId: buf.subarray(2, 34), body: JSON.parse(buf.subarray(34).toString('utf8')) }
  } catch { return null } // malformed group frame — drop, never throw into the app
}

// ── sender-key ratchet ───────────────────────────────────────────────────────────────────────

/** mk_i = HMAC(ck_i, 0x01) ; ck_{i+1} = HMAC(ck_i, 0x02) — one-way ⇒ forward secrecy. */
const msgKey = (ck) => createHmac('sha256', ck).update(Buffer.from([1])).digest()
const nextCk = (ck) => createHmac('sha256', ck).update(Buffer.from([2])).digest()

/** Nonce: 4 zero bytes ‖ u64 LE seq — same encoding discipline as noise.js:140. */
function nonceFor(seq) {
  const n = Buffer.alloc(12)
  n.writeBigUInt64LE(BigInt(seq), 4)
  return n
}

/** A ratchet the SENDER advances; receivers hold one of these per sender and skip-ahead on loss. */
function ratchet(chainKey, startSeq = 0) {
  return { ck: Buffer.from(chainKey), seq: startSeq, skipped: new Map() }
}
function keyForSeq(r, seq) {
  if (r.skipped.has(seq)) { const k = r.skipped.get(seq); r.skipped.delete(seq); return k }
  if (seq < r.seq) return null // already consumed and not cached — replay or ancient
  if (seq - r.seq > MAX_SKIP) return null // absurd jump — refuse (fail closed)
  while (r.seq < seq) { r.skipped.set(r.seq, msgKey(r.ck)); r.ck = nextCk(r.ck); r.seq++ }
  const k = msgKey(r.ck)
  r.ck = nextCk(r.ck); r.seq++
  return k
}

const aeadEnc = (key, seq, aad, pt) => {
  const c = createCipheriv('chacha20-poly1305', key, nonceFor(seq), { authTagLength: TAGLEN })
  c.setAAD(aad, { plaintextLength: pt.length })
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()])
}
const aeadDec = (key, seq, aad, ct) => {
  if (ct.length < TAGLEN) throw new Error('group ciphertext shorter than tag')
  const d = createDecipheriv('chacha20-poly1305', key, nonceFor(seq), { authTagLength: TAGLEN })
  d.setAAD(aad, { plaintextLength: ct.length - TAGLEN })
  d.setAuthTag(ct.subarray(ct.length - TAGLEN))
  return Buffer.concat([d.update(ct.subarray(0, ct.length - TAGLEN)), d.final()]) // throws on bad tag
}

// ── membership chain ─────────────────────────────────────────────────────────────────────────

/**
 * Canonical signing bytes for an op — field order is FIXED (a signature over JSON must be).
 * `init` (a create's initial roster) MUST be covered: it decides who the group starts as, so an
 * unsigned/​unhashed init lets any relay splice members (incl. itself) into a create op and read all
 * traffic. Included here ⇒ it is signed AND part of opHash (GRP-5).
 */
const opBytes = (o) => utf8(['op', o.t, o.by, o.subj || '', (o.init || []).join(','), (o.parents || []).join(','), o.n ?? 0].join('|'))
const opHash = (o) => sha256(opBytes(o), unb64(o.sig)).toString('hex').slice(0, 32)

/**
 * Canonical bytes an author signs over a KEYDIST (GRP-3). A sender key handed out with no signature
 * and no check that the delivering peer IS the claimed sender let ANY group member forge a KEYDIST
 * claiming `s:V` with an attacker-chosen ck → clobber the victim's receive-ratchet for V → V's real
 * messages then fail (`ratchet` divergence) until V rotates: a cheap, repeatable per-sender DoS from
 * inside the group. Binding gidHex‖s‖ck‖q under the sender's Ed25519 key closes it — only the real V
 * can produce a KEYDIST that mutates V's ratchet.
 */
const keydistBytes = (gidHex, s, ck, q) => utf8([gidHex, 'keydist', s, ck, String(q)].join('|'))

/**
 * Deterministic fold: every member computes the SAME membership from the SAME op SET, with no
 * server — a PURE FUNCTION of the ops, independent of receipt order.
 *
 * The order is a canonical topological sort (Kahn's algorithm) that breaks every tie by opHash
 * (lexicographically lowest first). This closes GRP-1: two causally-unlinked `create` roots (or any
 * concurrent ops) resolve to the SAME linear order — hence the SAME admin — on every peer, instead
 * of the old receipt-order visitation where whoever's `create` arrived first won and a member could
 * escalate to admin on the peers that saw its rival `create` first.
 *
 * v1 policy (Briar-style): the lowest-hash `create` author is admin; only an admin adds/removes.
 * @param {Array} ops
 * @returns {{admin:string|null, members:Set<string>}}
 */
function foldMembership(ops) {
  const byHash = new Map(ops.map((o) => [opHash(o), o]))
  const indeg = new Map()
  const children = new Map()
  for (const h of byHash.keys()) { indeg.set(h, 0); children.set(h, []) }
  for (const [h, o] of byHash) {
    for (const p of o.parents || []) {
      if (!byHash.has(p)) continue             // parent not yet known — an external head, not a dep
      indeg.set(h, indeg.get(h) + 1)
      children.get(p).push(h)
    }
  }
  const ready = [...byHash.keys()].filter((h) => indeg.get(h) === 0).sort()  // roots, hash-ordered
  const order = []
  const done = new Set()
  while (ready.length) {
    const h = ready.shift()                     // lowest hash among the currently-ready ⇒ canonical
    if (done.has(h)) continue
    done.add(h)
    order.push(byHash.get(h))
    let grew = false
    for (const c of children.get(h)) {
      indeg.set(c, indeg.get(c) - 1)
      if (indeg.get(c) === 0) { ready.push(c); grew = true }
    }
    if (grew) ready.sort()
  }

  let admin = null
  const members = new Set()
  for (const o of order) {
    if (o.t === 'create') { if (admin) continue; admin = o.by; members.add(o.by); for (const m of o.init || []) members.add(m) }
    else if (o.t === 'add') { if (o.by !== admin) continue; members.add(o.subj) }      // admin-only
    else if (o.t === 'remove') { if (o.by !== admin) continue; members.delete(o.subj) } // admin-only
  }
  return { admin, members }
}

// ── secure group ─────────────────────────────────────────────────────────────────────────────

/**
 * A real group over the existing pairwise Noise mesh.
 *
 * @param {object} node      node from listen()
 * @param {object} identity  this host's identity (needs S, edPub, edPriv, xPub)
 * @param {object} opts
 * @param {Buffer|string} opts.secret  the 32-byte group secret G (shared out-of-band, like a key)
 * @param {string[]} [opts.members]    initial members' contact strings (creator only)
 * @param {boolean} [opts.create]      true ⇒ author the `create` op (the creator is admin)
 * @returns {object} group
 */
export function createSecureGroup(node, identity, { secret, members: initial = [], create = false } = {}) {
  if (!secret) throw new TypeError('group secret G required')
  // Accept a raw 32-byte secret (Buffer or Uint8Array) or its base64 string. Deliberately NOT
  // `Buffer.isBuffer(secret)`: under the browser shim a Buffer can come from a different module
  // instance of the shim class, and isBuffer() is instanceof-based — it would say "false" for a
  // perfectly good buffer and we would silently base64-decode garbage.
  const G = typeof secret === 'string' ? Buffer.from(secret, 'base64') : Buffer.from(secret)
  const groupId = groupIdFor(G)
  const gidHex = groupId.toString('hex')
  const me = String(identity.S).toUpperCase()
  // Bootstrap contacts: members I was told about out-of-band (the `members` option / an invite share).
  // For a LATE joiner these are the only peers it can reach before it has ingested any ops — the seed
  // for the GRP-4 pull. For the creator they are its initial roster (already in the create op).
  const bootstrap = (initial || []).map((s) => String(s).toUpperCase()).filter((s) => s !== me)

  const ops = []                    // membership chain (unordered; folded on read)
  const opHeads = new Set()
  const sendChain = { ck: null, seq: 0 }        // MY sender key
  const recvChains = new Map()      // S -> ratchet
  const idOf = new Map()            // S -> {edPub, xPub}  (bound to S by the commitment)
  const heads = new Set()           // causal heads (message hashes)
  const seenMsgs = new Set()
  const pending = []                // messages whose parents we haven't seen yet
  const handlers = { message: [], membership: [], divergence: [] }
  const keyedTo = new Set()         // members who already hold my sender key (join-order independence)
  const pulling = new Set()         // members I have an outstanding KEYREQ to (bounds pull amplification)
  let joined = false

  const emit = (ev, ...a) => { for (const fn of handlers[ev] || []) { try { fn(...a) } catch { /* handler threw */ } } }
  const membership = () => foldMembership(ops)
  const others = () => [...membership().members].filter((m) => m !== me)

  /** Bind a claimed author S to real pubkeys via the SAME commitment the handshake gate uses. */
  function bindIdentity(S, edPubB64, xPubB64) {
    const edPub = unb64(edPubB64), xPub = unb64(xPubB64)
    let commitment
    try { commitment = decodeKey(String(S).toUpperCase()).commitment } catch { return null }
    if (!verifyCommitment(commitment, edPub, xPub)) return null   // 2^110 to forge — fail closed
    idOf.set(String(S).toUpperCase(), { edPub, xPub })
    return { edPub, xPub }
  }
  bindIdentity(me, b64(identity.edPub), b64(identity.xPub))

  const myPub = () => ({ e: b64(identity.edPub), x: b64(identity.xPub) })

  // ── ops ──
  function authorOp(t, subj = null, extra = {}) {
    const o = { t, by: me, subj, parents: [...opHeads], n: ops.length, ...extra, ...myPub() }
    o.sig = b64(signEd(identity.edPriv, opBytes(o)))
    ingestOp(o)
    return o
  }
  function ingestOp(o) {
    const bound = bindIdentity(o.by, o.e, o.x)
    if (!bound) { emit('divergence', { reason: 'op-identity', by: o.by }); return false }
    if (!verifyEd(bound.edPub, opBytes(o), unb64(o.sig))) { emit('divergence', { reason: 'op-signature', by: o.by }); return false }
    const h = opHash(o)
    if (ops.some((x) => opHash(x) === h)) return false
    ops.push(o)
    for (const p of o.parents || []) opHeads.delete(p)
    opHeads.add(h)
    // A second `create` for a KNOWN groupId is never a silent resolution (GRP-1): the fold now picks
    // the lowest-hash create deterministically, but a rival root is a real divergence event — surface
    // it so the app sees a member's attempted admin-escalation, not just a quietly-ignored op.
    if (o.t === 'create' && ops.some((x) => x !== o && x.t === 'create')) emit('divergence', { reason: 'rival-create', by: o.by })
    emit('membership', [...membership().members])
    // GRP-2: cryptographic ejection must cover EVERY sender, not just the admin who authored the
    // removal. remove() rotates only the caller's sender key; a NON-ADMIN survivor that never rotates
    // keeps ratcheting the very chain the removed member already holds — so the removed member
    // computes all of that survivor's future keys forever (one-way ratchet). Fix: on an authoritative
    // `remove`, every surviving member rotates its OWN sender key and redistributes to survivors only.
    // Guarded so it fires exactly once per remove (ops dedup above), never on a bogus non-admin remove
    // (o.by === admin), and never double-rotates the admin (me !== o.by — remove() already rotated it).
    if (o.t === 'remove') {
      const m = membership()
      if (o.by === m.admin && me !== o.by && me !== o.subj && m.members.has(me)) rotate()
    }
    // Learning the chain can REVEAL members we didn't know existed when we joined. Without this,
    // join-order matters: a member that join()s before the admin's chain reaches it distributes its
    // sender key to nobody, and its messages then decrypt for no one — a silent, order-dependent
    // dead end. Re-sync instead: anyone newly visible who lacks my sender key gets it now (push), AND
    // pull any sender key I'm still missing from the members the chain just revealed (GRP-4).
    if (joined) { syncKeys(); pullKeys() }
    return true
  }

  /**
   * GRP-4: PULL the sender keys I'm missing. The push side (syncKeys) marks a member 'keyed' as soon
   * as the pairwise send acks — but that ack means "the node got the bytes", NOT "the recipient's
   * GROUP object processed them". A member whose group is created AFTER the admin pushed (a late
   * joiner) has its keydist dropped, yet the admin marks it done and never re-pushes → it can never
   * decrypt. The durable fix is a member-side pull: once my group exists I ask every member I know
   * (bootstrap contacts I was seeded with, plus any I've since folded) that I still lack a receive-key
   * from to (re)send it. Bounded by `pulling` so a burst of ingests can't amplify into a KEYREQ flood.
   */
  function pullKeys() {
    for (const S of new Set([...bootstrap, ...others()])) {
      if (S === me || recvChains.has(S) || pulling.has(S)) continue
      pulling.add(S)
      toMember(S, encodeEnv(T.KEYREQ, groupId, { s: me, ...myPub() })).catch(() => { pulling.delete(S) })
    }
  }

  /** Give my sender key to every member who doesn't have it yet. Idempotent; safe to call often. */
  function syncKeys() {
    const todo = others().filter((S) => !keyedTo.has(S))
    return Promise.allSettled(todo.map(async (S) => {
      keyedTo.add(S)                                   // mark first: keeps concurrent calls idempotent
      try { await keydistTo(S) } catch (error) { keyedTo.delete(S); throw error }  // retry on a later sync
    }))
  }

  if (create) {
    authorOp('create', null, { init: initial.map((s) => String(s).toUpperCase()) })
    sendChain.ck = randomBytes(32)     // my sender key
  }

  // ── send/receive plumbing over the pairwise links ──
  async function toMember(S, env) {
    const peer = await node.connect(S)          // reuses the existing Noise link if already up
    return peer.send(env)
  }

  /**
   * Give a member my current sender key (over its authenticated pairwise Noise link), preceded by
   * the membership chain so it can fold the same membership I did.
   *
   * The ops are sent as SEPARATE frames, deliberately: node.js's app layer has no fragmentation and
   * wire.js THROWS above its ~1183-byte payload budget — a piggybacked chain crosses that as soon as
   * a group has a few ops, and node.js swallows the throw, so the send would hang forever instead of
   * failing. One op per frame keeps every group frame small. (The underlying core limitation is
   * reported separately — it is not this layer's to fix.)
   */
  async function keydistTo(S) {
    if (!sendChain.ck) sendChain.ck = randomBytes(32)
    for (const o of ops) await toMember(S, encodeEnv(T.OP, groupId, o))
    const ck = b64(sendChain.ck), q = sendChain.seq
    const k = b64(signEd(identity.edPriv, keydistBytes(gidHex, me, ck, q)))   // GRP-3: sign the handout
    return toMember(S, encodeEnv(T.KEYDIST, groupId, { s: me, ck, q, k, ...myPub() }))
  }

  /** Rotate MY sender key and redistribute to survivors only ⇒ ejects anyone removed. */
  async function rotate() {
    sendChain.ck = randomBytes(32)
    sendChain.seq = 0
    keyedTo.clear()                  // the OLD key is void: every survivor must receive the new one
    authorOp('rotate')
    joined = true
    return syncKeys()
  }

  function onEnvelope(peer, buf) {
    const env = decodeEnv(buf)
    if (!env || !env.groupId.equals(groupId)) return false   // not ours — let the app have it
    const { type, body } = env

    if (type === T.KEYDIST) {
      const S = String(body.s).toUpperCase()
      const bound = bindIdentity(S, body.e, body.x)
      if (!bound) { emit('divergence', { reason: 'keydist-identity', by: S }); return true }
      // GRP-3: the ck only mutates V's ratchet if V itself signed this handout. An insider forging a
      // KEYDIST claiming s:V cannot produce this signature (needs V's edPriv) ⇒ no per-sender DoS.
      if (!verifyEd(bound.edPub, keydistBytes(gidHex, S, body.ck, body.q || 0), unb64(body.k || ''))) {
        emit('divergence', { reason: 'keydist-signature', by: S }); return true
      }
      for (const o of body.ops || []) ingestOp(o)             // learn the membership chain
      if (!membership().members.has(S)) { emit('divergence', { reason: 'keydist-nonmember', by: S }); return true }
      recvChains.set(S, ratchet(unb64(body.ck), body.q || 0))
      pulling.delete(S)                                       // GRP-4: the pull for S is satisfied
      return true
    }

    if (type === T.KEYREQ) {                                  // GRP-4: a member is (re)requesting my key
      const R = String(body.s).toUpperCase()
      const bound = bindIdentity(R, body.e, body.x)
      if (!bound) return true                                 // unbindable requester — ignore, fail closed
      if (!membership().members.has(R)) return true           // only serve CURRENT members (a removed one cannot re-pull)
      keyedTo.add(R)
      keydistTo(R).catch(() => { /* still unreachable — the requester will retry on its next pull */ })
      return true
    }

    if (type === T.OP) { ingestOp(body); return true }

    if (type === T.RELAY) {                                   // forward a blind, signed ciphertext
      const dst = String(body.to).toUpperCase()
      if (dst === me) return onEnvelope(peer, unb64(body.env))
      if (!membership().members.has(dst)) return true
      toMember(dst, unb64(body.env)).catch(() => { /* still unreachable — honest partial delivery */ })
      return true
    }

    if (type === T.MSG) {
      const S = String(body.s).toUpperCase()
      const { members } = membership()
      if (!members.has(S)) { emit('divergence', { reason: 'msg-nonmember', by: S }); return true }
      const id = idOf.get(S)
      if (!id) { emit('divergence', { reason: 'msg-unknown-identity', by: S }); return true }

      const canon = utf8([gidHex, S, body.q, body.c, (body.p || []).join(',')].join('|'))
      if (!verifyEd(id.edPub, canon, unb64(body.g))) { emit('divergence', { reason: 'msg-signature', by: S }); return true }

      const h = sha256(canon, unb64(body.g)).toString('hex').slice(0, 32)
      if (seenMsgs.has(h)) return true                        // dedup (fan-out + relay ⇒ duplicates)

      const r = recvChains.get(S)
      if (!r) { emit('divergence', { reason: 'no-sender-key', by: S }); return true }
      const mk = keyForSeq(r, body.q)
      if (!mk) { emit('divergence', { reason: 'ratchet', by: S }); return true }

      let plain
      try {
        plain = aeadDec(mk, body.q, Buffer.concat([groupId, utf8(S), Buffer.from(String(body.q))]), unb64(body.c))
      } catch (error) { emit('divergence', { reason: 'group-decrypt', by: S, error }); return true }

      seenMsgs.add(h)
      const msg = { from: S, data: plain, hash: h, parents: body.p || [] }
      deliverCausally(msg)
      return true
    }
    return true
  }

  /** Causal (DAG) order: hold a message until every parent it named has been delivered. */
  function deliverCausally(msg) {
    const ready = (m) => (m.parents || []).every((p) => seenDelivered.has(p))
    if (!ready(msg)) { pending.push(msg); return }
    doDeliver(msg)
    for (let i = 0; i < pending.length;) {                    // drain whatever this unblocked
      if (ready(pending[i])) { doDeliver(pending.splice(i, 1)[0]); i = 0 } else i++
    }
  }
  const seenDelivered = new Set()
  function doDeliver(m) {
    seenDelivered.add(m.hash)
    for (const p of m.parents || []) heads.delete(p)
    heads.add(m.hash)
    emit('message', m.from, m.data, m)
  }

  node.on('message', (peer, buf) => { onEnvelope(peer, buf) })

  return {
    groupId: gidHex,
    /** the shareable group secret (treat exactly like a 26-char key — anyone holding it can be found) */
    secret: b64(G),
    members() { return [...membership().members] },
    admin() { return membership().admin },
    heads() { return [...heads] },
    on(ev, fn) { (handlers[ev] ||= []).push(fn); return this },

    /**
     * Hand my sender key to every member. Call it once; ORDER DOES NOT MATTER — if the membership
     * chain reaches us later (e.g. we joined before the admin propagated it), ingestOp re-syncs and
     * the members we only learn about afterwards still get our key.
     */
    async join() {
      if (!sendChain.ck) sendChain.ck = randomBytes(32)
      joined = true
      pullKeys()                      // GRP-4: pull keys from members I know, even if I have no ops yet
      return syncKeys()
    },

    /** Admin: add a member — signs an op, tells everyone, and gives the newcomer my sender key. */
    async add(S) {
      const key = String(S).toUpperCase()
      const o = authorOp('add', key)
      await Promise.allSettled(others().map((m) => toMember(m, encodeEnv(T.OP, groupId, o))))
      joined = true
      return syncKeys()               // the newcomer is now visible ⇒ gets my sender key
    },

    /**
     * Admin: remove a member — signs an op, then ROTATES my sender key and redistributes it to the
     * survivors only. The removed member keeps what it could already read (unavoidable) and can
     * decrypt NOTHING further: cryptographic ejection, not a polite request.
     */
    async remove(S) {
      const key = String(S).toUpperCase()
      const o = authorOp('remove', key)
      await Promise.allSettled(others().map((m) => toMember(m, encodeEnv(T.OP, groupId, o))))
      return rotate()
    },

    rotate,

    /**
     * Encrypt ONCE with my sender key, sign it, and fan the single ciphertext out. Members I cannot
     * reach directly are served by asking a member I CAN reach to relay the byte-identical envelope
     * — a blind relay: it cannot read or forge it.
     * @param {Buffer|string} data
     */
    async send(data) {
      if (!sendChain.ck) sendChain.ck = randomBytes(32)
      const pt = Buffer.isBuffer(data) ? data : utf8(String(data))
      const seq = sendChain.seq
      const mk = msgKey(sendChain.ck)
      sendChain.ck = nextCk(sendChain.ck); sendChain.seq++          // ratchet forward ⇒ FS

      const aad = Buffer.concat([groupId, utf8(me), Buffer.from(String(seq))])
      const ct = aeadEnc(mk, seq, aad, pt)
      const parents = [...heads]
      const canon = utf8([gidHex, me, seq, b64(ct), parents.join(',')].join('|'))
      const sig = b64(signEd(identity.edPriv, canon))
      const body = { s: me, q: seq, p: parents, c: b64(ct), g: sig }
      const env = encodeEnv(T.MSG, groupId, body)
      // node.js/wire.js cap an app payload at ~1183 bytes and node.js SWALLOWS the throw (the send
      // would hang, never reject). Fail LOUDLY here instead of hanging. Chat lines are far below
      // this; large payloads need app-level fragmentation in node.js, which is not this layer's call.
      if (env.length > 1183) throw new RangeError(`group message too large: ${env.length}B envelope > 1183B transport budget`)

      const h = sha256(canon, unb64(sig)).toString('hex').slice(0, 32)
      seenMsgs.add(h)                                                // never re-deliver my own echo
      seenDelivered.add(h)
      for (const p of parents) heads.delete(p)
      heads.add(h)

      const targets = others()
      const results = await Promise.all(targets.map(async (S) => {
        try { await toMember(S, env); return { key: S, ok: true } }
        catch (error) { return { key: S, ok: false, error } }
      }))

      // blind peer-relay for whoever we couldn't reach (incomplete mesh — §7.3 "seamless")
      const reachable = results.filter((r) => r.ok).map((r) => r.key)
      const unreachable = results.filter((r) => !r.ok).map((r) => r.key)
      for (const dst of unreachable) {
        const relayEnv = encodeEnv(T.RELAY, groupId, { to: dst, env: b64(env) })
        for (const via of reachable) toMember(via, relayEnv).catch(() => { /* best effort */ })
      }
      return { seq, hash: h, delivered: reachable, relayed: unreachable }
    },
  }
}

export default { createGroup, createSecureGroup, groupIdFor }
