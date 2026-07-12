// p2p — transport: dual-stack UDP core + in-house STUN client + ICE-lite hole punch.
// Zero deps (node:dgram/net/os/dns/crypto). DESIGN D8 (transport ladder), INTERFACES
// §src/transport.js, research/transport-nat.md (STUN §2, punch §1, keepalive §6, ladder §0).
//
// Contract:
//   createEndpoint({port?})  -> ep
//   ep.candidates()          -> [{proto:'udp6'|'udp4'|'tcp', ip, port, kind:'host'|'lan'|'srflx'}]
//   ep.stun()                -> {ip,port}                    (reflexive candidate; also cached)
//   ep.punch(remoteCands,{signal}) -> socketLike             (races ladder, keep-best)
//   ep.on('netchange')        emitted when local IPs change (node.js re-announces)
//   socketLike: .send(buf) / .onMessage(cb) / .close()
// Keepalive (25s UDP / 60s TCP) is owned by wire.tick — transport sends NO keepalives.

import dgram from 'node:dgram';
import net from 'node:net';
import os from 'node:os';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';

const MAGIC = 0x2112a442; // STUN magic cookie (RFC 8489)
const MAGIC_BUF = Buffer.from([0x21, 0x12, 0xa4, 0x42]);

// Live public STUN servers (research/transport-nat.md §2.5). stun.stunprotocol.org is
// DEFUNCT per live probe — omitted. Query 2-3 in parallel, take first valid response.
export const STUN_SERVERS = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun.cloudflare.com', port: 3478 },
  { host: 'stun1.l.google.com', port: 19302 },
  { host: 'stun.nextcloud.com', port: 3478 },
];

// ---- STUN Binding client (RFC 8489) -----------------------------------------

/** Build a 20-byte STUN Binding Request (no attributes). @returns {{buf:Buffer,txid:Buffer}} */
function bindingRequest() {
  const buf = Buffer.alloc(20);
  buf.writeUInt16BE(0x0001, 0); // Binding Request
  buf.writeUInt16BE(0x0000, 2); // message length: no attributes
  buf.writeUInt32BE(MAGIC, 4); // magic cookie
  const txid = randomBytes(12);
  txid.copy(buf, 8);
  return { buf, txid };
}

/** Parse a Binding Success Response's XOR-MAPPED-ADDRESS (0x0020), legacy MAPPED (0x0001)
 * fallback. @returns {{ip:string,port:number,family:4|6}|null} */
function parseBindingResponse(msg, txid) {
  if (msg.length < 20) return null;
  if (msg.readUInt16BE(0) !== 0x0101) return null; // Binding Success Response
  if (msg.readUInt32BE(4) !== MAGIC) return null;
  if (!msg.subarray(8, 20).equals(txid)) return null; // txid must echo
  let off = 20;
  const end = 20 + msg.readUInt16BE(2);
  while (off + 4 <= msg.length && off + 4 <= end) {
    const atype = msg.readUInt16BE(off);
    const alen = msg.readUInt16BE(off + 2);
    const val = msg.subarray(off + 4, off + 4 + alen);
    if (atype === 0x0020) return decodeAddr(val, true, txid);
    if (atype === 0x0001) return decodeAddr(val, false, txid);
    off += 4 + alen + ((4 - (alen % 4)) % 4); // attributes are 4-byte aligned
  }
  return null;
}

function decodeAddr(val, xor, txid) {
  if (val.length < 8) return null;
  const family = val.readUInt8(1); // 0x01 = IPv4, 0x02 = IPv6
  const port = xor ? val.readUInt16BE(2) ^ (MAGIC >>> 16) : val.readUInt16BE(2);
  if (family === 0x01) {
    const a = Buffer.from(val.subarray(4, 8));
    if (xor) for (let i = 0; i < 4; i++) a[i] ^= MAGIC_BUF[i];
    return { ip: `${a[0]}.${a[1]}.${a[2]}.${a[3]}`, port, family: 4 };
  }
  if (family === 0x02 && val.length >= 20) {
    const a = Buffer.from(val.subarray(4, 20));
    if (xor) {
      const mask = Buffer.concat([MAGIC_BUF, txid]);
      for (let i = 0; i < 16; i++) a[i] ^= mask[i];
    }
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(a.readUInt16BE(i).toString(16));
    return { ip: parts.join(':'), port, family: 6 };
  }
  return null;
}

// ---- helpers ----------------------------------------------------------------

const norm = (fam) => (fam === 6 || fam === 'IPv6' ? 6 : 4);
const akey = (ip, port) => `${ip}|${port}`;

/** Classify a local address: private/link-local/ULA -> 'lan', else 'host'. */
function classify(ip) {
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    if (l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l === '::1') return 'lan';
    return 'host';
  }
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.') || ip.startsWith('127.')) return 'lan';
  const m = ip.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return 'lan'; // 172.16.0.0/12
  return 'host';
}

/** Preference ladder (DESIGN D8, lower = better): IPv6 > LAN > host-udp4 > srflx/punched. */
function rank(c) {
  if (c.proto === 'udp6') return c.kind === 'lan' ? 1 : 0;
  if (c.kind === 'lan') return 2;
  if (c.kind === 'host') return 3;
  return 4; // srflx / unknown
}

/** Signature of the machine's non-internal addresses, for netchange detection. */
function ifaceSig() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) for (const a of ifs[name] || []) if (!a.internal) out.push(`${a.family}:${a.address}`);
  return out.sort().join(',');
}

// ---- punch wire (our own tiny probe protocol, distinct 4-byte magic) ---------
const PUNCH_MAGIC = 0x50327050; // "P2pP"
const PROBE = 0x01;
const PROBE_ACK = 0x02;
const ZERO_TOKEN = Buffer.alloc(8); // untrusted/legacy: no session correlation -> per-4-tuple accept

// ---- DOS-1 accept-path guards (wargame-findings §2 DOS-1 / §5 DOS-2) --------
// Pre-fix, ANY remote sender who reached the UDP port could stream forged 21-byte PROBEs (fresh
// token per packet) and each one minted a socketLike into `_peers` AND `_accepted` — neither ever
// evicted, no cap, no rate limit — then fired onConnection (→ a node peer record). Zero-cost,
// remotely triggerable, unbounded memory. Fix: the accept table is now BOUNDED (hard cap), SWEPT
// (accepted-but-no-HS1 expires; a confirmed-then-silent peer expires later), and RATE-LIMITED
// (token bucket on new accepts + per-source-IP bucket on PROBE packets). Mirrors the DOS-1-WSS
// guards already shipped in transport-wss.js (same shape, same names) — one doctrine, two transports.
//
// Bounds are chosen with real headroom over honest load (normal steady state is <10 concurrent
// peers; a legit dialer produces exactly ONE accept and its ICE-lite burst is ~50 PROBEs/s/source
// at 3 remote candidates × ~16.7 bursts/s):
const MAX_ACCEPTED = 256;      // inbound socketLikes tracked at once (~25× the realistic peak)
const MAX_PENDING = 64;        // of those, how many may be UNCONFIRMED (no HS1 yet) — a flood can
                               // never crowd out the ≥192 slots left for real, handshaked peers
const PENDING_TTL_MS = 20_000; // accepted but no HS1 within this → evict (HELLO retransmit gives up
                               // after 8×250ms = 2s, so 20s is 10× the honest window)
const ACCEPT_IDLE_MS = 90_000; // confirmed-but-silent → evict. MUST exceed wire's livenessMs
                               // (keepalive 25s × 3 = 75s): wire declares a peer dead first, so this
                               // sweep can never kill a channel the peer still considers alive.
const ACCEPT_RATE = 20;        // sustained NEW accepts/s (token-bucket refill) — 20× honest rate
const ACCEPT_BURST = 40;       // burst cap on new accepts
const PROBE_RATE = 200;        // sustained PROBEs/s per source IP (4× the ~50/s honest ICE burst)
const PROBE_BURST = 400;       // burst cap per source IP
const MAX_SOURCES = 4096;      // bounded rate-limiter table (LRU) — the limiter is not itself a leak
const SWEEP_MS = 5_000;        // idle-sweep cadence

function probePkt(type, tok8, nonce8) {
  const b = Buffer.alloc(21);
  b.writeUInt32BE(PUNCH_MAGIC, 0);
  b[4] = type;
  tok8.copy(b, 5);
  nonce8.copy(b, 13);
  return b;
}

// ---- Endpoint ---------------------------------------------------------------

class Endpoint extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.sock4 = null;
    this.sock6 = null;
    this.port4 = 0;
    this.port6 = 0;
    this.port = 0;
    this._stunPending = new Map(); // txidHex -> (res) => void
    this._punch = null; // active punch session { token, onProbe(type,nonce,rinfo) }
    this._peers = new Map(); // addrKey -> onMessage cb (one shared port, many punched peers)
    this._onConnCb = null; // onConnection callback — set => this endpoint accepts inbound first-contact
    this._accepted = new Map(); // acceptKey -> socketLike (dedup multi-path accepts of one dialer session)
    this._srflx = null; // cached reflexive candidate
    this._netTimer = null;
    this._sweepTimer = null;
    // DOS-1 guards (all overridable — tests drive them with tiny bounds/TTLs)
    this._now = opts.now || (() => Date.now());
    this._maxAccepted = opts.maxAccepted ?? MAX_ACCEPTED;
    this._maxPending = opts.maxPending ?? MAX_PENDING;
    this._pendingTtlMs = opts.pendingTtlMs ?? PENDING_TTL_MS;
    this._acceptIdleMs = opts.acceptIdleMs ?? ACCEPT_IDLE_MS;
    this._acceptRate = opts.acceptRate ?? ACCEPT_RATE;
    this._acceptBurst = opts.acceptBurst ?? ACCEPT_BURST;
    this._probeRate = opts.probeRate ?? PROBE_RATE;
    this._probeBurst = opts.probeBurst ?? PROBE_BURST;
    this._maxSources = opts.maxSources ?? MAX_SOURCES;
    this._sweepMs = opts.sweepMs ?? SWEEP_MS;
    this._acceptTokens = this._acceptBurst;
    this._acceptRefill = this._now();
    this._probeBuckets = new Map(); // srcIP -> {tokens,last} (LRU-bounded)
    this._probeAuthCb = null; // META-1: invite-mode probe authenticator (see probeAuth())
  }

  // ---- DOS-1: rate limits ----------------------------------------------------

  /** Token bucket over PROBE packets from ONE source IP. The table is LRU-bounded, so the
   * limiter itself can never be turned into the memory leak it exists to prevent. (A SPOOFING
   * flood defeats any per-source limiter by construction — the hard caps below are what bound
   * memory there; this bucket targets the finding's stated attack, which needs no spoofing.) */
  _allowProbe(ip) {
    const t = this._now();
    let b = this._probeBuckets.get(ip);
    if (b) {
      this._probeBuckets.delete(ip); // re-insert => Map iteration order is LRU
      b.tokens = Math.min(this._probeBurst, b.tokens + ((t - b.last) / 1000) * this._probeRate);
      b.last = t;
    } else {
      if (this._probeBuckets.size >= this._maxSources) this._probeBuckets.delete(this._probeBuckets.keys().next().value);
      b = { tokens: this._probeBurst, last: t };
    }
    this._probeBuckets.set(ip, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /** Token bucket over NEW accepts (global). A legit dialer costs exactly one token. */
  _allowAccept() {
    const t = this._now();
    this._acceptTokens = Math.min(this._acceptBurst, this._acceptTokens + ((t - this._acceptRefill) / 1000) * this._acceptRate);
    this._acceptRefill = t;
    if (this._acceptTokens < 1) return false;
    this._acceptTokens -= 1;
    return true;
  }

  // ---- DOS-1: bounded accept table -------------------------------------------

  _dropAccept(k, s) {
    this._accepted.delete(k);
    try { s.close(); } catch { /* close() also purges every _peers tuple pointing at it */ }
  }

  /** Evict expired accepts: unconfirmed ones that never produced an HS1, and confirmed ones the
   * peer has stopped talking on (after wire has already declared them dead). */
  _sweepAccepts() {
    const t = this._now();
    for (const [k, s] of this._accepted) {
      const expired = s.closed
        || (!s._confirmed && t - s._acceptedAt > this._pendingTtlMs)
        || (s._confirmed && t - s.lastSeen > this._acceptIdleMs);
      if (expired) this._dropAccept(k, s);
    }
  }

  _pendingCount() { let n = 0; for (const s of this._accepted.values()) if (!s._confirmed) n++; return n; }

  /** Make room for a newcomer: shed the stalest UNCONFIRMED accept first (an unauthenticated
   * flooder is always the cheapest thing to throw away), only then the stalest confirmed one. */
  _evictOne() {
    let pend = null, pendAt = Infinity, conf = null, confAt = Infinity;
    for (const [k, s] of this._accepted) {
      if (!s._confirmed) { if (s._acceptedAt < pendAt) { pendAt = s._acceptedAt; pend = k; } }
      else if (s.lastSeen < confAt) { confAt = s.lastSeen; conf = k; }
    }
    const pick = pend ?? conf;
    if (pick == null) return false;
    this._dropAccept(pick, this._accepted.get(pick));
    return true;
  }

  /**
   * META-1: install an authenticator for unsolicited PROBEs. `fn(tok, nonce, rinfo) -> boolean`;
   * a false verdict drops the packet SILENTLY — no PROBE_ACK, no accept, and above all no HELLO
   * (which carries our identity pubkeys in the clear). Unset (reusable-S mode) => today's
   * behaviour, byte-identical. node.js installs one in INVITE mode only.
   */
  probeAuth(fn) { this._probeAuthCb = typeof fn === 'function' ? fn : null; }

  _attach() {
    const handler = (msg, rinfo) => this._onMessage(msg, { ...rinfo, family: norm(rinfo.family) });
    this.sock4?.on('message', handler);
    this.sock6?.on('message', handler);
    this._ifSig = ifaceSig();
    // ponytail: interval poll for local-IP change (no native netlink in stdlib);
    // 10s is fine — node.js re-announces on 'netchange'. Swap for OS events if ever needed.
    this._netTimer = setInterval(() => {
      const s = ifaceSig();
      if (s !== this._ifSig) {
        this._ifSig = s;
        this.emit('netchange');
      }
    }, 10000);
    this._netTimer.unref?.();
    // DOS-1: idle sweep — expire accepted-but-never-handshaked probes and long-silent peers even
    // when no new PROBE arrives to trigger the inline sweep.
    this._sweepTimer = setInterval(() => { try { this._sweepAccepts(); } catch { /* never throw on a timer */ } }, this._sweepMs);
    this._sweepTimer.unref?.();
  }

  _onMessage(msg, rinfo) {
    // 1) STUN success response for one of our pending transactions
    if (msg.length >= 20 && msg.readUInt32BE(4) === MAGIC) {
      const txid = msg.subarray(8, 20);
      const cb = this._stunPending.get(txid.toString('hex'));
      if (cb) {
        const r = parseBindingResponse(msg, txid);
        if (r) return cb(r);
      }
    }
    // 2) punch probe/ack
    if (msg.length >= 21 && msg.readUInt32BE(0) === PUNCH_MAGIC) {
      const type = msg[4];
      const tok = msg.subarray(5, 13);
      const nonce = msg.subarray(13, 21);
      const p = this._punch;
      if (p && tok.equals(p.token)) return p.onProbe(type, nonce, rinfo); // our active dial
      // no matching dial session: an unsolicited PROBE is an INBOUND first-contact (D4 —
      // transport is untrusted; real auth is the commitment gate + Noise IK node.js runs on top).
      if (type === PROBE) return this._acceptInbound(tok, nonce, rinfo);
      return; // stray ACK, no session
    }
    // 3) application data — route to the matching punched peer
    const sock = this._peers.get(akey(rinfo.address, rinfo.port));
    if (sock) sock._emit(msg, rinfo);
  }

  _sendRaw(buf, ip, port, v6) {
    const s = v6 ? this.sock6 : this.sock4;
    if (s) try { s.send(buf, port, ip); } catch { /* transient send error — punch retries */ }
  }

  /** Host + LAN candidates from local interfaces, plus cached srflx if stun() ran. */
  candidates() {
    const out = [];
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const a of ifs[name] || []) {
        if (a.internal) continue;
        const v6 = norm(a.family) === 6;
        // ponytail: skip IPv6 link-local (fe80) — needs %scope id, same-link only (mDNS covers it).
        if (v6 && a.address.toLowerCase().startsWith('fe80')) continue;
        const port = v6 ? this.port6 : this.port4;
        if (!port) continue;
        out.push({ proto: v6 ? 'udp6' : 'udp4', ip: a.address, port, kind: classify(a.address) });
      }
    }
    if (this._srflx) out.push({ ...this._srflx });
    return out;
  }

  /** Server-reflexive candidate via public STUN (from our real udp4 socket, so the mapping
   * matches the port peers will punch). Races 2-3 servers, retries with jitter. -> {ip,port} */
  async stun({ servers = STUN_SERVERS, timeout = 3000, attempts = 3 } = {}) {
    if (!this.sock4) throw new Error('STUN needs a udp4 socket');
    const targets = (
      await Promise.all(
        servers.slice(0, 3).map(async (s) => {
          try { return { ip: (await dns.lookup(s.host, { family: 4 })).address, port: s.port }; }
          catch { return null; }
        }),
      )
    ).filter(Boolean);
    if (!targets.length) throw new Error('no STUN server resolved');

    return await new Promise((resolve, reject) => {
      let done = false;
      const txids = [];
      const cleanup = () => { for (const t of txids) this._stunPending.delete(t); clearInterval(iv); clearTimeout(deadline); };
      const finish = (v, e) => { if (done) return; done = true; cleanup(); e ? reject(e) : resolve(v); };
      const onHit = (r) => {
        this._srflx = { proto: r.family === 6 ? 'udp6' : 'udp4', ip: r.ip, port: r.port, kind: 'srflx' };
        finish({ ip: r.ip, port: r.port });
      };
      let n = 0;
      const burst = () => {
        if (done || n++ >= attempts) return;
        for (const t of targets) {
          const { buf, txid } = bindingRequest();
          const hex = txid.toString('hex');
          txids.push(hex);
          this._stunPending.set(hex, onHit);
          this.sock4.send(buf, t.port, t.ip);
        }
      };
      // ponytail: jittered retransmit (research §2.5 "treat any single server as unreliable").
      const iv = setInterval(() => burst(), 250 + Math.floor(randomBytes(1)[0] / 255 * 250));
      const deadline = setTimeout(() => finish(null, new Error('all STUN servers failed/unreachable')), timeout);
      burst();
    });
  }

  /** ICE-lite punch: burst PROBEs to every remote candidate at once, validate a 4-tuple on
   * PROBE_ACK echo, keep the best-ranked validated path (IPv6>LAN>punched). Falls back to
   * TCP simultaneous-open when no UDP path validates. -> socketLike {send,onMessage,close}
   * @param {Array} remoteCands  candidates from the rendezvous lane
   * @param {{signal?:AbortSignal, timeout?:number, token?:Buffer|string, nonce?:Buffer}} opts
   *   `nonce` (META-1): send this FIXED 8-byte nonce on every PROBE instead of a fresh random one.
   *   node.js sets it in invite mode to a K_inv-derived proof over `token`, so the responder can tell
   *   the invitee from a scanner. PROBE_ACK echoes it exactly as before — nothing else changes (the
   *   packet is the same 21 bytes, the nonce is pseudorandom either way: no new wire signal). */
  punch(remoteCands, { signal, timeout = 6000, token, nonce } = {}) {
    const tok8 = Buffer.alloc(8);
    if (token) (Buffer.isBuffer(token) ? token : Buffer.from(token)).copy(tok8);
    const fixedNonce = nonce ? Buffer.from(nonce) : null;
    const cands = (remoteCands || []).filter((c) => c.proto === 'udp4' || c.proto === 'udp6');

    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(new Error('punch aborted'));
      const validated = new Map(); // addrKey -> {rinfo, cand}
      const candByAddr = new Map(); // addrKey -> cand
      const sent = new Map(); // addrKey -> Set(nonceHex)
      for (const c of cands) candByAddr.set(akey(c.ip, c.port), c);
      let done = false, nomTimer = null, burstIv = null, udpTimer = null;

      const cleanup = () => {
        clearInterval(burstIv); clearTimeout(nomTimer); clearTimeout(udpTimer);
        signal?.removeEventListener?.('abort', onAbort);
      };
      const finish = (sock, err) => {
        if (done) return; done = true; cleanup();
        // keep answering late peer PROBEs briefly so the OTHER side also validates & resolves.
        if (!err && this._punch) {
          const lp = this._punch;
          setTimeout(() => { if (this._punch === lp) this._punch = null; }, 800).unref?.();
        } else { this._punch = null; }
        err ? reject(err) : resolve(sock);
      };
      const onAbort = () => finish(null, new Error('punch aborted'));
      signal?.addEventListener?.('abort', onAbort);

      const nominate = () => {
        if (done || validated.size === 0) return;
        const best = [...validated.values()].sort((a, b) => rank(a.cand) - rank(b.cand))[0];
        finish(this._udpSocketLike(best.rinfo));
      };

      this._punch = {
        token: tok8,
        onProbe: (type, nonce, rinfo) => {
          const ak = akey(rinfo.address, rinfo.port);
          if (type === PROBE) {
            this._sendRaw(probePkt(PROBE_ACK, tok8, nonce), rinfo.address, rinfo.port, rinfo.family === 6);
          } else if (type === PROBE_ACK) {
            if (validated.has(ak)) return;
            const s = sent.get(ak);
            if (!s || !s.has(nonce.toString('hex'))) return; // not a nonce we sent there
            const cand = candByAddr.get(ak) || { proto: rinfo.family === 6 ? 'udp6' : 'udp4', ip: rinfo.address, port: rinfo.port, kind: 'srflx' };
            validated.set(ak, { rinfo, cand });
            if (validated.size >= cands.length) nominate();
            else if (!nomTimer) nomTimer = setTimeout(nominate, 200); // grace window to prefer a better path
          }
        },
      };

      const burst = () => {
        if (done) return;
        for (const c of cands) {
          const ak = akey(c.ip, c.port);
          if (validated.has(ak)) continue;
          const n8 = fixedNonce || randomBytes(8);
          if (!sent.has(ak)) sent.set(ak, new Set());
          sent.get(ak).add(n8.toString('hex'));
          this._sendRaw(probePkt(PROBE, tok8, n8), c.ip, c.port, c.proto === 'udp6');
        }
      };

      if (cands.length) {
        burst();
        burstIv = setInterval(burst, 60); // ~16 probes/s/candidate, expect early loss (research §1.1)
      }
      // Give UDP ~60% of the budget, then fall back to TCP simultaneous-open (research §4).
      const udpBudget = cands.length ? Math.floor(timeout * 0.6) : 0;
      udpTimer = setTimeout(() => {
        if (done) return;
        clearInterval(burstIv);
        if (validated.size) return nominate();
        this._tcpFallback(remoteCands || [], timeout - udpBudget, signal).then((sl) => finish(sl)).catch((e) => finish(null, e));
      }, udpBudget);
    });
  }

  /** UDP socketLike bound to the validated peer. Demux happens in _onMessage. */
  _udpSocketLike(rinfo) {
    const rk = akey(rinfo.address, rinfo.port);
    let closed = false, locked = false;
    let handler = () => {};
    // `cur` is the LIVE reply target once locked. `tuples` are all source paths correlated to
    // this peer (a dialer's ICE-lite burst arrives as several v4/v6 sources). We do NOT yet know
    // which path the dialer validated until it sends inbound data — so PRE-LOCK, send() FANS OUT
    // to every tuple (guarantees the dialer's validated-path socket receives HELLO retransmits);
    // the FIRST inbound datagram locks `cur` to the delivering path and steady-state uses it only.
    const cur = { address: rinfo.address, port: rinfo.port, family: rinfo.family === 6 ? 6 : 4 };
    const tuples = [{ address: cur.address, port: cur.port, v6: cur.family === 6 }];
    const sock = {
      get proto() { return cur.family === 6 ? 'udp6' : 'udp4'; },
      get remote() { return { ...cur }; },
      get rinfo() { return { ...cur }; },
      get onMessage() { return (cb) => { handler = typeof cb === 'function' ? cb : (() => {}); }; },
      set onMessage(fn) { handler = typeof fn === 'function' ? fn : (() => {}); },
      get closed() { return closed; },
      // DOS-1 bookkeeping (inbound accepts only; a dialed socket just carries them inertly).
      _ak: null,               // key in `_accepted`
      _acceptedAt: 0,          // when the PROBE was accepted -> pending TTL
      _confirmed: false,       // node.js calls confirm() the moment HS1 authenticates
      lastSeen: 0,             // last inbound datagram -> idle eviction
      /** Leave the pre-auth (pending) set: this peer has proven what the handshake can prove. */
      confirm: () => { sock._confirmed = true; sock.lastSeen = this._now(); },
      send: (buf) => {
        if (closed) return;
        if (locked) { this._sendRaw(buf, cur.address, cur.port, cur.family === 6); return; }
        for (const t of tuples) this._sendRaw(buf, t.address, t.port, t.v6); // fan out until the path is known
      },
      close: () => {
        closed = true;
        for (const [k, s] of this._peers) if (s === sock) this._peers.delete(k);
        if (sock._ak && this._accepted.get(sock._ak) === sock) this._accepted.delete(sock._ak);
      },
      _emit: (msg, ri) => {
        sock.lastSeen = this._now();
        if (ri) { cur.address = ri.address; cur.port = ri.port; cur.family = ri.family === 6 ? 6 : 4; locked = true; } // first inbound locks the path
        try { handler(msg, ri); } catch { /* consumer handler threw */ }
      },
      _addTuple: (ri) => { if (!tuples.some((t) => t.address === ri.address && t.port === ri.port)) tuples.push({ address: ri.address, port: ri.port, v6: ri.family === 6 }); },
    };
    this._peers.set(rk, sock);
    return sock;
  }

  /** Register an inbound-connection acceptor. Set => this endpoint answers unsolicited PROBEs
   * (node.listen). One callback per NEW inbound peer with a ready socketLike. */
  onConnection(cb) { this._onConnCb = cb; }

  /** Accept an unsolicited inbound PROBE as a new peer (listener side of first-contact). */
  _acceptInbound(tok, nonce, rinfo) {
    if (!this._onConnCb) return; // not listening for inbound — drop (don't ACK)
    if (!this._allowProbe(rinfo.address)) return; // DOS-1: per-source flood — drop before any work
    // META-1: in invite mode an unauthenticated prober gets NOTHING back — not even the PROBE_ACK
    // that would confirm a p2p listener lives here, and never the pubkey-bearing HELLO.
    if (this._probeAuthCb && !this._probeAuthCb(tok, nonce, rinfo)) return;
    // ACK every inbound PROBE (retransmits too) so the dialer's punch() validates the 4-tuple.
    this._sendRaw(probePkt(PROBE_ACK, tok, nonce), rinfo.address, rinfo.port, rinfo.family === 6);
    const now = this._now();
    const rk = akey(rinfo.address, rinfo.port);
    const routed = this._peers.get(rk);
    if (routed) { routed.lastSeen = now; return; } // this exact 4-tuple already routed

    // A dialer's ICE-lite punch bursts from several source addresses (v4 + multiple v6), so one
    // logical dialer arrives as MANY distinct rinfo tuples. When the PROBE carries a non-zero
    // session token we correlate them: fire onConnection ONCE per token and route every
    // same-token tuple to that one socketLike (its reply target follows the live path). With a
    // zero token (no correlation available) we key per-4-tuple — ICE-correct; the responder whose
    // HELLO reaches the dialer's chosen path wins, the rest go silent (node.js converges). Both
    // kinds now live in `_accepted`, so the legacy zero-token path is capped/swept too (DOS-2).
    const ak = tok.equals(ZERO_TOKEN) ? 'z:' + rk : 't:' + tok.toString('hex');
    const existing = this._accepted.get(ak);
    if (existing && !existing.closed) { existing.lastSeen = now; existing._addTuple(rinfo); this._peers.set(rk, existing); return; } // same session, extra path
    if (existing) this._dropAccept(ak, existing); // stale/closed entry — never resurrect it

    // DOS-1 admission control: sweep the expired, then the hard caps, then the rate bucket.
    this._sweepAccepts();
    if (this._pendingCount() >= this._maxPending) return;                          // too many un-handshaked
    if (this._accepted.size >= this._maxAccepted && !this._evictOne()) return;     // table full, nothing sheddable
    if (!this._allowAccept()) return;                                              // new-accept rate

    const sock = this._udpSocketLike(rinfo);
    sock._ak = ak;
    sock._acceptedAt = now;
    sock.lastSeen = now;
    this._accepted.set(ak, sock);
    this._onConnCb(sock);
  }

  /** TCP simultaneous-open fallback: listen on our port AND connect out to every tcp/udp
   * candidate; first established socket wins. Datagrams framed with a 2-byte length prefix
   * (wire.js is datagram-oriented). */
  _tcpFallback(remoteCands, timeout, signal) {
    const tcp = remoteCands.filter((c) => c.proto === 'tcp');
    const derived = remoteCands.filter((c) => c.proto !== 'tcp').map((c) => ({ ip: c.ip, port: c.port, proto: 'tcp', kind: c.kind }));
    const targets = [...tcp, ...derived];
    if (!targets.length) return Promise.reject(new Error('no candidates: UDP punch failed, no TCP fallback'));

    return new Promise((resolve, reject) => {
      let done = false;
      const socks = [];
      const timer = setTimeout(() => fail(new Error('TCP fallback timeout')), timeout);
      const server = net.createServer((s) => win(s));
      server.on('error', () => {}); // port may be busy; connects still race
      try { server.listen(this.port4 || this.port); } catch { /* ignore */ }
      const onAbort = () => fail(new Error('punch aborted'));
      signal?.addEventListener?.('abort', onAbort);
      const win = (s) => {
        if (done) return; done = true;
        clearTimeout(timer); signal?.removeEventListener?.('abort', onAbort);
        socks.forEach((x) => x !== s && x.destroy());
        try { server.close(); } catch { /* ignore */ }
        resolve(this._tcpSocketLike(s));
      };
      const fail = (e) => {
        if (done) return; done = true;
        clearTimeout(timer); signal?.removeEventListener?.('abort', onAbort);
        socks.forEach((x) => x.destroy());
        try { server.close(); } catch { /* ignore */ }
        reject(e);
      };
      targets.forEach((t, i) => {
        // ponytail: reuse our local port on the first connect for true simultaneous-open;
        // rest use ephemeral (SO_REUSEPORT for concurrent same-port dials needs a native
        // addon — P2). Covers the common "UDP blocked, one side reachable" TCP case.
        const optsList = i === 0 ? [{ localPort: this.port4 || this.port }, {}] : [{}];
        const tryConnect = (rest) => {
          if (done || !rest.length) return;
          const s = net.connect({ host: t.ip, port: t.port, ...rest[0] });
          socks.push(s);
          s.once('connect', () => win(s));
          s.once('error', () => { s.destroy(); tryConnect(rest.slice(1)); });
        };
        tryConnect(optsList);
      });
    });
  }

  _tcpSocketLike(s) {
    s.setNoDelay(true);
    let acc = Buffer.alloc(0);
    return {
      proto: 'tcp',
      remote: { address: s.remoteAddress, port: s.remotePort, family: norm(s.remoteFamily) },
      send: (buf) => {
        const h = Buffer.alloc(2);
        h.writeUInt16BE(buf.length, 0);
        try { s.write(Buffer.concat([h, buf])); } catch { /* closed */ }
      },
      onMessage: (cb) => {
        s.on('data', (d) => {
          acc = Buffer.concat([acc, d]);
          while (acc.length >= 2) {
            const n = acc.readUInt16BE(0);
            if (acc.length < 2 + n) break;
            cb(acc.subarray(2, 2 + n), { address: s.remoteAddress, port: s.remotePort, family: norm(s.remoteFamily) });
            acc = acc.subarray(2 + n);
          }
        });
      },
      close: () => { try { s.end(); } catch { /* ignore */ } },
    };
  }

  close() {
    clearInterval(this._netTimer);
    clearInterval(this._sweepTimer);
    try { this.sock4?.close(); } catch { /* ignore */ }
    try { this.sock6?.close(); } catch { /* ignore */ }
  }
}

function bindSock(sock, port) {
  return new Promise((res, rej) => {
    const onErr = (e) => rej(e);
    sock.once('error', onErr);
    sock.bind(port, () => { sock.removeListener('error', onErr); res(); });
  });
}

/** Create a dual-stack UDP endpoint (udp6 + udp4, same port when possible; udp4-only fallback).
 * Accept-path guards (DOS-1) are on by default and tunable: {now, maxAccepted, maxPending,
 * pendingTtlMs, acceptIdleMs, acceptRate, acceptBurst, probeRate, probeBurst, maxSources, sweepMs}.
 * @param {{port?:number}} opts  @returns {Promise<Endpoint>} */
export async function createEndpoint({ port = 0, ...opts } = {}) {
  const ep = new Endpoint(opts);
  // udp6 first (ipv6Only so udp4 is handled by its own socket — no ambiguous dual bind).
  try {
    const s6 = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: true });
    await bindSock(s6, port);
    ep.sock6 = s6; ep.port6 = s6.address().port;
  } catch { ep.sock6 = null; }
  // udp4 on the same port as udp6 when we can, else ephemeral.
  const want4 = ep.port6 || port;
  for (const p of [want4, 0]) {
    try {
      const s4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      await bindSock(s4, p);
      ep.sock4 = s4; ep.port4 = s4.address().port;
      break;
    } catch { ep.sock4 = null; }
  }
  if (!ep.sock4 && !ep.sock6) throw new Error('failed to bind any UDP socket');
  ep.port = ep.port4 || ep.port6;
  ep._attach();
  return ep;
}

// ---- standalone STUN helpers (kept for reuse by spike/tools) -----------------

/** Query ONE STUN server on a throwaway socket. @returns {Promise<{ip,port,server}>} */
export function stun(host, port, { timeoutMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const { buf, txid } = bindingRequest();
    let done = false;
    const finish = (err, res) => {
      if (done) return; done = true;
      clearTimeout(timer); try { sock.close(); } catch { /* ignore */ }
      err ? reject(err) : resolve(res);
    };
    const timer = setTimeout(() => finish(new Error(`STUN timeout ${host}:${port}`)), timeoutMs);
    sock.on('message', (msg) => { const r = parseBindingResponse(msg, txid); if (r) finish(null, { ip: r.ip, port: r.port, server: `${host}:${port}` }); });
    sock.on('error', (e) => finish(e));
    sock.send(buf, port, host, (e) => e && finish(e));
  });
}

/** Race several STUN servers, resolve with the first valid reflexive candidate. */
export async function stunAny(servers = STUN_SERVERS, opts = {}) {
  return await Promise.any(servers.map((s) => stun(s.host, s.port, opts))).catch(() => {
    throw new Error('all STUN servers failed/unreachable');
  });
}
