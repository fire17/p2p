// Minimal Mainline (BitTorrent) DHT client — KRPC over node:dgram, client-only
// (no serving routing table). Iterative get_peers toward an infohash + announce_peer.
// Zero deps. Rides bencode.js. See DESIGN.md D6/D7, research/rendezvous.md §2.

import dgram from 'node:dgram';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { encode, decode } from './bencode.js';
// Single-source rid derivation (canonicalizes the key → no case-mismatch between peers).
import { deriveRid } from '../key.js';
export { deriveRid };

export const BOOTSTRAP = [
  { host: 'router.bittorrent.com', port: 6881 },
  { host: 'router.utorrent.com', port: 6881 },
  { host: 'dht.transmissionbt.com', port: 6881 },
  { host: 'dht.libtorrent.org', port: 25401 },
];

const xor = (a, b) => { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };
const cmpBuf = (a, b) => Buffer.compare(a, b); // XOR distance compare (buffers same length)

/** parse compact "nodes" (26B each: 20 id + 4 ip + 2 port) */
function parseNodes(buf) {
  const nodes = [];
  if (!Buffer.isBuffer(buf)) return nodes;
  for (let i = 0; i + 26 <= buf.length; i += 26) {
    const id = buf.subarray(i, i + 20);
    const host = `${buf[i + 20]}.${buf[i + 21]}.${buf[i + 22]}.${buf[i + 23]}`;
    const port = buf.readUInt16BE(i + 24);
    if (port > 0) nodes.push({ id, host, port });
  }
  return nodes;
}

/** parse compact peer "values" (list of 6B: 4 ip + 2 port) */
function parseValues(values) {
  const peers = [];
  if (!Array.isArray(values)) return peers;
  for (const v of values) {
    if (Buffer.isBuffer(v) && v.length === 6) {
      peers.push(`${v[0]}.${v[1]}.${v[2]}.${v[3]}:${v.readUInt16BE(4)}`);
    }
  }
  return peers;
}

export class DHT {
  constructor() {
    this.id = crypto.randomBytes(20);
    this.socket = dgram.createSocket('udp4');
    this.pending = new Map(); // txid hex -> {resolve, reject, timer}
    this.tx = 0;
    this.socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));
    this.socket.on('error', () => {}); // ignore transient ICMP-port-unreachable noise
    this._ready = new Promise((res) => this.socket.bind(0, res));
  }

  ready() { return this._ready; }

  _onMessage(msg, rinfo) {
    let m;
    try { m = decode(msg); } catch { return; }
    if (!m || !Buffer.isBuffer(m.t)) return;
    const key = m.t.toString('hex');
    const p = this.pending.get(key);
    if (!p) return;
    this.pending.delete(key);
    clearTimeout(p.timer);
    const y = Buffer.isBuffer(m.y) ? m.y.toString() : '';
    if (y === 'r' && m.r) p.resolve({ r: m.r, rinfo });
    else p.reject(new Error(y === 'e' ? `krpc error ${JSON.stringify(m.e)}` : 'krpc non-response'));
  }

  /** send a KRPC query to {host,port}; resolves with response dict r */
  query(node, method, args, timeout = 3000) {
    const t = Buffer.from([(this.tx >> 8) & 0xff, this.tx & 0xff]);
    this.tx = (this.tx + 1) & 0xffff;
    const key = t.toString('hex');
    const msg = encode({ t, y: 'q', q: method, a: { id: this.id, ...args } });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(key); reject(new Error('timeout')); }, timeout);
      this.pending.set(key, { resolve, reject, timer });
      this.socket.send(msg, node.port, node.host, (err) => {
        if (err) { clearTimeout(timer); this.pending.delete(key); reject(err); }
      });
    });
  }

  async ping(node) { return this.query(node, 'ping', {}); }

  /** iterative get_peers toward infohash (20B). Optionally announce self under it.
   *  @returns {Promise<{peers:string[], announced:number, queried:number, tokenNodes:number}>} */
  async getPeers(infohash, { announce = false, port = 0, rounds = 6, alpha = 8, signal, stopOnFirstPeers = false } = {}) {
    await this.ready();
    const seen = new Map();   // "host:port" -> {id?, host, port, token?, queried, dist}
    const peers = new Set();
    const withToken = [];

    // seed: resolve bootstrap hosts to IPs IN PARALLEL (a slow/dead resolver must not serialize
    // in front of the others — this is on the latency path for the DHT fallback).
    await Promise.all(BOOTSTRAP.map(async (b) => {
      try {
        const { address } = await dns.lookup(b.host, { family: 4 });
        const k = `${address}:${b.port}`;
        if (!seen.has(k)) seen.set(k, { host: address, port: b.port, queried: false, dist: null });
      } catch { /* skip unresolvable bootstrap */ }
    }));

    const dist = (n) => (n.id ? xor(n.id, infohash) : Buffer.alloc(20, 0xff));

    for (let round = 0; round < rounds; round++) {
      if (signal?.aborted) break; // caller gave up (e.g. LAN peer already found) — stop early
      // stopOnFirstPeers: lookups (not announces) can return the moment any peer is found —
      // shaves rounds off the latency path. OFF by default so the live gate test is unaffected.
      if (stopOnFirstPeers && !announce && peers.size > 0) break;
      const cand = [...seen.values()].filter((n) => !n.queried)
        .sort((a, b) => cmpBuf(dist(a), dist(b))).slice(0, alpha);
      if (cand.length === 0) break;

      await Promise.all(cand.map(async (n) => {
        n.queried = true;
        try {
          const { r } = await this.query(n, 'get_peers', { info_hash: infohash });
          if (Buffer.isBuffer(r.token)) { n.token = r.token; if (r.id) n.id = r.id; withToken.push(n); }
          for (const pr of parseValues(r.values)) peers.add(pr);
          for (const nn of parseNodes(r.nodes)) {
            const k = `${nn.host}:${nn.port}`;
            if (!seen.has(k)) seen.set(k, { ...nn, queried: false });
          }
        } catch { /* dead node — expected on public DHT */ }
      }));
    }

    let announced = 0;
    if (announce) {
      // announce to the 8 closest nodes that handed us a token
      const targets = withToken.filter((n) => n.token)
        .sort((a, b) => cmpBuf(dist(a), dist(b))).slice(0, 8);
      await Promise.all(targets.map(async (n) => {
        try {
          await this.query(n, 'announce_peer', {
            info_hash: infohash, port, token: n.token, implied_port: port ? 0 : 1,
          });
          announced++;
        } catch { /* node refused — fine */ }
      }));
    }

    return { peers: [...peers], announced, queried: [...seen.values()].filter((n) => n.queried).length, tokenNodes: withToken.length };
  }

  // ── BEP44 mutable items (invite mode only) ───────────────────────────────────────────────────
  // WHY: announce_peer is unfixable for privacy — it PUBLISHES your source ip:port and get_peers
  // hands it to anyone (BEP5). There is no payload to encrypt; the leaked datum IS the transport
  // address. BEP44 stores an ARBITRARY value under target = SHA1(pubkey ‖ salt), signed with
  // Ed25519 — so we store a sealed, fixed-length ciphertext instead of an IP.
  // (research/metadata-privacy.md §4.2 — this is the decision that revives DESIGN D7's rejected
  // BEP44 path: D7's blocker was that a commitment-only S cannot yield the 32-byte signing pubkey a
  // reader needs. With a per-invite K_inv BOTH parties derive the SAME keypair from it, so both
  // compute the same target — and "the write key is public to holders" now means "public to the ONE
  // invitee", who has no incentive to squat their own invite. Reusable-S mode keeps announce_peer.)

  /** Iterative traversal toward `target`, calling `method` on each node. @returns {{withToken:object[], best:object|null}} */
  async _traverse(target, method, extraArgs, { rounds = 6, alpha = 8, signal } = {}) {
    await this.ready();
    const seen = new Map();
    const withToken = [];
    let best = null; // highest-seq valid-shaped mutable item seen

    await Promise.all(BOOTSTRAP.map(async (b) => {
      try {
        const { address } = await dns.lookup(b.host, { family: 4 });
        const k = `${address}:${b.port}`;
        if (!seen.has(k)) seen.set(k, { host: address, port: b.port, queried: false });
      } catch { /* skip unresolvable bootstrap */ }
    }));

    const dist = (n) => (n.id ? xor(n.id, target) : Buffer.alloc(20, 0xff));

    for (let round = 0; round < rounds; round++) {
      if (signal?.aborted) break;
      const cand = [...seen.values()].filter((n) => !n.queried)
        .sort((a, b) => cmpBuf(dist(a), dist(b))).slice(0, alpha);
      if (cand.length === 0) break;
      await Promise.all(cand.map(async (n) => {
        n.queried = true;
        try {
          const { r } = await this.query(n, method, { target, ...extraArgs });
          if (Buffer.isBuffer(r.token)) { n.token = r.token; if (r.id) n.id = r.id; withToken.push(n); }
          if (Buffer.isBuffer(r.v) && Buffer.isBuffer(r.sig) && Buffer.isBuffer(r.k)) {
            const seq = typeof r.seq === 'number' ? r.seq : 0;
            if (!best || seq > best.seq) best = { v: r.v, sig: r.sig, k: r.k, seq };
          }
          for (const nn of parseNodes(r.nodes)) {
            const k = `${nn.host}:${nn.port}`;
            if (!seen.has(k)) seen.set(k, { ...nn, queried: false });
          }
        } catch { /* dead node — expected on the public DHT */ }
      }));
    }
    return { withToken, best, queried: [...seen.values()].filter((n) => n.queried).length };
  }

  /** BEP44 `get` — fetch the newest mutable item at `target`. @returns {Promise<{item:object|null}>} */
  async bep44Get(target, opts = {}) {
    const { best } = await this._traverse(target, 'get', {}, opts);
    return { item: best };
  }

  /** BEP44 `put` of a signed mutable item (v MUST be under the 1000-byte soft cap). */
  async bep44Put({ target, k, salt, seq, v, sig }, opts = {}) {
    const { withToken } = await this._traverse(target, 'get', {}, opts);
    const targets = withToken.filter((n) => n.token).slice(0, 8);
    let stored = 0;
    await Promise.all(targets.map(async (n) => {
      try {
        await this.query(n, 'put', { k, salt, seq, v, sig, token: n.token });
        stored++;
      } catch { /* node refused (unsupported/full) — fine, others take it */ }
    }));
    return { stored };
  }

  close() { try { this.socket.close(); } catch { /* already closed */ } }
}

/**
 * Uniform rendezvous-channel descriptor over the DHT — consumed by src/rendezvous/race.js
 * alongside createMdns/createTracker. announce = get_peers + announce_peer under the rid
 * infohash with a marker port; lookup = get_peers yielding discovered ip:port candidates.
 * DHT stores only a PORT hint (DESIGN D6), so announce info = { port }.
 * @param {object} [opts]
 * @param {{getPeers:Function, close:Function}} [opts.dht] injectable backend (tests avoid real UDP)
 * @param {() => number} [opts.now] clock (ms)
 * @param {number} [opts.port] default announce port when info.port is absent
 * @param {number} [opts.rounds] iterative get_peers rounds
 * @param {object} [opts.invite] an src/invite.js createInvite() context → INVITE MODE: the channel
 *   switches from plaintext announce_peer to ENCRYPTED BEP44 (sealed candidates, never an IP on the
 *   DHT). Absent → today's reusable-S behaviour, byte-identical.
 * @returns {{name:'dht', ridLen:20, announce:Function, lookup:Function, close:Function}}
 */
export function createDht(opts = {}) {
  const now = opts.now || (() => Date.now());
  const rounds = opts.rounds ?? 6;
  const dht = opts.dht || new DHT();
  const inv = opts.invite || null;

  /** INVITE MODE: put a sealed, signed, fixed-length blob at the K_inv-derived BEP44 target. */
  function announceBep44(rid, info) {
    const candidates = (info && info.candidates) || (info && info.port ? [{ proto: 'udp4', port: info.port, kind: 'host' }] : []);
    const blob = { v: 1, ts: now(), candidates };
    const v = inv.codec.seal(blob, rid);                  // fixed-length ciphertext (288 B « BEP44's 1000 B cap)
    const seq = Math.floor(now() / 1000);                 // monotonic per BEP44
    const sig = inv.bep44Sign(rid, seq, v);
    const target = inv.bep44Target(rid);
    Promise.resolve(dht.bep44Put({ target, k: inv.bepPub, salt: inv.bep44Salt(rid), seq, v, sig }, { rounds }))
      .catch(() => {});                                    // fire-and-forget, same contract as announce_peer
    return { stop() {} };
  }

  /** INVITE MODE: fetch the item, verify the K_inv-derived signature, AEAD-open the candidates. */
  async function* lookupBep44(rid, lopts) {
    const target = inv.bep44Target(rid);
    let item;
    try { ({ item } = await dht.bep44Get(target, { rounds, signal: lopts.signal })); } catch { return; }
    if (!item || !Buffer.isBuffer(item.v)) return;
    if (Buffer.isBuffer(item.k) && !item.k.equals(inv.bepPub)) return;      // someone else's item at this target
    if (!inv.bep44Verify(rid, item.seq, item.v, item.sig)) return;          // BEP44 signature (belt)
    const blob = inv.codec.open(item.v, rid);                               // AEAD tag (braces) — null if not ours
    if (!blob || !Array.isArray(blob.candidates) || !blob.candidates.length) return;
    yield { candidates: blob.candidates, channel: 'dht', ts: blob.ts || now() };
  }

  function announce(rid, info = {}) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    if (inv) return announceBep44(rid, info);
    const port = info.port ?? opts.port ?? 0;
    // fire-and-forget: race drives re-announce on epoch/netchange; a failed announce is non-fatal
    Promise.resolve(dht.getPeers(rid, { announce: true, port, rounds })).catch(() => {});
    return { stop() {} };
  }

  async function* lookup(rid, lopts = {}) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    if (inv) { yield* lookupBep44(rid, lopts); return; }
    let res;
    try {
      res = await dht.getPeers(rid, { announce: false, rounds, signal: lopts.signal, stopOnFirstPeers: true });
    } catch { return; }
    const candidates = [];
    for (const hp of res.peers || []) {
      const i = hp.lastIndexOf(':');
      if (i < 0) continue;
      const ip = hp.slice(0, i);
      const port = Number(hp.slice(i + 1));
      if (Number.isInteger(port) && port > 0) candidates.push({ proto: 'udp4', ip, port, kind: 'srflx' });
    }
    if (candidates.length) yield { candidates, channel: 'dht', ts: now() };
  }

  function close() { try { dht.close(); } catch { /* already closed */ } }

  return { name: 'dht', ridLen: 20, announce, lookup, close };
}
