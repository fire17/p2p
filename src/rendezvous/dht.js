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
  async getPeers(infohash, { announce = false, port = 0, rounds = 6, alpha = 8 } = {}) {
    await this.ready();
    const seen = new Map();   // "host:port" -> {id?, host, port, token?, queried, dist}
    const peers = new Set();
    const withToken = [];

    // seed: resolve bootstrap hosts to IPs
    for (const b of BOOTSTRAP) {
      try {
        const { address } = await dns.lookup(b.host, { family: 4 });
        const k = `${address}:${b.port}`;
        if (!seen.has(k)) seen.set(k, { host: address, port: b.port, queried: false, dist: null });
      } catch { /* skip unresolvable bootstrap */ }
    }

    const dist = (n) => (n.id ? xor(n.id, infohash) : Buffer.alloc(20, 0xff));

    for (let round = 0; round < rounds; round++) {
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

  close() { try { this.socket.close(); } catch { /* already closed */ } }
}
