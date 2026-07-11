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
  constructor() {
    super();
    this.sock4 = null;
    this.sock6 = null;
    this.port4 = 0;
    this.port6 = 0;
    this.port = 0;
    this._stunPending = new Map(); // txidHex -> (res) => void
    this._punch = null; // active punch session { token, onProbe(type,nonce,rinfo) }
    this._peers = new Map(); // addrKey -> onMessage cb (one shared port, many punched peers)
    this._srflx = null; // cached reflexive candidate
    this._netTimer = null;
  }

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
      const p = this._punch;
      if (!p) return;
      const tok = msg.subarray(5, 13);
      if (!tok.equals(p.token)) return; // wrong session
      return p.onProbe(msg[4], msg.subarray(13, 21), rinfo);
    }
    // 3) application data — route to the matching punched peer
    const cb = this._peers.get(akey(rinfo.address, rinfo.port));
    if (cb) cb(msg, rinfo);
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
   * @param {{signal?:AbortSignal, timeout?:number, token?:Buffer|string}} opts */
  punch(remoteCands, { signal, timeout = 6000, token } = {}) {
    const tok8 = Buffer.alloc(8);
    if (token) (Buffer.isBuffer(token) ? token : Buffer.from(token)).copy(tok8);
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
          const nonce = randomBytes(8);
          if (!sent.has(ak)) sent.set(ak, new Set());
          sent.get(ak).add(nonce.toString('hex'));
          this._sendRaw(probePkt(PROBE, tok8, nonce), c.ip, c.port, c.proto === 'udp6');
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
    const v6 = rinfo.family === 6;
    this._peers.set(rk, () => {}); // reserve the route until onMessage binds a real cb
    return {
      proto: v6 ? 'udp6' : 'udp4',
      remote: { address: rinfo.address, port: rinfo.port, family: v6 ? 6 : 4 },
      send: (buf) => this._sendRaw(buf, rinfo.address, rinfo.port, v6),
      onMessage: (cb) => { this._peers.set(rk, cb); },
      close: () => { this._peers.delete(rk); },
    };
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
 * @param {{port?:number}} opts  @returns {Promise<Endpoint>} */
export async function createEndpoint({ port = 0 } = {}) {
  const ep = new Endpoint();
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
