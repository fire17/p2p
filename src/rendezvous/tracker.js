// Public WebTorrent WSS tracker client (native global WebSocket, Node >=22).
// Spike scope: prove reachability + the announce/offer message format. The tracker is
// a LIVE matchmaker (DESIGN.md D6): a listener holds a persistent conn and answers
// offers. Full offer/answer matchmaking is P1; here we do announce -> response, and
// a best-effort two-peer offer relay. Zero deps. See research/rendezvous.md §3.

import crypto from 'node:crypto';

// live-probed healthy 2026-07-11 (research/rendezvous.md appendix)
export const TRACKERS = [
  'wss://tracker.openwebtorrent.com',
  'wss://tracker.webtorrent.dev',
  'wss://tracker.btorrent.xyz',
];

// 20-char printable-ASCII id (avoids UTF-8 mangling of the JSON string on the wire)
export function randId20() {
  const b = crypto.randomBytes(20);
  let s = '';
  for (let i = 0; i < 20; i++) s += String.fromCharCode(0x21 + (b[i] % 0x5d)); // 0x21..0x7d
  return s;
}

const FAKE_SDP = 'v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=p2p-spike-offer\r\n';

/**
 * Connect to a WSS tracker, send one announce carrying an offer, await the tracker's
 * announce response. Proves reachability + message format.
 * @returns {Promise<{ok:boolean, url:string, latencyMs:number, response?:object, error?:string}>}
 */
export function trackerProbe(url, infoHash = randId20(), { timeout = 12000 } = {}) {
  return new Promise((resolve) => {
    const started = performance.now();
    let ws, timer, done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); try { ws && ws.close(); } catch {} resolve(r); };
    timer = setTimeout(() => finish({ ok: false, url, latencyMs: timeout, error: 'timeout' }), timeout);
    try { ws = new WebSocket(url); } catch (e) { return finish({ ok: false, url, latencyMs: 0, error: String(e) }); }

    ws.onopen = () => {
      const peerId = randId20();
      ws.send(JSON.stringify({
        action: 'announce', info_hash: infoHash, peer_id: peerId,
        numwant: 5, uploaded: 0, downloaded: 0, left: 0,
        offers: [{ offer_id: randId20(), offer: { type: 'offer', sdp: FAKE_SDP } }],
      }));
    };
    ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : ''); } catch { return; }
      // tracker echoes info_hash + an interval on the announce response
      if (m && m.action === 'announce' || (m && ('interval' in m || 'complete' in m))) {
        finish({ ok: true, url, latencyMs: Math.round(performance.now() - started), response: m });
      }
    };
    ws.onerror = (e) => finish({ ok: false, url, latencyMs: Math.round(performance.now() - started), error: (e && e.message) || 'ws error' });
    ws.onclose = () => finish({ ok: false, url, latencyMs: Math.round(performance.now() - started), error: 'closed before response' });
  });
}

/**
 * Best-effort two-peer matchmaker proof on ONE tracker: peer A announces an offer under
 * infoHash, peer B announces (numwant>0) under the same infoHash; the tracker should
 * relay A's offer to B. Resolves {relayed} true if B saw an 'offer' message.
 */
export function trackerRelayProbe(url, infoHash = randId20(), { timeout = 15000 } = {}) {
  return new Promise((resolve) => {
    let a, b, timer, done = false, aReady = false;
    const idA = randId20(), idB = randId20(), offerId = randId20();
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); try { a && a.close(); } catch {} try { b && b.close(); } catch {} resolve(r); };
    timer = setTimeout(() => finish({ ok: false, url, relayed: false, error: 'timeout' }), timeout);
    try { a = new WebSocket(url); b = new WebSocket(url); } catch (e) { return finish({ ok: false, url, relayed: false, error: String(e) }); }

    a.onopen = () => {
      a.send(JSON.stringify({ action: 'announce', info_hash: infoHash, peer_id: idA, numwant: 5,
        uploaded: 0, downloaded: 0, left: 0,
        offers: [{ offer_id: offerId, offer: { type: 'offer', sdp: FAKE_SDP } }] }));
      aReady = true;
    };
    // B announces slightly after A so the offer is already parked
    b.onopen = () => setTimeout(() => { if (aReady) b.send(JSON.stringify({
      action: 'announce', info_hash: infoHash, peer_id: idB, numwant: 5,
      uploaded: 0, downloaded: 0, left: 0 })); }, 1500);
    b.onmessage = (ev) => {
      let m; try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : ''); } catch { return; }
      if (m && m.offer && m.offer_id) finish({ ok: true, url, relayed: true, from: m.peer_id });
    };
    a.onerror = b.onerror = (e) => finish({ ok: false, url, relayed: false, error: (e && e.message) || 'ws error' });
  });
}

// ── live WSS matchmaker (v1.1, DESIGN D6 — trystero pattern, research/rendezvous.md §3) ────────
// The tracker is a pure relay: it matches announcers under an infohash and forwards their
// WebRTC offer/answer SDP blobs. We piggyback our candidate blob inside the SDP (an a=p2p-blob
// line survives the tracker's opaque relay), keyed by a derived infohash. No WebRTC is actually
// used — the tracker is just the signaling rendezvous.

const NUMWANT = 10;
const OFFERS_PER_ANNOUNCE = 4;   // each offer is single-use; a handful lets several dialers match
const DEFAULT_INTERVAL_MS = 10000; // trystero cadence; offers expire ~120s so we refresh
const RECONNECT_MS = 3000;
const SDP_HEAD = 'v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n';

/** Wrap a candidate blob in a minimal SDP so it relays cleanly through the tracker. */
function packSdp(blob) {
  const b64 = Buffer.from(JSON.stringify(blob), 'utf8').toString('base64');
  return SDP_HEAD + 'a=p2p-blob:' + b64 + '\r\n';
}
/** Extract a candidate blob from an SDP produced by packSdp (null if absent/corrupt). */
function unpackSdp(sdp) {
  const m = typeof sdp === 'string' && /a=p2p-blob:([A-Za-z0-9+/=]+)/.exec(sdp);
  if (!m) return null;
  try { return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8')); } catch { return null; }
}
/**
 * Deterministic 20-char printable-ASCII infohash from a 20-byte rid. Both peers derive the same
 * from the same rid; printable ASCII avoids the JSON UTF-8 mangling that a raw binary id suffers.
 */
export function infoHashFor(rid) {
  if (!Buffer.isBuffer(rid) || rid.length < 20) throw new TypeError('rid must be a >=20-byte Buffer');
  let s = '';
  for (let i = 0; i < 20; i++) s += String.fromCharCode(0x21 + (rid[i] % 0x5d)); // 0x21..0x7d
  return s;
}

/**
 * Uniform rendezvous-channel descriptor over WSS trackers — consumed by src/rendezvous/race.js
 * alongside createMdns/createDht. The tracker carries the FULL candidate blob (DESIGN D6) and is
 * a LIVE matchmaker: a listener holds persistent connections and answers incoming offers, so a
 * dialer that shows up later is matched (the tracker retains offers ~120s).
 * @param {object} [opts]
 * @param {string[]} [opts.trackers] tracker URLs (defaults to TRACKERS)
 * @param {*} [opts.WebSocket] WebSocket constructor (defaults to global; injectable for tests)
 * @param {() => number} [opts.now] clock (ms)
 * @param {number} [opts.announceIntervalMs] re-announce cadence for persistent connections
 * @returns {{name:'tracker', ridLen:20, announce:Function, lookup:Function, close:Function}}
 */
export function createTracker(opts = {}) {
  const trackers = opts.trackers || TRACKERS;
  const WS = opts.WebSocket || (typeof WebSocket !== 'undefined' ? WebSocket : null);
  const now = opts.now || (() => Date.now());
  const intervalMs = opts.announceIntervalMs || DEFAULT_INTERVAL_MS;
  const myId = randId20();

  const active = new Map(); // infoHash -> { blob, conns:[], stop }

  function offersFor(blob) {
    const sdp = packSdp(blob);
    return Array.from({ length: OFFERS_PER_ANNOUNCE }, () => ({ offer_id: randId20(), offer: { type: 'offer', sdp } }));
  }
  function announceMsg(infoHash, blob) {
    return { action: 'announce', info_hash: infoHash, peer_id: myId, numwant: NUMWANT, uploaded: 0, downloaded: 0, left: 0, offers: offersFor(blob) };
  }
  function answerMsg(infoHash, toPeerId, offerId, blob) {
    return { action: 'announce', info_hash: infoHash, peer_id: myId, to_peer_id: toPeerId, offer_id: offerId, answer: { type: 'answer', sdp: packSdp(blob) } };
  }
  const send = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch { /* not open */ } };

  /**
   * Open a WS to `url` for one infohash. Announces our offers (carrying getBlob()); on an incoming
   * offer, surfaces the peer's blob AND answers back so they learn us; on an incoming answer,
   * surfaces the peer's blob. `persistent` connections re-announce + reconnect.
   */
  function openConn(url, infoHash, getBlob, onPeerBlob, { persistent = false, signal } = {}) {
    if (!WS) return { close() {} };
    let ws, interval, reconnect, closed = false;
    const clearTimers = () => { if (interval) clearInterval(interval); if (reconnect) clearTimeout(reconnect); };
    const scheduleReconnect = () => {
      if (closed || !persistent) return;
      reconnect = setTimeout(start, RECONNECT_MS);
      if (reconnect && reconnect.unref) reconnect.unref();
    };
    function start() {
      if (closed) return;
      try { ws = new WS(url); } catch { scheduleReconnect(); return; }
      ws.onopen = () => {
        send(ws, announceMsg(infoHash, getBlob()));
        if (persistent) {
          interval = setInterval(() => send(ws, announceMsg(infoHash, getBlob())), intervalMs);
          if (interval && interval.unref) interval.unref();
        }
      };
      ws.onmessage = (ev) => {
        let m;
        try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data?.toString?.() || ''); } catch { return; }
        if (!m || m.peer_id === myId) return; // ignore our own echoes
        if (m.offer && m.offer_id && m.peer_id) {
          const blob = unpackSdp(m.offer.sdp);
          if (blob) onPeerBlob(blob);
          send(ws, answerMsg(infoHash, m.peer_id, m.offer_id, getBlob())); // let them learn us too
        } else if (m.answer && m.peer_id) {
          const blob = unpackSdp(m.answer.sdp);
          if (blob) onPeerBlob(blob);
        }
      };
      ws.onclose = () => { clearTimers(); scheduleReconnect(); };
      ws.onerror = () => { try { ws.close(); } catch { /* */ } };
    }
    const close = () => { closed = true; clearTimers(); try { ws && ws.close(); } catch { /* */ } };
    signal?.addEventListener('abort', close, { once: true });
    start();
    return { close };
  }

  /**
   * Stay registered under the rid's infohash and answer offers (LIVE matchmaker). Idempotent per
   * infohash — a re-announce just refreshes the blob on the existing connections.
   * @param {Buffer} rid @param {object} [info] full candidate blob { candidates:[...] }
   */
  function announce(rid, info) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    const infoHash = infoHashFor(rid);
    const blob = { v: 1, ts: now(), candidates: (info && info.candidates) || [] };
    const existing = active.get(infoHash);
    if (existing) { existing.blob = blob; return { stop: existing.stop }; } // refresh, reuse conns
    const state = { blob };
    const conns = trackers.map((url) => openConn(url, infoHash, () => state.blob, () => {}, { persistent: true }));
    const stop = () => { for (const c of conns) c.close(); active.delete(infoHash); };
    state.conns = conns;
    state.stop = stop;
    active.set(infoHash, state);
    return { stop };
  }

  /**
   * Find peers for a rid via the tracker: announce an offer, then yield the candidate blob from
   * any incoming offer OR answer under the infohash. Ends on timeout/signal.
   * @param {Buffer} rid
   * @param {object} [lopts] @param {number} [lopts.timeout=8000] @param {AbortSignal} [lopts.signal]
   * @returns {AsyncIterable<{candidates:object[], channel:'tracker', ts:number}>}
   */
  async function* lookup(rid, lopts = {}) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    const infoHash = infoHashFor(rid);
    const timeout = lopts.timeout ?? 8000;
    const myBlob = { v: 1, ts: now(), candidates: [] }; // a dialer seeks; it shares no candidates here
    const queue = [];
    const seen = new Set();
    let wake = null;
    const bump = () => { if (wake) { const w = wake; wake = null; w(); } };
    const onPeerBlob = (blob) => {
      const key = JSON.stringify(blob.candidates || []);
      if (seen.has(key)) return;
      seen.add(key);
      queue.push({ candidates: blob.candidates || [], channel: 'tracker', ts: blob.ts || now() });
      bump();
    };
    const conns = trackers.map((url) => openConn(url, infoHash, () => myBlob, onPeerBlob, { persistent: false, signal: lopts.signal }));
    let done = false;
    // NOT unref'd: this timer terminates the stream (same rule as mdns.lookup)
    const timer = setTimeout(() => { done = true; bump(); }, timeout);
    const onAbort = () => { done = true; bump(); };
    lopts.signal?.addEventListener('abort', onAbort, { once: true });
    try {
      while (!done || queue.length) {
        if (queue.length) { yield queue.shift(); continue; }
        if (done) break;
        await new Promise((r) => (wake = r));
      }
    } finally {
      clearTimeout(timer);
      lopts.signal?.removeEventListener('abort', onAbort);
      for (const c of conns) c.close();
    }
  }

  function close() {
    for (const state of active.values()) for (const c of state.conns) c.close();
    active.clear();
  }

  return { name: 'tracker', ridLen: 20, announce, lookup, close };
}
