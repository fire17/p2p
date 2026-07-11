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

/**
 * Uniform rendezvous-channel descriptor over WSS trackers — consumed by src/rendezvous/race.js
 * alongside createMdns/createDht. tracker carries the FULL candidate blob (DESIGN D6).
 * v1 = announce/echo only: the live offer-RELAY matchmaker (peer discovery via the tracker)
 * is P1 per D6, so lookup surfaces no peers yet — mDNS + DHT carry v1 discovery. Non-fatal.
 * @param {object} [opts]
 * @param {string[]} [opts.trackers] tracker URLs (defaults to TRACKERS)
 * @param {(url:string, infoHash:string, o?:object)=>Promise<any>} [opts.probe] injectable (tests)
 * @returns {{name:'tracker', ridLen:20, announce:Function, lookup:Function, close:Function}}
 */
export function createTracker(opts = {}) {
  const trackers = opts.trackers || TRACKERS;
  const probe = opts.probe || trackerProbe;

  // info (full candidate blob) is accepted for forward-compat; v1 announce is an echo only,
  // so the blob is parked until relay matchmaking lands (P1).
  function announce(rid, _info) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    const infoHash = rid.toString('hex'); // ASCII-safe over the tracker's JSON wire
    Promise.resolve(probe(trackers[0], infoHash)).catch(() => {});
    return { stop() {} };
  }

  // ponytail: v1 tracker yields no peers — live offer relay (peer discovery) is P1 per D6.
  async function* lookup(rid) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer');
    // eslint-disable-next-line no-unreachable — intentional empty async generator (P1 relay pending)
    return;
  }

  function close() { /* probes self-close their WebSocket; nothing persistent to tear down */ }

  return { name: 'tracker', ridLen: 20, announce, lookup, close };
}
