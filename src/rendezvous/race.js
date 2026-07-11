// src/rendezvous/race.js — rendezvous orchestrator: publish-fanout + read-race + epoch handling.
// Zero deps. Contract: docs/INTERFACES.md §rendezvous/race.js. Semantics: DESIGN.md D6.
//
//   publishAll(s, endpoint) — announce across ALL channels, per-channel rid (key.deriveRid),
//                             epoch + pre-announce next epoch before UTC rollover,
//                             re-announce on 'netchange'. Returns a handle with stop().
//   resolve(s)             — merged, deduped, ranked candidate stream from all channels/epochs,
//                             with dial caps (D6 anti-poisoning). Async iterable.
//
// Channels are injected (createRace({channels})) so this stays pure glue and tests use mocks.
// Each channel: { name, ridLen, announce(rid,info,opts), lookup(rid,opts) -> asyncIterable }.

import { deriveRid } from '../key.js'

const DAY_MS = 86_400_000
const PREANNOUNCE_MS = 3_600_000 // pre-announce tomorrow within 1h of rollover (INTERFACES)

/** UTC-day string "YYYY-MM-DD" for a ms timestamp. @param {number} ms @returns {string} */
export function epochStr(ms) {
  return new Date(ms).toISOString().slice(0, 10)
}

/** ms remaining until the next UTC midnight. @param {number} ms @returns {number} */
export function msUntilRollover(ms) {
  return DAY_MS - (((ms % DAY_MS) + DAY_MS) % DAY_MS)
}

/** Epochs to ANNOUNCE under now: today, plus tomorrow when within 1h of rollover. */
export function announceEpochs(nowMs) {
  const eps = [epochStr(nowMs)]
  if (msUntilRollover(nowMs) <= PREANNOUNCE_MS) eps.push(epochStr(nowMs + DAY_MS))
  return eps
}

/** Epochs to READ: yesterday, today, tomorrow (readers tolerate ±1 clock skew — D6). */
export function resolveEpochs(nowMs) {
  return [epochStr(nowMs - DAY_MS), epochStr(nowMs), epochStr(nowMs + DAY_MS)]
}

/** Stable dedup key for a candidate. @param {{proto,ip,port}} c @returns {string} */
export function candidateKey(c) {
  return `${c.proto}:${c.ip}:${c.port}`
}

// lower weight = dial first. LAN direct is cheapest/fastest, DHT gives only a single hint (D6).
// weight 0 = "fast/LAN" channel, started immediately in resolve; >0 = deferred fallback.
const CHANNEL_WEIGHT = { mdns: 0, tracker: 1, dht: 2 }

/**
 * Merge async iterables concurrently into one stream (order = arrival).
 * Abort-responsive: when `signal` fires, the pending wait resolves at once and children are
 * released (fire-and-forget it.return()) so the consumer's it.return() can't block on a slow
 * straggler (e.g. a 20s DHT crawl) — the bug that made same-LAN connects wait for the DHT.
 * @param {AsyncIterable<any>[]} iterables
 * @param {AbortSignal} [signal]
 */
async function* merge(iterables, signal) {
  const queue = []
  let wake = null
  let live = iterables.length
  let stopped = false
  if (!live) return
  const bump = () => { if (wake) { const w = wake; wake = null; w() } }
  const onAbort = () => bump()
  signal?.addEventListener('abort', onAbort, { once: true })
  for (const it of iterables) {
    ;(async () => {
      try {
        for await (const v of it) {
          if (stopped || signal?.aborted) break
          queue.push(v)
          bump()
        }
      } catch {
        /* a dead channel just contributes nothing (D6: channels are zero-trust, best-effort) */
      } finally {
        live--
        bump()
      }
    })()
  }
  try {
    while (live || queue.length) {
      if (queue.length) {
        yield queue.shift()
        continue
      }
      if (!live || signal?.aborted) break
      await new Promise((r) => (wake = r))
    }
  } finally {
    stopped = true
    signal?.removeEventListener('abort', onAbort)
    // release children without awaiting — a straggler (DHT) must not stall our own return
    for (const it of iterables) { try { it.return?.() } catch { /* */ } }
  }
}

/**
 * @param {object} cfg
 * @param {Array<{name:string,ridLen:number,announce:Function,lookup:Function}>} cfg.channels
 * @param {() => number} [cfg.now] clock (ms)
 * @param {number} [cfg.dialCap] max candidates yielded by resolve (default 20)
 * @param {number} [cfg.perChannelCap] max candidates per channel (anti-poisoning; default 8)
 */
export function createRace(cfg) {
  if (!cfg || !Array.isArray(cfg.channels) || !cfg.channels.length) {
    throw new TypeError('createRace requires a non-empty channels array')
  }
  const channels = cfg.channels
  const now = cfg.now || (() => Date.now())
  const dialCap = cfg.dialCap ?? 20
  const perChannelCap = cfg.perChannelCap ?? 8

  /** Build the per-channel info blob (dht = port only; mdns/tracker = full candidate blob). */
  function infoFor(channel, endpoint) {
    const candidates = endpoint.candidates ? endpoint.candidates() : []
    if (channel.name === 'dht') {
      const udp = candidates.find((c) => c.proto && c.proto.startsWith('udp'))
      return { port: (udp || candidates[0] || {}).port ?? endpoint.port }
    }
    return { v: 1, candidates }
  }

  /**
   * Fan-out announce across every channel for the current announce-epochs.
   * @param {string} s @param {object} endpoint
   */
  function publishAll(s, endpoint) {
    let stopped = false
    let timer = null

    const doPublish = () => {
      if (stopped) return
      const eps = announceEpochs(now())
      for (const ch of channels) {
        const info = infoFor(ch, endpoint)
        for (const ep of eps) {
          try {
            ch.announce(deriveRid(s, ch.name, ep, ch.ridLen), info)
          } catch {
            /* one channel/epoch failing must not abort the others (best-effort fan-out) */
          }
        }
      }
    }

    // republish at the next boundary: the pre-announce point, else just past rollover
    const schedule = () => {
      if (stopped) return
      const untilRoll = msUntilRollover(now())
      const untilPre = untilRoll - PREANNOUNCE_MS
      const delay = untilPre > 0 ? untilPre : untilRoll + 1000
      timer = setTimeout(() => {
        doPublish()
        schedule()
      }, delay)
      if (typeof timer?.unref === 'function') timer.unref()
    }

    const onNetchange = () => doPublish() // local IP changed → candidates changed, re-announce now
    if (typeof endpoint.on === 'function') endpoint.on('netchange', onNetchange)

    doPublish()
    schedule()

    return {
      stop() {
        stopped = true
        if (timer) clearTimeout(timer)
        if (typeof endpoint.off === 'function') endpoint.off('netchange', onNetchange)
        else if (typeof endpoint.removeListener === 'function') endpoint.removeListener('netchange', onNetchange)
      },
    }
  }

  /**
   * Race reads across every channel × {yesterday,today,tomorrow}; merge, dedup, rank, cap.
   * @param {string} s
   * @param {object} [ropts] @param {AbortSignal} [ropts.signal] @param {number} [ropts.timeout]
   * @returns {AsyncIterable<{proto,ip,port,kind?,channel:string,ts:number,score:number}>}
   */
  async function* resolve(s, ropts = {}) {
    const eps = resolveEpochs(now())
    // LAN-FIRST, two phases (DESIGN D6; matches the "blazingly fast" requirement):
    //   phase 1 — mDNS (fast, ~ms on LAN). Yield its candidates the instant they arrive.
    //   phase 2 — DHT + tracker (slow internet fallback) run ONLY IF mDNS found nobody.
    // Why phased and not concurrent: a DHT get_peers crawl runs ~15-20s (dead-node timeouts).
    // If it shared the stream, the consumer's cleanup (it.return()) would block on that crawl —
    // an async generator suspended in `await` can't run its finally until the await settles — so
    // same-LAN connects waited ~17s for a DHT they never needed. Phasing means the LAN path never
    // has a slow channel open behind it: the stream ends when mDNS's own window closes.
    const lanGraceMs = ropts.lanGraceMs ?? cfg.lanGraceMs ?? 1500
    const ac = new AbortController()
    const signal = ropts.signal ? AbortSignal.any([ropts.signal, ac.signal]) : ac.signal
    // Bound the mDNS window so the fallback decision is timely; slow lookups just get the signal.
    const fastOpts = { ...ropts, signal, timeout: ropts.timeout ?? lanGraceMs }
    const slowOpts = { ...ropts, signal }

    const fast = []
    const slow = []
    for (const ch of channels) {
      for (const ep of eps) {
        const rid = deriveRid(s, ch.name, ep, ch.ridLen)
        const isFast = CHANNEL_WEIGHT[ch.name] === 0
        const opts = isFast ? fastOpts : slowOpts
        ;(isFast ? fast : slow).push(() => tagStream(ch, ch.lookup(rid, opts)))
      }
    }

    const seen = new Set()
    const perChannel = new Map()
    let yielded = 0
    // dedup + per-channel/global cap + ranking, shared by both phases
    async function* pipe(source) {
      for await (const item of source) {
        for (const cand of item.candidates || []) {
          const key = candidateKey(cand)
          if (seen.has(key)) continue
          const cn = perChannel.get(item.channel) || 0
          if (cn >= perChannelCap) continue // anti-poisoning: no single channel dominates the budget
          seen.add(key)
          perChannel.set(item.channel, cn + 1)
          const weight = CHANNEL_WEIGHT[item.channel] ?? 3
          // score: lower = dial first — channel weight dominates, freshness (age in seconds) tie-breaks
          const ageSec = Math.max(0, (now() - item.ts) / 1000)
          yield { ...cand, channel: item.channel, ts: item.ts, score: weight * 1e6 + ageSec }
          if (++yielded >= dialCap) return
        }
      }
    }

    try {
      if (fast.length) yield* pipe(merge(fast.map((t) => t()), signal))
      // Fallback to the slow internet channels ONLY if the LAN surfaced nobody.
      if (yielded < dialCap && seen.size === 0 && slow.length) {
        yield* pipe(merge(slow.map((t) => t()), signal))
      }
    } finally {
      ac.abort() // release any still-running lookups (mDNS retransmits, a fallback DHT crawl)
    }
  }

  /** Tag each {candidates,channel,ts} record from a channel lookup with its channel name. */
  async function* tagStream(ch, iterable) {
    for await (const rec of iterable) {
      yield { candidates: rec.candidates, channel: rec.channel || ch.name, ts: rec.ts ?? now() }
    }
  }

  return { publishAll, resolve }
}
