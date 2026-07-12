// test/fixtures/mock-relay.mjs — an in-process MQTT 3.1.1 broker behind a fake WebSocket.
//
// src/transport-wss.js speaks raw MQTT over WSS to a PUBLIC broker. To test the relay path (and
// tui↔web interop, which rides it) with ZERO network — and, critically, with no mDNS and no LAN
// UDP that could pollute a live session on this machine — we inject a WebSocket ctor that talks to
// this broker object instead of the wire.
//
// Implements exactly the subset transport-wss uses: CONNECT→CONNACK, SUBSCRIBE→SUBACK,
// PUBLISH (QoS 0, fan-out to every subscriber of the topic), PINGREQ (ignored). `hopMs` gives the
// relay a realistic latency so a raced UDP leg wins on merit, not because the mock is instant.

/** MQTT remaining-length decoder. @returns {[len, bytesConsumed]} */
function remlen(buf, i) {
  let mult = 1, len = 0, b, n = 0
  do { b = buf[i + n]; n++; len += (b & 127) * mult; mult *= 128 } while (b & 0x80)
  return [len, n]
}
const enc = (n) => { const o = []; do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; o.push(b) } while (n > 0); return o }
const pkt = (type, flags, body) => Uint8Array.from([(type << 4) | flags, ...enc(body.length), ...body])
const CONNACK = pkt(2, 0, [0, 0])
const SUBACK = pkt(9, 0, [0, 1, 0])

/**
 * @param {{hopMs?:number, drop?:(topic:string)=>boolean}} [opts] hopMs: one-way latency per hop.
 * @returns {{WebSocket:Function, subs:Map, published:number, close:Function}}
 */
export function mockRelay({ hopMs = 15, drop = () => false } = {}) {
  const subs = new Map()   // topic -> Set<FakeWS>
  const relay = { subs, published: 0, sockets: [] }

  const deliver = (ws, bytes) => {
    const t = setTimeout(() => { if (!ws._closed && ws.onmessage) ws.onmessage({ data: bytes }) }, hopMs)
    t.unref?.()
  }

  class FakeWS {
    constructor(url) {
      this.url = url
      this.binaryType = ''
      this._closed = false
      this.onopen = this.onmessage = this.onclose = this.onerror = null
      relay.sockets.push(this)
      const t = setTimeout(() => { if (!this._closed && this.onopen) this.onopen() }, 0)
      t.unref?.()
    }
    send(u8) {
      if (this._closed) return
      const buf = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8)
      let i = 0
      while (i < buf.length) {
        const type = buf[i] >> 4
        const [len, n] = remlen(buf, i + 1)
        const body = buf.subarray(i + 1 + n, i + 1 + n + len)
        if (type === 1) deliver(this, CONNACK)                                  // CONNECT
        else if (type === 8) {                                                  // SUBSCRIBE
          const tl = (body[2] << 8) | body[3]                                   // [2B pktId][2B len][topic][qos]
          const topic = Buffer.from(body.subarray(4, 4 + tl)).toString()
          if (!subs.has(topic)) subs.set(topic, new Set())
          subs.get(topic).add(this)
          deliver(this, SUBACK)
        } else if (type === 3) {                                                // PUBLISH (QoS 0)
          const tl = (body[0] << 8) | body[1]
          const topic = Buffer.from(body.subarray(2, 2 + tl)).toString()
          relay.published++
          if (!drop(topic)) {
            for (const s of subs.get(topic) || []) if (s !== this) deliver(s, pkt(3, 0, [...body]))
          }
        }
        i += 1 + n + len
      }
    }
    close() {
      if (this._closed) return
      this._closed = true
      for (const set of subs.values()) set.delete(this)
      if (this.onclose) this.onclose()
    }
  }

  relay.WebSocket = FakeWS
  relay.close = () => { for (const s of relay.sockets) s.close() }
  return relay
}

export default { mockRelay }
