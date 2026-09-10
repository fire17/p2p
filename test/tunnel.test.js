// test/tunnel.test.js — the AGENT TUNNEL pure layer (src/tunnel.js).
//
// Everything here is offline and deterministic: no node, no socket, no filesystem. The point of
// the pure layer is that the wire format can be proven without a network, so this file must stay
// that way.
//
// The bar that matters: `peer.send()` REJECTS above peer.maxMessage — src/node.js:169,
// mtu 1200 - HEADER_LEN 17 - MAC_LEN 16 (src/wire.js:45,47) - AEAD_TAG 16 - APP_HDR 5
// (src/node.js:61-62) = 1146 bytes. A part that exceeds it is not "slow", it is a thrown
// RangeError mid-conversation, so every chunk assertion below checks BOTH the caller's bar and
// that hard wire ceiling.

import test from 'node:test'
import assert from 'node:assert/strict'
import {
  WIRE_MAX, CHUNK_MAX, MAX_DECODE_BYTES, PROMPT_TAIL,
  encodeMsg, decodeMsg, chunk, createAssembler, splitLines, tunnelDir, newId, renderPrompt
} from '../src/tunnel.js'

const bytes = (s) => Buffer.byteLength(s, 'utf8')
const msg = (over = {}) => ({ v: 1, from: 'A'.repeat(26), id: 'deadbeefdeadbeef', t: '2026-09-11T00:00:00.000Z', text: 'hi', ...over })

// A real 5,000+ byte Hebrew paragraph: 2 bytes per letter, so byte length != char length and a
// naive byte slice would cut a letter in half.
const HEBREW = 'שלום חבר, זה הסוכן של תמי מדבר. '.repeat(120)   // 6,600 bytes / 3,840 chars

// ── encode / decode ───────────────────────────────────────────────────────────────────────────

test('encodeMsg/decodeMsg round-trip, including Hebrew and emoji', () => {
  const m = msg({ text: 'שלום 👋 world' })
  const back = decodeMsg(encodeMsg(m))
  assert.deepEqual(back, m)
})

test('encodeMsg never emits a literal newline (one message = one jsonl row)', () => {
  const s = encodeMsg(msg({ text: 'line one\nline two\r\nline three' }))
  assert.equal(s.includes('\n'), false)
  assert.equal(s.includes('\r'), false)
  assert.equal(decodeMsg(s).text, 'line one\nline two\r\nline three')
})

test('decodeMsg: hostile input returns null and never throws', () => {
  const hostile = [
    '{"__proto__":1',                    // truncated JSON (the brief\'s exact case)
    'A'.repeat(1024 * 1024),             // 1 MB of garbage
    '',
    '   ',
    'null',
    '[]',
    '[{"v":1}]',
    '"just a string"',
    '42',
    '{"v":2,"text":"wrong version"}',
    '{"text":"no version"}',
    '{"v":1,"text":123}',                // wrong field type
    '{"v":1,"id":"x","part":0,"of":3,"text":"a"}',   // part is 1-based
    '{"v":1,"id":"x","part":4,"of":3,"text":"a"}',   // part > of
    '{"v":1,"part":1,"of":3,"text":"a"}',            // chunked but no group id
    Buffer.from('{"v":1}'),              // not a string
    null, undefined, 7, {}, []
  ]
  for (const h of hostile) {
    let out
    assert.doesNotThrow(() => { out = decodeMsg(h) }, 'decodeMsg threw on ' + String(h).slice(0, 40))
    assert.equal(out, null, 'accepted hostile input: ' + String(h).slice(0, 40))
  }
})

test('decodeMsg: a __proto__ key cannot pollute the prototype', () => {
  const out = decodeMsg('{"v":1,"text":"x","__proto__":{"polluted":true}}')
  assert.equal(out.text, 'x')
  assert.equal(Object.prototype.hasOwnProperty.call(out, '__proto__'), false)
  assert.equal({}.polluted, undefined, 'Object.prototype was polluted')
})

test('decodeMsg: oversize but VALID JSON is still refused (a datagram cannot be this big)', () => {
  const big = encodeMsg(msg({ text: 'x'.repeat(MAX_DECODE_BYTES) }))
  assert.ok(bytes(big) > MAX_DECODE_BYTES)
  assert.equal(decodeMsg(big), null)
})

// ── chunking ──────────────────────────────────────────────────────────────────────────────────

test('chunk: a message that already fits is passed through as one part, unchanged', () => {
  const m = msg({ text: 'short' })
  const parts = chunk(m)
  assert.equal(parts.length, 1)
  assert.equal(parts[0], encodeMsg(m))
  assert.equal(decodeMsg(parts[0]).part, undefined, 'a single part carries no part/of')
})

test('chunk: 5,000+ bytes of Hebrew -> every part under the bar AND under peer.maxMessage', () => {
  assert.ok(bytes(HEBREW) > 5000, 'fixture is ' + bytes(HEBREW) + ' bytes')
  const parts = chunk(msg({ text: HEBREW }))
  assert.ok(parts.length > 5, 'expected several parts, got ' + parts.length)
  for (const [i, p] of parts.entries()) {
    assert.ok(bytes(p) <= CHUNK_MAX, 'part ' + (i + 1) + ' is ' + bytes(p) + ' bytes > CHUNK_MAX ' + CHUNK_MAX)
    assert.ok(bytes(p) < WIRE_MAX, 'part ' + (i + 1) + ' is ' + bytes(p) + ' bytes >= peer.maxMessage ' + WIRE_MAX)
  }
})

test('chunk: Hebrew reassembles BYTE-IDENTICAL (no codepoint was cut in half)', () => {
  const m = msg({ text: HEBREW })
  const asm = createAssembler()
  let whole = null
  for (const p of chunk(m)) whole = asm.push(decodeMsg(p)) || whole
  assert.ok(whole, 'never assembled')
  assert.equal(whole.text, HEBREW)
  assert.equal(Buffer.compare(Buffer.from(whole.text, 'utf8'), Buffer.from(HEBREW, 'utf8')), 0)
  assert.equal(whole.from, m.from)
  assert.equal(whole.id, m.id)
})

test('chunk: parts share one id and are numbered 1..n of n', () => {
  const parts = chunk(msg({ text: HEBREW })).map(decodeMsg)
  const n = parts.length
  assert.ok(n > 1)
  for (const [i, p] of parts.entries()) {
    assert.equal(p.id, 'deadbeefdeadbeef')
    assert.equal(p.part, i + 1)
    assert.equal(p.of, n)
    assert.equal(p.v, 1)
  }
})

test('chunk: escape-heavy text (quotes, backslashes, control chars) still respects the bar', () => {
  // JSON escaping expands these 1 -> 2 or 1 -> 6 bytes; a byte-count-only splitter overflows here.
  const nasty = '"\\\n\t'.repeat(600)
  const parts = chunk(msg({ text: nasty }))
  for (const p of parts) assert.ok(bytes(p) <= CHUNK_MAX, 'escape expansion blew the bar: ' + bytes(p))
  const asm = createAssembler()
  let whole = null
  for (const p of parts) whole = asm.push(decodeMsg(p)) || whole
  assert.equal(whole.text, nasty)
})

test('chunk: 4-byte astral codepoints are never split', () => {
  const emoji = '🧠🤝'.repeat(500)
  const parts = chunk(msg({ text: emoji }))
  for (const p of parts) assert.ok(decodeMsg(p), 'a part failed to decode — a surrogate pair was cut')
  const asm = createAssembler()
  let whole = null
  for (const p of parts) whole = asm.push(decodeMsg(p)) || whole
  assert.equal(whole.text, emoji)
})

test('chunk: a bar too small for the envelope is refused, not silently truncated', () => {
  assert.throws(() => chunk(msg({ text: HEBREW }), 40), RangeError)
  assert.throws(() => chunk(msg(), 0), TypeError)
  assert.throws(() => chunk('not an object'), TypeError)
})

test('chunk: a message with no id gets one, so every part is assemblable', () => {
  const m = { v: 1, text: HEBREW }
  const parts = chunk(m).map(decodeMsg)
  assert.match(parts[0].id, /^[0-9a-f]{16}$/)
  assert.ok(parts.every((p) => p.id === parts[0].id))
})

// ── assembler ─────────────────────────────────────────────────────────────────────────────────

test('assembler: OUT-OF-ORDER parts reassemble in index order, not arrival order', () => {
  const parts = chunk(msg({ text: HEBREW })).map(decodeMsg)
  const shuffled = [...parts].reverse()
  const asm = createAssembler()
  const outs = shuffled.map((p) => asm.push(p))
  assert.equal(outs.filter(Boolean).length, 1, 'emitted more than once')
  assert.equal(outs[outs.length - 1].text, HEBREW, 'reassembled in the wrong order')
})

test('assembler: nothing is emitted until the LAST part arrives', () => {
  const parts = chunk(msg({ text: HEBREW })).map(decodeMsg)
  const asm = createAssembler()
  for (const p of parts.slice(0, -1)) assert.equal(asm.push(p), null, 'emitted early')
  assert.equal(asm.pending, 1)
  assert.equal(asm.push(parts[parts.length - 1]).text, HEBREW)
  assert.equal(asm.pending, 0, 'the finished group must be released')
})

test('assembler: duplicate parts are dropped and the message still completes exactly once', () => {
  const parts = chunk(msg({ text: HEBREW })).map(decodeMsg)
  const asm = createAssembler()
  const feed = [...parts, ...parts]                    // every part twice
  const outs = feed.map((p) => asm.push(p)).filter(Boolean)
  assert.equal(outs.length, 1)
  assert.equal(outs[0].text, HEBREW)
})

test('assembler: two interleaved messages do not contaminate each other', () => {
  const a = chunk(msg({ id: 'a'.repeat(16), text: HEBREW })).map(decodeMsg)
  const b = chunk(msg({ id: 'b'.repeat(16), text: HEBREW.split('').reverse().join('') })).map(decodeMsg)
  const asm = createAssembler()
  const outs = []
  const max = Math.max(a.length, b.length)
  for (let i = 0; i < max; i++) {
    if (a[i]) { const o = asm.push(a[i]); if (o) outs.push(o) }
    if (b[i]) { const o = asm.push(b[i]); if (o) outs.push(o) }
  }
  assert.equal(outs.length, 2)
  assert.equal(outs.find((o) => o.id === 'a'.repeat(16)).text, HEBREW)
})

test('assembler: unchunked and of:1 messages pass straight through', () => {
  const asm = createAssembler()
  const plain = msg({ text: 'no parts here' })
  assert.deepEqual(asm.push(plain), plain)
  const one = asm.push(msg({ text: 'solo', part: 1, of: 1 }))
  assert.equal(one.text, 'solo')
  assert.equal(one.part, undefined)
  assert.equal(one.of, undefined)
})

test('assembler: a hostile group (bad part numbers, inconsistent of, junk) never throws', () => {
  const asm = createAssembler()
  for (const bad of [null, 'str', [], { part: 1 }, { id: 'x', part: 0, of: 2 }, { id: 'x', part: 3, of: 2 }]) {
    assert.doesNotThrow(() => asm.push(bad))
    assert.equal(asm.push(bad), null)
  }
  assert.equal(asm.push({ v: 1, id: 'g', part: 1, of: 2, text: 'a' }), null)
  assert.equal(asm.push({ v: 1, id: 'g', part: 2, of: 5, text: 'b' }), null, 'an inconsistent `of` must be ignored')
  assert.equal(asm.push({ v: 1, id: 'g', part: 2, of: 2, text: 'b' }).text, 'ab')
})

test('assembler: an abandoned group is evicted instead of growing without bound', () => {
  const asm = createAssembler({ maxPending: 3 })
  for (let i = 0; i < 10; i++) asm.push({ v: 1, id: 'g' + i, part: 1, of: 2, text: 'x' })
  assert.equal(asm.pending, 3)
})

// ── line framing ──────────────────────────────────────────────────────────────────────────────

test('splitLines: complete lines out, partial tail kept', () => {
  assert.deepEqual(splitLines('a\nb\nc'), { lines: ['a', 'b'], rest: 'c' })
  assert.deepEqual(splitLines('a\nb\n'), { lines: ['a', 'b'], rest: '' })
  assert.deepEqual(splitLines(''), { lines: [], rest: '' })
  assert.deepEqual(splitLines('no newline yet'), { lines: [], rest: 'no newline yet' })
  assert.deepEqual(splitLines(Buffer.from('a\nb')), { lines: ['a'], rest: 'b' })
})

test('splitLines: blank lines are skipped (an empty jsonl row is not a message)', () => {
  assert.deepEqual(splitLines('a\n\n\nb\n'), { lines: ['a', 'b'], rest: '' })
})

test('splitLines: a read split mid-message reassembles across two reads', () => {
  const wire = encodeMsg(msg()) + '\n' + encodeMsg(msg({ text: 'second' })) + '\n'
  const cut = 20
  const first = splitLines(wire.slice(0, cut))
  const second = splitLines(first.rest + wire.slice(cut))
  assert.deepEqual([...first.lines, ...second.lines].map((l) => decodeMsg(l).text), ['hi', 'second'])
})

// ── paths + ids ───────────────────────────────────────────────────────────────────────────────

test('tunnelDir: posix layout under an explicit home', () => {
  assert.equal(tunnelDir('mind', { home: '/home/x/.p2p', platform: 'linux' }), '/home/x/.p2p/tunnel/mind')
})

test('tunnelDir: P2P_HOME wins over the default home', () => {
  const d = tunnelDir('mind', { platform: 'linux', env: { P2P_HOME: '/srv/p2p' } })
  assert.equal(d, '/srv/p2p/tunnel/mind')
})

test('tunnelDir: a traversal name is refused, not sanitized into something surprising', () => {
  for (const bad of ['..', '../etc', 'a/b', 'a\\b', '', '.hidden', 'x'.repeat(80), null, 7]) {
    assert.throws(() => tunnelDir(bad, { home: '/h', platform: 'linux' }), TypeError, 'accepted ' + JSON.stringify(bad))
  }
  assert.equal(tunnelDir('mind-2.a_b', { home: '/h', platform: 'linux' }), '/h/tunnel/mind-2.a_b')
})

test('newId: 16 hex chars, and two calls differ', () => {
  assert.match(newId(), /^[0-9a-f]{16}$/)
  const seen = new Set(Array.from({ length: 200 }, newId))
  assert.equal(seen.size, 200)
})

// ── the prompt ────────────────────────────────────────────────────────────────────────────────

const PROMPT = renderPrompt({ share: 'S'.repeat(26) + '-abcd', name: 'livemind' })

test('renderPrompt: pure ASCII, so its byte length equals its JS length', () => {
  assert.match(PROMPT, /^[\x20-\x7e\n]*$/, 'the prompt carries a byte no PowerShell paste survives')
  assert.equal(bytes(PROMPT), PROMPT.length, 'byte length != char length -> not ASCII')
})

test('renderPrompt: BOTH install lines, exactly as README section 1', () => {
  assert.ok(PROMPT.includes('curl -fsSL https://p2p.akeyo.io/init | sh'), 'the macOS/Linux install line is missing')
  assert.ok(PROMPT.includes('irm https://p2p.akeyo.io/init.ps1 | iex'), 'the Windows install line is missing')
})

test('renderPrompt: BOTH absolute-shim join commands carry the share', () => {
  const share = 'S'.repeat(26) + '-abcd'
  assert.ok(PROMPT.includes('~/.local/bin/p2p tunnel join ' + share), 'posix join line missing')
  assert.ok(PROMPT.includes('\\.local\\bin\\p2p.cmd" tunnel join ' + share), 'windows join line missing')
})

test('renderPrompt: the protocol paragraph and the three verbs are present', () => {
  assert.match(PROMPT, /PROTOCOL:/)
  assert.match(PROMPT, /"v":1/)
  assert.match(PROMPT, /reply_to/)
  for (const verb of ['tunnel send', 'tunnel recv', 'tunnel stop']) {
    assert.ok(PROMPT.includes(verb), 'verb missing: ' + verb)
  }
})

test('renderPrompt: the closing sentence is verbatim and last', () => {
  assert.equal(PROMPT_TAIL, 'reply with your first message; the other side is waiting')
  assert.ok(PROMPT.includes(PROMPT_TAIL))
  assert.equal(PROMPT.trimEnd().endsWith(PROMPT_TAIL), true, 'the closing sentence must be the last line')
})

test('renderPrompt: a Hebrew first message is ASCII-folded (the WIRE stays UTF-8, the PROMPT does not)', () => {
  const p = renderPrompt({ share: 'S'.repeat(26), name: 'מוח', firstHint: 'שלום' })
  assert.match(p, /^[\x20-\x7e\n]*$/)
  assert.equal(bytes(p), p.length)
  // the tunnel itself still carries Hebrew end to end:
  assert.equal(decodeMsg(encodeMsg(msg({ text: 'שלום' }))).text, 'שלום')
})

test('renderPrompt: a share is required (an invite with no secret is not a prompt)', () => {
  assert.throws(() => renderPrompt({}), TypeError)
  assert.throws(() => renderPrompt(), TypeError)
})
