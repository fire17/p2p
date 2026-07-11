// bencode encode/decode over node Buffers. Zero deps.
// Grammar: integers i<n>e ; byte strings <len>:<bytes> ; lists l..e ; dicts d..e.
// encode accepts: Buffer|string (byte string), number|bigint (integer),
//   Array (list), plain object (dict; keys sorted by raw bytes, values recursed).
// decode returns: Buffer for byte strings, Number for ints, Array for lists,
//   plain object (utf8 keys) for dicts. Binary is preserved as Buffers.

/** @param {*} v @returns {Buffer} */
export function encode(v) {
  const out = [];
  enc(v, out);
  return Buffer.concat(out);
}

function enc(v, out) {
  if (Buffer.isBuffer(v)) {
    out.push(Buffer.from(`${v.length}:`), v);
  } else if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    out.push(Buffer.from(`${b.length}:`), b);
  } else if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isInteger(v)) throw new Error('bencode: non-integer number');
    out.push(Buffer.from(`i${v}e`));
  } else if (Array.isArray(v)) {
    out.push(Buffer.from('l'));
    for (const e of v) enc(e, out);
    out.push(Buffer.from('e'));
  } else if (v && typeof v === 'object') {
    out.push(Buffer.from('d'));
    for (const k of Object.keys(v).sort()) {
      const kb = Buffer.from(k, 'utf8');
      out.push(Buffer.from(`${kb.length}:`), kb);
      enc(v[k], out);
    }
    out.push(Buffer.from('e'));
  } else {
    throw new Error(`bencode: cannot encode ${typeof v}`);
  }
}

/** @param {Buffer} buf @returns {*} */
export function decode(buf) {
  const st = { buf, i: 0 };
  const v = dec(st);
  if (st.i !== buf.length) throw new Error('bencode: trailing bytes');
  return v;
}

function dec(st) {
  const c = st.buf[st.i];
  if (c === undefined) throw new Error('bencode: unexpected end');
  if (c === 0x69) return decInt(st);        // 'i'
  if (c === 0x6c) return decList(st);       // 'l'
  if (c === 0x64) return decDict(st);       // 'd'
  if (c >= 0x30 && c <= 0x39) return decStr(st); // digit
  throw new Error(`bencode: bad prefix 0x${c.toString(16)} at ${st.i}`);
}

function decInt(st) {
  st.i++; // 'i'
  const end = st.buf.indexOf(0x65, st.i); // 'e'
  if (end < 0) throw new Error('bencode: unterminated int');
  const s = st.buf.toString('ascii', st.i, end);
  if (!/^-?\d+$/.test(s) || (s.length > 1 && s[0] === '0') || s === '-0' || /^-0/.test(s))
    throw new Error(`bencode: bad int "${s}"`);
  st.i = end + 1;
  return Number(s);
}

function decStr(st) {
  const colon = st.buf.indexOf(0x3a, st.i); // ':'
  if (colon < 0) throw new Error('bencode: unterminated string length');
  const lenStr = st.buf.toString('ascii', st.i, colon);
  if (!/^\d+$/.test(lenStr)) throw new Error('bencode: bad string length');
  const len = Number(lenStr);
  const start = colon + 1;
  const end = start + len;
  if (end > st.buf.length) throw new Error('bencode: string past end');
  st.i = end;
  return st.buf.subarray(start, end); // Buffer view (binary-safe)
}

function decList(st) {
  st.i++; // 'l'
  const arr = [];
  while (st.buf[st.i] !== 0x65) {
    if (st.i >= st.buf.length) throw new Error('bencode: unterminated list');
    arr.push(dec(st));
  }
  st.i++; // 'e'
  return arr;
}

function decDict(st) {
  st.i++; // 'd'
  const obj = {};
  while (st.buf[st.i] !== 0x65) {
    if (st.i >= st.buf.length) throw new Error('bencode: unterminated dict');
    const key = decStr(st).toString('utf8');
    obj[key] = dec(st);
  }
  st.i++; // 'e'
  return obj;
}
