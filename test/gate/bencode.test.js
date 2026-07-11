import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encode, decode } from '../../src/rendezvous/bencode.js';

test('integers', () => {
  assert.equal(encode(0).toString(), 'i0e');
  assert.equal(encode(42).toString(), 'i42e');
  assert.equal(encode(-7).toString(), 'i-7e');
  assert.equal(decode(Buffer.from('i42e')), 42);
  assert.equal(decode(Buffer.from('i-7e')), -7);
  assert.throws(() => decode(Buffer.from('i-0e')));
  assert.throws(() => decode(Buffer.from('i03e')));
});

test('byte strings preserve binary', () => {
  const bin = Buffer.from([0, 1, 2, 255, 0x3a, 0x65]);
  const round = decode(encode(bin));
  assert.ok(Buffer.isBuffer(round));
  assert.deepEqual(round, bin);
  assert.equal(encode(Buffer.from('spam')).toString(), '4:spam');
});

test('lists', () => {
  const v = [1, Buffer.from('a'), [2]];
  const r = decode(encode(v));
  assert.equal(r[0], 1);
  assert.deepEqual(r[1], Buffer.from('a'));
  assert.deepEqual(r[2], [2]);
  assert.equal(encode([]).toString(), 'le');
});

test('dicts sort keys by raw bytes', () => {
  assert.equal(encode({ b: 1, a: 2 }).toString(), 'd1:ai2e1:bi1ee');
  const r = decode(Buffer.from('d3:cow3:moo4:spam4:eggse'));
  assert.deepEqual(r.cow, Buffer.from('moo'));
  assert.deepEqual(r.spam, Buffer.from('eggs'));
});

test('KRPC-shaped roundtrip', () => {
  const id = Buffer.alloc(20, 7);
  const msg = { t: Buffer.from([0, 1]), y: 'q', q: 'get_peers', a: { id, info_hash: Buffer.alloc(20, 9) } };
  const r = decode(encode(msg));
  assert.deepEqual(r.t, Buffer.from([0, 1]));
  assert.deepEqual(r.y, Buffer.from('q'));
  assert.deepEqual(r.a.id, id);
});

test('rejects malformed input', () => {
  assert.throws(() => decode(Buffer.from('4:ab')));   // string past end
  assert.throws(() => decode(Buffer.from('i1e2:xx'))); // trailing bytes
  assert.throws(() => decode(Buffer.from('d1:a')));    // unterminated dict
  assert.throws(() => decode(Buffer.from('l1:a')));    // unterminated list
});
