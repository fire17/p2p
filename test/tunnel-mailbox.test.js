import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, readFileSync, rmSync, statSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readRows } from '../bin/p2p-tunnel.js'

const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const json = value => JSON.stringify(value) + '\n'
function fixture() {
  const home = mkdtempSync(join(tmpdir(), 'p2p-mailbox-pages-')), id = 'a'.repeat(32)
  const root = join(home, 'tunnel', 'default'), dir = join(root, id)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(root, 'current.json'), json({ id }))
  writeFileSync(join(dir, 'session.json'), json({ id }))
  writeFileSync(join(dir, 'state.json'), json({ id, pid: process.pid, beat: Date.now(), connected: true, self: 'fixture-self', peerKey: 'fixture-peer' }))
  return { home, dir, close: () => rmSync(home, { recursive: true, force: true }) }
}
function cli(f, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin, 'tunnel', ...args], { env: { ...process.env, P2P_HOME: f.home }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = ''
    child.stdout.on('data', chunk => { out += chunk }); child.stderr.on('data', chunk => { err += chunk })
    child.on('error', reject); child.on('exit', code => resolve({ code, out, err }))
  })
}
const terminalHistory = () => json({ v: 1, channel: 'term', text: 'x'.repeat(1024) }).repeat(9000)

test('mailbox reader seeks beyond consumed history and rejects a row larger than its bounded page', () => {
  const f = fixture(), file = join(f.dir, 'inbox.jsonl')
  try {
    const prefix = 'x'.repeat(9 * 1024 * 1024) + '\n'
    writeFileSync(file, prefix + json({ text: 'after consumed history' }))
    assert.deepEqual(readRows(file, Buffer.byteLength(prefix)).rows, [{ text: 'after consumed history' }])
    assert.throws(() => readRows(file, 0), /row exceeds 8 MiB/)
  } finally { f.close() }
})

test('ordinary recv and --all find chat after multiple terminal pages; --all never consumes the cursor', async () => {
  const f = fixture()
  try {
    writeFileSync(join(f.dir, 'inbox.jsonl'), terminalHistory() + json({ v: 1, text: 'visible chat' }))
    writeFileSync(join(f.dir, 'cursor.json'), json({ offset: 0 }))
    const history = await cli(f, ['recv', '--all'])
    assert.equal(history.code, 0, history.err)
    assert.deepEqual(history.out.trim().split('\n').map(JSON.parse).map(row => row.text), ['visible chat'])
    assert.equal(JSON.parse(readFileSync(join(f.dir, 'cursor.json'))).offset, 0)
    const fresh = await cli(f, ['recv'])
    assert.equal(fresh.code, 0, fresh.err)
    assert.equal(JSON.parse(fresh.out).text, 'visible chat')
    assert.equal(JSON.parse(readFileSync(join(f.dir, 'cursor.json'))).offset, statSync(join(f.dir, 'inbox.jsonl')).size)
  } finally { f.close() }
})

test('send --wait observes a new acknowledgment beyond an old multi-page acknowledgment history', async () => {
  const f = fixture()
  let timer
  try {
    writeFileSync(join(f.dir, 'acks.jsonl'), json({ id: 'old', delivered: true, filler: 'x'.repeat(1000) }).repeat(9000))
    timer = setInterval(() => {
      let out
      try { out = JSON.parse(readFileSync(join(f.dir, 'outbox.jsonl'), 'utf8').trim()) } catch { return }
      appendFileSync(join(f.dir, 'acks.jsonl'), json({ id: out.id, delivered: true }))
      clearInterval(timer)
    }, 20)
    const sent = await cli(f, ['send', 'new message', '--wait', '3'])
    assert.equal(sent.code, 0, sent.err + sent.out)
    assert.equal(JSON.parse(sent.out.trim().split('\n').at(-1)).delivered, true)
  } finally { clearInterval(timer); f.close() }
})
