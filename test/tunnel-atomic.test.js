import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { atomicJson } from '../src/atomic-json.js'

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'p2p-atomic-json-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const path = join(directory, 'state.json')
  const old = { connected: true, beat: 1, text: 'old valid state' }
  writeFileSync(path, JSON.stringify(old))
  return { directory, path, old, read: () => JSON.parse(readFileSync(path, 'utf8')) }
}

test('tunnel atomic JSON: transient Windows locks retain old JSON until replacement succeeds', t => {
  const f = fixture(t), next = { connected: false, beat: 2, text: 'שלום 🌻' }, pauses = []
  const failures = ['EPERM', 'EBUSY', 'EACCES']
  let attempts = 0
  atomicJson(f.path, next, {
    platform: 'win32', pause: ms => pauses.push(ms),
    rename: (from, to) => {
      assert.equal(to, f.path)
      assert.deepEqual(f.read(), f.old, 'destination is never removed or partially rewritten')
      assert.deepEqual(JSON.parse(readFileSync(from, 'utf8')), next, 'complete replacement is staged')
      if (attempts++ < failures.length) throw Object.assign(new Error('open reader'), { code: failures[attempts - 1] })
      renameSync(from, to)
    },
  })
  assert.equal(attempts, 4)
  assert.deepEqual(pauses, [10, 20, 40])
  assert.deepEqual(f.read(), next)
  assert.deepEqual(readdirSync(f.directory), ['state.json'], 'no staging files left after success')
})

test('tunnel atomic JSON: persistent Windows lock is bounded and cleans its staging file', t => {
  const f = fixture(t), pauses = [], error = Object.assign(new Error('locked'), { code: 'EPERM' })
  let attempts = 0
  assert.throws(() => atomicJson(f.path, { beat: 2 }, {
    platform: 'win32', pause: ms => pauses.push(ms),
    rename: () => { attempts++; assert.deepEqual(f.read(), f.old); throw error },
  }), e => e === error)
  assert.equal(attempts, 13)
  assert.ok(pauses.reduce((sum, ms) => sum + ms, 0) <= 1200, 'retry sleep budget stays below 1.2 seconds')
  assert.deepEqual(f.read(), f.old)
  assert.deepEqual(readdirSync(f.directory), ['state.json'], 'failed replacement leaves no temporary file')
})

for (const [platform, code] of [['win32', 'EIO'], ['linux', 'EPERM'], ['darwin', 'EBUSY']]) {
  test(`tunnel atomic JSON: ${platform} ${code} fails immediately without touching old state`, t => {
    const f = fixture(t), error = Object.assign(new Error('permanent error'), { code })
    let attempts = 0
    assert.throws(() => atomicJson(f.path, { beat: 2 }, {
      platform, pause: () => assert.fail('unexpected retry'), rename: () => { attempts++; throw error },
    }), e => e === error)
    assert.equal(attempts, 1)
    assert.deepEqual(f.read(), f.old)
    assert.deepEqual(readdirSync(f.directory), ['state.json'])
  })
}
