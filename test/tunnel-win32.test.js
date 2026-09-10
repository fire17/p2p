// test/tunnel-win32.test.js — the tunnel on the OTHER machine.
//
// His words, 2026-09-10: "הכל צריך להיות cross-platform" — the friend is on WINDOWS. This suite
// runs on macOS/Linux in CI and still proves the Windows behaviour, three ways:
//
//   (a) PARAMETER-INJECTED platform — tunnelDir takes {platform, env}, so the win32 branch is a
//       pure function we can call directly. Fast, and it pins the exact string.
//   (b) A SPAWNED CHILD with process.platform redefined and tunnelDir called with DEFAULT args —
//       because (a) proves the branch, not that the DEFAULT reaches it. This is the leg that
//       fails if someone "simplifies" the default away.
//   (c) THE PROMPT is what a human pastes into PowerShell. A backtick is PowerShell's escape
//       character and `$` is interpolation in BOTH shells: one stray byte and the friend's
//       install line silently becomes something else.
//   (d) A SOURCE TRIPWIRE, in the shape of test/quit-always.test.js: the tunnel files must stay
//       free of the four macOS-isms that would make the Windows side fail at runtime, where no
//       CI of ours will ever see it.

import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { tunnelDir, renderPrompt, splitLines, decodeMsg } from '../src/tunnel.js'

const abs = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url))

// ── (a) the win32 branch, parameter-injected ──────────────────────────────────────────────────

test('(a) tunnelDir: win32 + %USERPROFILE% -> a real Windows path', () => {
  const d = tunnelDir('mind', { platform: 'win32', env: { USERPROFILE: 'C:\\Users\\x' } })
  assert.equal(d, 'C:\\Users\\x\\.p2p\\tunnel\\mind')
})

test('(a) tunnelDir: win32 honours P2P_HOME exactly as init.ps1 defines it', () => {
  // init.ps1:335 — set "P2P_HOME=%USERPROFILE%\.p2p" unless already set.
  const d = tunnelDir('mind', { platform: 'win32', env: { USERPROFILE: 'C:\\Users\\x', P2P_HOME: 'D:\\p2p' } })
  assert.equal(d, 'D:\\p2p\\tunnel\\mind')
})

test('(a) tunnelDir: the same name yields a POSIX path on a POSIX platform', () => {
  assert.equal(tunnelDir('mind', { platform: 'darwin', home: '/Users/x/.p2p' }), '/Users/x/.p2p/tunnel/mind')
})

// ── (b) the DEFAULT path, in a child that really believes it is Windows ────────────────────────

test('(b) tunnelDir with DEFAULT args, in a child whose process.platform is win32', () => {
  const url = pathToFileURL(abs('src/tunnel.js')).href
  const code = [
    "Object.defineProperty(process,'platform',{value:'win32'});",
    'const m = await import(' + JSON.stringify(url) + ');',
    "process.stdout.write(m.tunnelDir('mind'));"
  ].join('\n')
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', code], {
    encoding: 'utf8',
    env: { ...process.env, USERPROFILE: 'C:\\Users\\x', P2P_HOME: '' }
  })
  assert.equal(out, 'C:\\Users\\x\\.p2p\\tunnel\\mind', 'the DEFAULT arguments do not reach the win32 branch')
})

// ── the CRLF leg: these files may be touched by a Windows editor ───────────────────────────────

test('splitLines: CRLF rows are framed exactly like LF rows', () => {
  assert.deepEqual(splitLines('a\r\nb\r\nc'), { lines: ['a', 'b'], rest: 'c' })
  assert.deepEqual(splitLines('a\r\nb\r\n'), { lines: ['a', 'b'], rest: '' })
  assert.deepEqual(splitLines('a\nb\r\nc\n'), { lines: ['a', 'b', 'c'], rest: '' }, 'mixed endings must both frame')
  // a lone \r is NOT a terminator: it may be the first half of a CRLF split across two reads
  assert.deepEqual(splitLines('a\r'), { lines: [], rest: 'a\r' })
  const { lines } = splitLines('{"v":1,"text":"hi"}\r\n')
  assert.equal(decodeMsg(lines[0]).text, 'hi', 'a CRLF-terminated row must still decode')
})

// ── (c) the prompt survives a PowerShell paste ────────────────────────────────────────────────

const PROMPT = renderPrompt({ share: 'S'.repeat(26) + '-abcd', name: 'livemind' })

test('(c) the prompt carries the Windows p2p.cmd shim, absolutely pathed', () => {
  assert.ok(PROMPT.includes('& "$env:USERPROFILE\\.local\\bin\\p2p.cmd" tunnel join'),
    'the Windows connect line is missing or not absolute — init.ps1 writes p2p.cmd into %USERPROFILE%\\.local\\bin')
})

test('(c) no backtick anywhere: it is PowerShell\'s escape character', () => {
  assert.equal(PROMPT.includes('`'), false)
})

test('(c) the only $ in the prompt is the quoted $env:USERPROFILE', () => {
  const dollars = [...PROMPT.matchAll(/\$/g)].map((m) => PROMPT.slice(m.index, m.index + '$env:USERPROFILE'.length))
  assert.ok(dollars.length > 0, 'the Windows line lost its $env:USERPROFILE')
  for (const d of dollars) assert.equal(d, '$env:USERPROFILE', 'an unguarded $ would expand in bash: ' + d)
})

test('(c) no ! (bash history expansion) and no non-ASCII byte', () => {
  assert.equal(PROMPT.includes('!'), false, 'a ! inside double quotes is history expansion in an interactive bash')
  assert.match(PROMPT, /^[\x20-\x7e\n]*$/)
})

// ── (d) source tripwire ───────────────────────────────────────────────────────────────────────

/** Source lines with comment-only lines stripped, so a comment ABOUT a footgun is not the footgun.
 *  (Same helper as test/quit-always.test.js — deliberately, so the two tripwires read alike.) */
const codeLines = (text) =>
  text.split('\n').map((l, i) => ({ n: i + 1, l })).filter(({ l }) => {
    const t = l.trim()
    return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*')
  })

// src/tunnel.js is mine; bin/p2p-tunnel.js and src/tunnel-*.js belong to the other lanes of this
// feature and are held to the same bar the moment they land.
const TUNNEL_FILES = ['src/tunnel.js', 'src/tunnel-daemon.js', 'src/tunnel-session.js', 'bin/p2p-tunnel.js']
  .filter((f) => existsSync(abs(f)))

test('(d) the tripwire actually has something to scan', () => {
  assert.ok(TUNNEL_FILES.includes('src/tunnel.js'), 'src/tunnel.js must exist for this suite to mean anything')
})

for (const f of TUNNEL_FILES) {
  const text = readFileSync(abs(f), 'utf8')
  const lines = codeLines(text)

  test(`(d) ${f}: no hardcoded /tmp (there is no /tmp on Windows)`, () => {
    const bad = lines.filter(({ l }) => /['"`]\/tmp\b/.test(l))
    assert.deepEqual(bad, [], 'use os.tmpdir() instead')
  })

  test(`(d) ${f}: no shell out (sh -c / execSync) — cmd.exe is not sh`, () => {
    const bad = lines.filter(({ l }) => /sh\s+-c|execSync\s*\(/.test(l))
    assert.deepEqual(bad, [], 'spawn the executable directly, no shell')
  })

  test(`(d) ${f}: process.platform === only inside tunnelDir`, () => {
    // tunnelDir is the ONE sanctioned platform branch; anywhere else it is a portability bug.
    const start = text.split('\n').findIndex((l) => /export function tunnelDir/.test(l))
    let end = text.split('\n').length
    if (start >= 0) {
      const all = text.split('\n')
      for (let i = start + 1; i < all.length; i++) if (all[i] === '}') { end = i + 1; break }
    }
    const bad = lines.filter(({ n, l }) => /process\.platform\s*===/.test(l) && !(start >= 0 && n > start && n <= end))
    assert.deepEqual(bad, [], 'take the platform as a parameter instead')
  })

  test(`(d) ${f}: no bare chmodSync (it is a no-op that can throw on Windows)`, () => {
    const idx = lines.map(({ l }) => l)
    const bad = lines.filter(({ l }, i) => {
      if (!/chmodSync\s*\(/.test(l)) return false
      const near = idx.slice(Math.max(0, i - 3), i + 1).join('\n')
      return !/\btry\b/.test(near)          // lib.js:730 precedent: chmod is always in a try
    })
    assert.deepEqual(bad, [], 'wrap chmodSync in try/catch')
  })
}
