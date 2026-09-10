#!/usr/bin/env node
// Static Pages cannot execute a route handler. Render one audited script pair
// per listener; publishing a new key is explicit and does not change DNS.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decodeKey } from '../src/key.js'

const here = dirname(fileURLToPath(import.meta.url))
const base = 'https://raw.githubusercontent.com/fire17/p2p/c26fde63ea01164bcbdb470e3c6a6f69682f748b/'
export const INSTALLERS = Object.freeze({
  sh: { url: base + 'init', sha256: '71833d1f4b1d305f8fc551151182c113ea93ca5c02b3f5dc4a0c89ad0a0826cd' },
  ps1: { url: base + 'init.ps1', sha256: 'd57e40fb2784c5780295a8cd6f10daa68c987aa7f04d720406fe1face4a077e9' },
})
export function renderJoin(key, platform, installer = INSTALLERS[platform]) {
  if (!/^0[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$/.test(key || '')) throw new Error('Expected one canonical version-0 listener key')
  decodeKey(key) // Full cryptographic typo checksum, before constructing paths/scripts.
  if (!['sh', 'ps1'].includes(platform)) throw new Error('Expected sh or ps1')
  if (!installer || !/^[a-f0-9]{64}$/.test(installer.sha256)) throw new Error('Installer SHA256 is required')
  const url = new URL(installer.url)
  if (!['http:', 'https:'].includes(url.protocol) || /['\r\n]/.test(installer.url)) throw new Error('Invalid installer URL')
  const values = { KEY: key, INSTALLER_URL: installer.url, INSTALLER_SHA256: installer.sha256,
    HELPER: readFileSync(join(here, 'join-client.mjs'), 'utf8').trimEnd() }
  return readFileSync(join(here, 'join-bootstrap.' + platform + '.in'), 'utf8')
    .replace(/@@(KEY|INSTALLER_URL|INSTALLER_SHA256|HELPER)@@/g, (_, field) => values[field])
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [outDir, ...keys] = process.argv.slice(2)
  if (!outDir || !keys.length) throw new Error('usage: node tools/render-join.mjs OUTPUT_DIRECTORY KEY [KEY ...]')
  const files = keys.flatMap(key => ['sh', 'ps1'].map(platform => [key + (platform === 'ps1' ? '.ps1' : ''), renderJoin(key, platform)]))
  mkdirSync(outDir, { recursive: true })
  for (const [filename, script] of files) writeFileSync(join(outDir, filename), script, { mode: 0o644 })
  console.log('Rendered ' + files.length + ' join scripts in ' + resolve(outDir) + '. Review and publish through the Pages repository.')
}
