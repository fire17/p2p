import { openSync, closeSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes } from 'node:crypto'

const sleeper = new Int32Array(new SharedArrayBuffer(4))
const pauseSync = ms => Atomics.wait(sleeper, 0, 0, ms)
// Windows readers and scanners can briefly deny replacement of an open file.
// Keep the old complete JSON visible; never unlink it to make rename succeed.
const transient = new Set(['EPERM', 'EBUSY', 'EACCES'])
const retryDelays = [10, 20, 40, 80, 100, 100, 100, 100, 100, 100, 100, 100]

export function atomicJson(path, value, {
  rename = renameSync, pause = pauseSync, platform = process.platform,
} = {}) {
  const body = JSON.stringify(value)
  const temporary = path + '.' + process.pid + '.' + randomBytes(12).toString('hex') + '.tmp'
  let fd, owned = false
  try {
    fd = openSync(temporary, 'wx', 0o600)
    owned = true
    writeFileSync(fd, body)
    closeSync(fd); fd = undefined
    for (let attempt = 0; ; attempt++) {
      try { rename(temporary, path); return }
      catch (error) {
        if (platform !== 'win32' || !transient.has(error.code) || attempt >= retryDelays.length) throw error
        pause(retryDelays[attempt])
      }
    }
  } finally {
    if (fd !== undefined) { try { closeSync(fd) } catch {} }
    if (owned) { try { unlinkSync(temporary) } catch {} }
  }
}
