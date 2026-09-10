import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { PersistentTerminalShell } from '../src/tunnel-terminal-server.js'

test('terminal cleanup: a failed Windows tree-kill remains a failure after the owned shell exits', () => {
  // Fault injection in an isolated child: no real PID is ever targeted. The
  // Windows utility receives an invalid PID, or is absent on a POSIX runner.
  // In both cases the fake owned handle reports exit after termination begins.
  const moduleUrl = new URL('../src/tunnel-terminal-server.js', import.meta.url).href
  const script = `
    const { PersistentTerminalShell } = await import(${JSON.stringify(moduleUrl)});
    Object.defineProperty(process, 'platform', {value:'win32'});
    let exited;
    const target = { child:{pid:'not-a-valid-pid'}, exited:false, exitPromise:new Promise(resolve=>{exited=resolve}) };
    const attempt = PersistentTerminalShell.prototype.kill.call(target);
    setTimeout(()=>{target.exited=true;exited()},5);
    const failed = await attempt;
    const alreadyExited = await PersistentTerminalShell.prototype.kill.call({child:{pid:'not-a-valid-pid'},exited:true,exitPromise:Promise.resolve()});
    console.log(JSON.stringify({failed,alreadyExited}));
  `
  const result = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 10000 }))
  assert.equal(result.failed.cleanupFailed, true)
  assert.match(result.failed.cleanupError, /taskkill|ENOENT|spawn/)
  assert.equal(result.alreadyExited.cleanupFailed, false)
})

test('terminal output write failure revokes its owned shell instead of escaping a stream callback', { timeout: 15000 }, async () => {
  const shell = new PersistentTerminalShell({ shell: process.platform === 'win32' ? 'pwsh' : '/bin/sh' })
  try {
    await shell.ready
    const command = process.platform === 'win32'
      ? "[Console]::Out.Write(('x'*4096)); Start-Sleep -Seconds 30"
      : "printf '%4096s' x; sleep 30"
    const result = await shell.run(command, { timeoutMs: 5000,
      onOutput: () => { throw Object.assign(new Error('synthetic outbox EACCES'), { code: 'EACCES' }) } })
    const cleanup = await shell.kill()
    assert.equal(shell.exited, true)
    assert.equal(result.cancelled, true)
    assert.match(result.error, /output delivery failed.*EACCES/)
    assert.equal(cleanup.cleanupFailed, false)
  } finally { await shell.kill() }
})
