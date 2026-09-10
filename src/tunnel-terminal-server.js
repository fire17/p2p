import { spawn } from 'node:child_process'
import { basename, join, delimiter } from 'node:path'
import { StringDecoder } from 'node:string_decoder'
import { createHash } from 'node:crypto'
import { appendFileSync, readFileSync, statSync, openSync, closeSync, unlinkSync, existsSync } from 'node:fs'
import { atomicJson } from './atomic-json.js'
import { TERM_LIMITS, termId, isTermId, makeTermRow, decodeTermRow, createSecretRedactor } from './tunnel-terminal.js'

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const read = path => { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return null } }
const alive = pid => { try { process.kill(pid, 0); return true } catch { return false } }
const quote = text => "'" + text.replaceAll("'", "'\\''") + "'"
const defaultShell = env => process.platform !== 'win32' ? (env.SHELL || '/bin/sh') :
  ((env.PATH || env.Path || '').split(delimiter).some(dir => existsSync(join(dir.replace(/^"|"$/g, ''), 'pwsh.exe'))) ? 'pwsh.exe' : 'powershell.exe')

// A persistent, non-PTY shell. The marker is generated locally for each command,
// never taken from the wire. Commands execute in the same shell scope, preserving
// cwd/environment. Interactive terminal applications need a future PTY carrier.
export class PersistentTerminalShell {
  constructor({ env = process.env, shell = defaultShell(env), cwd = process.cwd() } = {}) {
    this.shell = shell
    const name = basename(shell).toLowerCase().replace(/\.exe$/, '')
    this.powerShell = ['pwsh', 'powershell'].includes(name)
    if (!this.powerShell && !['sh', 'bash', 'zsh', 'dash', 'ksh'].includes(name)) throw new Error('Supported persistent shells: pwsh, powershell, sh, bash, zsh, dash, ksh')
    const args = this.powerShell ? ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '-'] :
      name === 'bash' ? ['--noprofile', '--norc', '-s'] : name === 'zsh' ? ['-f', '-s'] : ['-s']
    this.child = spawn(shell, args, { cwd, env: { ...env, TERM: 'dumb' }, detached: process.platform !== 'win32', windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'] })
    this.ready = new Promise((resolve, reject) => { this.child.once('spawn', resolve); this.child.once('error', reject) })
    // Standalone users may call run() immediately; its normal error result still
    // applies. The owner service also waits for an interpreter marker before ready.
    void this.ready.catch(() => {})
    this.decoder = new StringDecoder('utf8')
    this.errorDecoder = new StringDecoder('utf8')
    this.pending = ''
    this.closed = false
    this.exited = false
    this.exitPromise = new Promise(resolve => { this.resolveExit = resolve })
    this.job = null
    this.child.stdout.on('data', bytes => this.consume(this.decoder.write(bytes)))
    this.child.stderr.on('data', bytes => this.output('stderr', this.errorDecoder.write(bytes)))
    this.child.on('error', error => { this.closed = true; this.exited = true; this.resolveExit(); this.finish({ code: null, signal: null, error: error.message }) })
    this.child.on('close', (code, signal) => {
      this.closed = true
      this.exited = true; this.resolveExit()
      if (this.job) {
        this.output('stdout', this.pending + this.decoder.end())
        this.output('stderr', this.errorDecoder.end())
        this.pending = ''
        this.finish({ code, signal, shellExited: true })
      }
    })
    for (const pipe of [this.child.stdin, this.child.stdout, this.child.stderr]) {
      pipe.on('error', error => { void this.abort({ error: 'shell pipe failed: ' + error.message, cancelled: true }) })
    }
    if (this.powerShell) {
      // Windows PowerShell 5.1 otherwise uses legacy code pages for native
      // command pipes. This is private to the owned shell, not a global setting.
      this.child.stdin.write('[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $OutputEncoding=[Text.UTF8Encoding]::new($false)\n')
    }
  }
  output(stream, text) {
    if (!this.job || !text) return
    try { this.job.output(stream, text) }
    catch (error) { void this.abort({ error: 'output delivery failed: ' + error.message, cancelled: true }) }
  }
  consume(text) {
    if (!this.job) return
    this.pending += text
    const marker = this.job.marker
    const at = this.pending.indexOf(marker)
    if (at !== -1) {
      const end = this.pending.indexOf('\x1f', at + marker.length)
      if (end !== -1) {
        const number = this.pending.slice(at + marker.length, end)
        if (/^-?\d{1,10}$/.test(number)) {
          this.output('stdout', this.pending.slice(0, at))
          this.pending = ''
          this.finish({ code: Number(number), signal: null })
          return
        }
      }
    }
    const keep = marker.length + 24
    if (this.pending.length > keep) {
      let cut = this.pending.length - keep
      if (/[\uD800-\uDBFF]/.test(this.pending[cut - 1]) && /[\uDC00-\uDFFF]/.test(this.pending[cut])) cut--
      this.output('stdout', this.pending.slice(0, cut))
      this.pending = this.pending.slice(cut)
    }
  }
  finish(result) {
    if (!this.job) return
    const job = this.job
    this.job = null
    clearTimeout(job.timer)
    job.resolve({ timedOut: false, truncated: false, cancelled: false, ...job.abort, ...result })
  }
  run(command, { timeoutMs = TERM_LIMITS.defaultTimeoutMs, onOutput = () => {} } = {}) {
    if (this.closed) return Promise.reject(new Error('persistent shell is closed'))
    if (this.job) return Promise.reject(new Error('persistent shell is busy'))
    this.pending = ''
    return new Promise(resolve => {
      const nonce = termId(), marker = '\x1eP2P_END_' + nonce + ':'
      this.job = { marker, resolve, output: onOutput, abort: {}, timer: null }
      this.job.timer = setTimeout(() => { void this.abort({ timedOut: true }) }, timeoutMs)
      let input
      if (this.powerShell) {
        const encoded = Buffer.from(command).toString('base64')
        input = `$global:LASTEXITCODE=0; $__p2p_ok=$true; try { Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))) *>&1; $__p2p_ok=$? } catch { Write-Output $_; $__p2p_ok=$false }; $__p2p_status=if($global:LASTEXITCODE -ne 0){$global:LASTEXITCODE}elseif($__p2p_ok){0}else{1}; [Console]::Out.Write(([char]30)+'P2P_END_${nonce}:'+([string]$__p2p_status)+([char]31)+([char]10))\n`
      } else {
        input = `eval ${quote(command)} 2>&1; __p2p_status=$?; printf '\\036P2P_END_${nonce}:%s\\037\\n' "$__p2p_status"\n`
      }
      this.child.stdin.write(input, error => { if (error) { void this.abort({ error: error.message }) } })
    })
  }
  async abort(result = { cancelled: true }) {
    if (this.job) this.job.abort = result
    const cleanup = await this.kill()
    this.finish({ code: null, signal: 'SIGKILL', ...result, ...cleanup })
  }
  async kill() {
    if (this.killPromise) return this.killPromise
    this.closed = true
    this.killPromise = (async () => {
      const pid = this.child.pid
      if (!pid) return { cleanupFailed: false }
      const exitedBeforeKill = this.exited
      let killError = null
      if (process.platform === 'win32' && !exitedBeforeKill) {
        killError = await new Promise(resolve => {
          const killer = spawn('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
          const timer = setTimeout(() => { try { killer.kill() } catch {}; resolve('taskkill timed out') }, 3000)
          killer.once('error', error => { clearTimeout(timer); resolve(error.message) })
          killer.once('exit', code => { clearTimeout(timer); resolve(code === 0 ? null : 'taskkill exited ' + code) })
        })
      } else if (process.platform !== 'win32') {
        try { process.kill(-pid, 'SIGTERM') } catch {}
        await sleep(200)
        try { process.kill(-pid, 'SIGKILL') } catch {}
      }
      if (!this.exited) await new Promise(resolve => {
        const timer = setTimeout(resolve, 3000)
        this.exitPromise.then(() => { clearTimeout(timer); resolve() })
      })
      // taskkill can report a partial tree failure even when the shell exits.
      // That is still failed cleanup. Do not target a Windows PID whose owned
      // process was already observed exiting before this attempt (PID reuse).
      const cleanupFailed = !this.exited || !!killError
      this.cleanupResult = { cleanupFailed, ...(cleanupFailed ? { cleanupError: killError || 'owned shell did not exit after termination' } : {}) }
      return this.cleanupResult
    })()
    return this.killPromise
  }
}

// The CLI is responsible for the local TTY/owner consent gate. Keeping the
// executor separate permits isolated tests without a hidden CLI bypass switch.
export async function serveTerminal({ session, allowKey, shell, cwd, env = process.env,
  io = { stdout: process.stdout, stderr: process.stderr }, signal, onReady, startupTimeoutMs = 45000 } = {}) {
  if (!Number.isInteger(startupTimeoutMs) || startupTimeoutMs < 1 || startupTimeoutMs > 45000) throw new Error('terminal startup timeout must be between 1 and 45000 ms')
  const generation = session.id, grantId = termId()
  const initial = session.requireLive()
  if (!initial.connected || initial.peerKey !== allowKey) throw new Error('terminal --allow must match the currently authenticated connected peer')
  const statePath = join(session.dir, 'term-owner.json'), stopPath = join(session.dir, 'term-stop.json')
  const lockPath = join(session.dir, 'term-owner.lock'), prior = read(statePath)
  if (existsSync(lockPath)) {
    if (prior?.pid && alive(prior.pid)) throw new Error('an owner terminal is already active')
    throw new Error('stale terminal lock; inspect the stopped owner process before removing term-owner.lock locally')
  }
  const lock = openSync(lockPath, 'wx', 0o600); closeSync(lock)
  const auditPath = join(session.dir, 'term-owner-audit.jsonl')
  const secretFilter = createSecretRedactor(env)
  const audit = event => appendFileSync(auditPath, JSON.stringify({ t: new Date().toISOString(), grantId, generation,
    ...event }) + '\n', { mode: 0o600 })
  const send = payload => session.appendOutbox(makeTermRow({ v: 1, grantId, generation, ...payload }, initial.self))
  let executor, active = null, stopped = false, reason = 'owner stopped'
  const handlers = new Set()
  const seen = new Set()
  const state = { pid: process.pid, generation, grantId, allowKey, shell, started: Date.now(), active: true, ready: false, beat: Date.now() }
  const save = () => { state.beat = Date.now(); atomicJson(statePath, state) }
  let offset = (() => { try { return statSync(session.termInbox || join(session.dir, 'inbox.jsonl')).size } catch { return 0 } })()
  const refuse = (request, why) => { send({ type: 'refused', requestId: request.requestId, reason: why }); audit({ type: 'refused', requestId: request.requestId, reason: why }) }
  const stop = async why => {
    if (stopped) return
    stopped = true; reason = why
    if (executor?.job) await executor.abort({ cancelled: true, reason: why })
    else await executor?.kill()
  }
  const abortSignal = () => { void stop('owner interrupted') }
  signal?.addEventListener('abort', abortSignal, { once: true })
  const ownerContinues = async () => {
    if (stopped) return false
    if (signal?.aborted) { await stop('owner interrupted'); return false }
    const requestStop = read(stopPath)
    if (requestStop?.grantId === grantId && requestStop.generation === generation) { await stop('owner stopped'); return false }
    let live
    try { live = session.requireLive() } catch { await stop('tunnel ended'); return false }
    if (live.id !== generation || !live.connected || live.peerKey !== allowKey) { await stop('authenticated peer disconnected or changed'); return false }
    return true
  }
  async function handle(row) {
    if (stopped || row.from !== allowKey) return
    const request = decodeTermRow(row)
    if (!request) return
    if (request.type === 'hello') {
      send({ type: 'ready', requestId: request.requestId, serverTime: Date.now(), shell: executor.shell,
        interactive: 'line', maxOutputBytes: TERM_LIMITS.maxOutputBytes })
      return
    }
    if (!['exec', 'cancel'].includes(request.type)) return
    if (request.grantId !== grantId || request.generation !== generation) { refuse(request, 'grant does not match this owner consent'); return }
    if (request.type === 'cancel') {
      if (active?.requestId === request.requestId) await stop('client cancelled command')
      return
    }
    if (seen.has(request.requestId)) { refuse(request, 'request was already handled'); return }
    if (seen.size >= TERM_LIMITS.maxRequests) { refuse(request, 'owner grant request limit reached'); await stop('request limit reached'); return }
    seen.add(request.requestId)
    if (active) { refuse(request, 'persistent shell is busy'); return }
    if (typeof request.command !== 'string' || !request.command.trim() || Buffer.byteLength(request.command) > TERM_LIMITS.maxCommandBytes) { refuse(request, 'invalid command size'); return }
    if (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > TERM_LIMITS.maxTimeoutMs ||
        !Number.isInteger(request.maxOutputBytes) || request.maxOutputBytes < 1 || request.maxOutputBytes > TERM_LIMITS.maxOutputBytes) { refuse(request, 'invalid execution limits'); return }
    if (!Number.isSafeInteger(request.expiresAt) || request.expiresAt <= Date.now() || request.expiresAt > Date.now() + TERM_LIMITS.maxTimeoutMs + 5000) { refuse(request, 'request deadline expired or invalid'); return }
    if (secretFilter.contains(request.command)) { refuse(request, 'command contains a known secret value; use the remote environment variable instead'); return }
    active = request
    const filters = { stdout: createSecretRedactor(env), stderr: createSecretRedactor(env) }
    let outputBytes = 0, truncated = false
    const emit = (stream, text) => {
      if (!text || truncated) return
      const data = Buffer.from(text)
      const remaining = request.maxOutputBytes - outputBytes
      const shown = data.subarray(0, Math.max(0, remaining))
      for (let start = 0; start < shown.length; start += TERM_LIMITS.outputChunkBytes) {
        send({ type: 'data', requestId: request.requestId, stream, data: shown.subarray(start, start + TERM_LIMITS.outputChunkBytes).toString('base64') })
      }
      outputBytes += shown.length
      if (data.length > remaining) { truncated = true; void executor.abort({ truncated: true }) }
    }
    audit({ type: 'exec', requestId: request.requestId, peer: allowKey, command: secretFilter.redact(request.command),
      commandSha256: createHash('sha256').update(request.command).digest('hex'), timeoutMs: request.timeoutMs })
    io.stdout?.write(`[terminal ${request.requestId}] ${secretFilter.redact(request.command)}\n`)
    try {
      const result = await executor.run(request.command, { timeoutMs: Math.max(1, Math.min(request.timeoutMs, request.expiresAt - Date.now())),
        onOutput: (stream, text) => emit(stream, filters[stream].write(text)) })
      if (executor.closed || result.timedOut || result.cancelled || result.truncated) Object.assign(result, await executor.kill())
      for (const stream of ['stdout', 'stderr']) emit(stream, filters[stream].flush())
      const outcome = { type: 'exit', requestId: request.requestId, code: result.code ?? null, signal: result.signal ?? null,
        timedOut: !!result.timedOut, truncated: truncated || !!result.truncated, cancelled: !!result.cancelled, outputBytes,
        cleanupFailed: !!result.cleanupFailed }
      send(outcome); audit(outcome)
      if (result.timedOut || result.cancelled || result.truncated || truncated || executor.closed) await stop('shell execution ended or was cancelled')
    } catch (error) {
      send({ type: 'refused', requestId: request.requestId, reason: 'local shell failed' })
      audit({ type: 'failure', requestId: request.requestId, reason: secretFilter.redact(error.message) })
      await stop('local shell failed')
    } finally { active = null }
  }
  try {
    executor = new PersistentTerminalShell({ shell, env, cwd })
    state.shell = executor.shell; state.shellPid = executor.child.pid; save()
    // OS spawn does not mean a cold PowerShell interpreter is ready. Complete a
    // local no-op through the real command framing before advertising the grant.
    // This separate bounded allowance never extends a remote command deadline.
    let initialized = false, startupResult, startupError
    const startup = executor.run(executor.powerShell ? '$null' : ':', { timeoutMs: startupTimeoutMs })
      .then(result => { startupResult = result; initialized = true }, error => { startupError = error; initialized = true })
    while (!initialized && await ownerContinues()) { save(); await sleep(50) }
    await startup
    if (!stopped) {
      if (startupError) throw startupError
      if (executor.closed || startupResult.code !== 0 || startupResult.timedOut || startupResult.cancelled) {
        throw new Error(startupResult.error || (startupResult.timedOut ? `selected shell did not initialize within ${startupTimeoutMs} ms` : 'selected shell exited before owner terminal became ready'))
      }
      if (await ownerContinues()) {
        state.ready = true; save()
        audit({ type: 'owner-opt-in', allowKey, shell: executor.shell })
        onReady?.({ ...state })
      }
    }
    while (await ownerContinues()) {
      if (executor.closed && !active) { await stop('persistent shell exited'); break }
      const incoming = session.readRows(session.termInbox || join(session.dir, 'inbox.jsonl'), offset)
      offset = incoming.next
      for (const row of incoming.rows) {
        if (stopped) break
        const work = handle(row)
        // The active command stays asynchronous so cancellation and local stop
        // are processed while it runs. All other handlers finish synchronously.
        handlers.add(work)
        void work.catch(() => { void stop('terminal handler failed') }).finally(() => handlers.delete(work))
      }
      save(); await sleep(50)
    }
  } catch (error) {
    if (!stopped) reason = secretFilter.redact(error.message)
    throw error
  } finally {
    await stop(reason)
    await Promise.allSettled([...handlers])
    const cleanup = await executor?.kill()
    if (cleanup?.cleanupFailed) { reason = 'cleanup failed: ' + cleanup.cleanupError; io.stderr?.write(reason + '\n') }
    state.active = false; state.ready = false; state.stopped = Date.now(); state.reason = reason; state.cleanupFailed = !!cleanup?.cleanupFailed; save()
    audit({ type: 'owner-revoked', reason })
    signal?.removeEventListener('abort', abortSignal)
    try { unlinkSync(lockPath) } catch {}
    io.stdout?.write('Agent Tunnel Terminal stopped; chat remains connected.\n')
  }
  return { grantId, generation, reason, cleanupFailed: state.cleanupFailed }
}
