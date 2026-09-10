import { appendFileSync, openSync, closeSync, readSync, statSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import { StringDecoder } from 'node:string_decoder'
import { createInterface } from 'node:readline'
import { TERM_LIMITS, makeTermRow, decodeTermRow, knownSecrets, redactKnown } from '../src/tunnel-terminal.js'

const LIMITS = { timeoutMs: 60000, maxTimeoutMs: 300000, commandBytes: 32768, outputBytes: 1048576 }
const id = () => randomBytes(16).toString('hex')
const isId = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value)
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const failure = (message, exitCode = 2) => Object.assign(new Error(message), { exitCode })
const hash = value => createHash('sha256').update(value).digest('hex')

// An independent cursor never consumes chat. Read bounded slices and discard
// oversized rows, so an unrelated long chat line cannot exhaust client memory.
function mailbox(file) {
  let offset = 0, partial = Buffer.alloc(0), discarding = false
  try { offset = statSync(file).size } catch (error) { if (error.code !== 'ENOENT') throw error }
  return () => {
    let fd
    try { fd = openSync(file, 'r') } catch (error) { if (error.code === 'ENOENT') return []; throw error }
    const rows = []
    try {
      const bytes = Buffer.allocUnsafe(65536)
      const count = readSync(fd, bytes, 0, bytes.length, offset)
      offset += count
      let start = 0
      for (let i = 0; i <= count; i++) {
        if (i < count && bytes[i] !== 10) continue
        const segment = bytes.subarray(start, i)
        if (!discarding) {
          if (partial.length + segment.length > 524288) { partial = Buffer.alloc(0); discarding = true }
          else partial = Buffer.concat([partial, segment])
        }
        if (i < count) {
          if (!discarding && partial.length) { try { rows.push(JSON.parse(partial.toString('utf8'))) } catch {} }
          partial = Buffer.alloc(0); discarding = false
        }
        start = i + 1
      }
      return rows
    } finally { closeSync(fd) }
  }
}

function timeout(flags) {
  if (flags.timeout === undefined) return LIMITS.timeoutMs
  const value = Number(flags.timeout) * 1000
  if (!Number.isFinite(value) || value < 100 || value > LIMITS.maxTimeoutMs) throw failure('--timeout must be between 0.1 and 300 seconds')
  return Math.ceil(value)
}
function commandInput(pos, flags) {
  let command
  if (flags.file !== undefined) {
    if (pos.length) throw failure('exec accepts one command or --file PATH, not both')
    const stat = statSync(flags.file)
    if (!stat.isFile() || stat.size > LIMITS.commandBytes) throw failure('--file must be a UTF-8 command file no larger than 32 KiB')
    command = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(flags.file))
  } else {
    if (pos.length !== 1) throw failure('exec needs one quoted command or --file PATH')
    command = pos[0]
  }
  return command
}

export async function terminalClient({ verb, pos = [], flags = {}, session, io = {} }) {
  const stdout = io.stdout || process.stdout, stderr = io.stderr || process.stderr, stdin = io.stdin || process.stdin
  const emit = row => stdout.write(JSON.stringify(row) + '\n')
  const duration = timeout(flags)
  const secrets = knownSecrets(process.env)
  const validateCommand = command => {
    if (typeof command !== 'string' || !command.trim() || Buffer.byteLength(command) > LIMITS.commandBytes) throw failure('command must contain 1 to 32768 UTF-8 bytes')
    if ([...secrets].some(secret => secret && command.includes(secret))) throw failure('Command contains a local secret value. Reference an environment variable on the remote machine instead.')
  }
  let firstCommand
  if (verb === 'exec') { firstCommand = commandInput(pos, flags); validateCommand(firstCommand) }
  else if (verb !== 'shell' || pos.length || flags.file !== undefined) throw failure('shell accepts no command or --file; use exec for a single command')
  if (!session.peerKey) throw failure('terminal needs a connected authenticated peer', 5)
  const localGeneration = session.id
  const ensureLive = () => {
    const state = session.requireLive()
    if (session.id !== localGeneration || (state?.id && state.id !== localGeneration) || state?.connected === false ||
        (state?.peerKey && state.peerKey !== session.peerKey)) throw failure('terminal tunnel generation or authenticated peer changed', 5)
  }
  ensureLive()
  const read = mailbox(session.termInbox || join(session.dir, 'inbox.jsonl'))
  const auditFile = session.termAudit || join(session.dir, 'term-client-audit.jsonl')
  const audit = data => appendFileSync(auditFile, JSON.stringify({ t: new Date().toISOString(), peerKey: session.peerKey, session: session.id, ...data }) + '\n', { mode: 0o600 })
  const send = payload => {
    const row = makeTermRow(payload, session.self)
    if (Buffer.byteLength(row.text) > TERM_LIMITS.maxFrameBytes) throw failure('encoded terminal request exceeds the 64 KiB protocol limit')
    session.appendOutbox(row)
  }
  let waiting = [], active = null, interrupted = false, lines = null, cancellationSent = false, lastRequestId = null
  const seen = new Set()
  const receive = async deadline => {
    while (Date.now() < deadline) {
      if (interrupted) throw failure('terminal request interrupted', 130)
      ensureLive()
      if (!waiting.length) waiting = read()
      while (waiting.length) {
        const row = waiting.shift()
        if (row.from !== session.peerKey || row.channel !== 'term') continue
        if (typeof row.id !== 'string' || seen.has(row.id)) continue
        seen.add(row.id)
        if (seen.size > 65536) throw failure('terminal event limit exceeded', 75)
        const payload = decodeTermRow(row)
        if (payload && payload.v === 1 && isId(payload.requestId)) return payload
      }
      await sleep(20)
    }
    throw failure('terminal response timed out', 124)
  }
  const cancel = reason => {
    if (!active || cancellationSent) return
    cancellationSent = true
    try { send({ v: 1, type: 'cancel', ...active, reason }) } catch {}
    audit({ type: 'cancel', requestId: active.requestId, reason })
  }
  const onInterrupt = () => { interrupted = true; cancel('client-interrupt'); lines?.close() }
  process.on('SIGINT', onInterrupt)
  try {
    const helloId = id(), helloDeadline = Date.now() + Math.min(duration, 10000)
    send({ v: 1, type: 'hello', requestId: helloId })
    let ready
    while (!ready) {
      const event = await receive(helloDeadline)
      if (event.requestId !== helloId) continue
      if (event.type === 'refused') throw failure('Remote owner has not enabled this terminal or refused access.', 77)
      if (event.type !== 'ready' || !isId(event.grantId) || !isId(event.generation) ||
          !Number.isSafeInteger(event.serverTime) || typeof event.shell !== 'string' || event.interactive !== 'line' ||
          !Number.isInteger(event.maxOutputBytes) || event.maxOutputBytes < 1 || event.maxOutputBytes > LIMITS.outputBytes) continue
      ready = { ...event, receivedAt: Date.now() }
    }
    audit({ type: 'ready', grantId: ready.grantId, generation: ready.generation })
    const execute = async (command, interactive) => {
      validateCommand(command)
      const requestId = id(), deadline = Date.now() + duration
      lastRequestId = requestId
      const maxOutputBytes = Math.min(ready.maxOutputBytes, LIMITS.outputBytes)
      const binding = { requestId, grantId: ready.grantId, generation: ready.generation }
      active = binding; cancellationSent = false
      audit({ type: 'exec', ...binding, commandHash: hash(command), commandBytes: Buffer.byteLength(command), timeoutMs: duration })
      send({ v: 1, type: 'exec', ...binding, command, timeoutMs: duration, maxOutputBytes,
        expiresAt: ready.serverTime + (Date.now() - ready.receivedAt) + duration })
      const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') }
      let outputBytes = 0
      const display = (stream, text) => {
        if (!text) return
        if (interactive) (stream === 'stderr' ? stderr : stdout).write(text)
        else emit({ type: 'data', requestId, stream, text })
      }
      try {
        while (true) {
          const event = await receive(deadline)
          if (event.requestId !== requestId || event.grantId !== ready.grantId || event.generation !== ready.generation) continue
          if (event.type === 'data') {
            if (!['stdout', 'stderr'].includes(event.stream) || typeof event.data !== 'string' || event.data.length > 65536 ||
                event.data.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(event.data)) continue
            const bytes = Buffer.from(event.data, 'base64')
            if (bytes.toString('base64') !== event.data) continue
            if (outputBytes + bytes.length > maxOutputBytes) {
              cancel('output-limit')
              throw failure('remote terminal exceeded the agreed output limit', 75)
            }
            outputBytes += bytes.length
            display(event.stream, decoders[event.stream].write(bytes))
          } else if (event.type === 'refused') {
            audit({ type: 'refused', requestId })
            throw failure('Remote terminal refused this request; local owner consent may have ended.', 77)
          } else if (event.type === 'exit') {
            if (!(event.code === null || Number.isInteger(event.code)) || typeof event.timedOut !== 'boolean' || typeof event.truncated !== 'boolean' ||
                (event.cancelled !== undefined && typeof event.cancelled !== 'boolean') || (event.cleanupFailed !== undefined && typeof event.cleanupFailed !== 'boolean')) continue
            for (const stream of ['stdout', 'stderr']) display(stream, decoders[stream].end())
            const result = { type: 'exit', requestId, code: event.code, signal: typeof event.signal === 'string' ? event.signal : null,
              timedOut: event.timedOut, truncated: event.truncated, cancelled: !!event.cancelled, cleanupFailed: !!event.cleanupFailed,
              ...(typeof event.cleanupError === 'string' ? { cleanupError: redactKnown(event.cleanupError, secrets) } : {}), outputBytes }
            audit(result)
            if (interactive) stderr.write(`\n[exit ${event.code}${event.timedOut ? ', timed out' : ''}${event.truncated ? ', output truncated' : ''}]\n`)
            else emit(result)
            return event.timedOut ? 124 : event.cancelled ? 130 : event.truncated || event.cleanupFailed ? 75 : event.code === 0 ? 0 : Number.isInteger(event.code) && event.code > 0 && event.code <= 255 ? event.code : 1
          }
        }
      } catch (error) {
        cancel(error.exitCode === 124 ? 'client-timeout' : 'client-error')
        audit({ type: 'failed', requestId, code: error.exitCode || 2 })
        throw error
      } finally { active = null }
    }
    if (verb === 'exec') return await execute(firstCommand, false)
    stderr.write(`Connected to ${ready.shell}. Line-oriented shell; .exit disconnects this client.\n`)
    lines = createInterface({ input: stdin, crlfDelay: Infinity, terminal: false })
    let lastCode = 0
    try {
      for await (const line of lines) {
        if (line === '.exit') break
        if (!line.trim()) continue
        lastCode = await execute(line, true)
        if (lastCode === 124) break
      }
      return interrupted ? 130 : lastCode
    } finally { lines.close() }
  } catch (error) {
    const code = error.exitCode || 2
    emit({ type: 'error', requestId: lastRequestId, code, message: redactKnown(error.message, secrets) })
    return code
  } finally { process.removeListener('SIGINT', onInterrupt) }
}
