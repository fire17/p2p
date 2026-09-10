// Application channel carried by the existing authenticated tunnel. Consent is
// local process state; no payload type below can create or extend a grant.
import { randomBytes } from 'node:crypto'

export const TERM_LIMITS = Object.freeze({ defaultTimeoutMs: 60000, maxTimeoutMs: 300000,
  maxOutputBytes: 1024 * 1024, maxCommandBytes: 32768, maxFrameBytes: 65536,
  maxRequests: 10000, outputChunkBytes: 4096 })
export const termId = () => randomBytes(16).toString('hex')
export const isTermId = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value)

export function makeTermRow(payload, from) {
  return { v: 1, channel: 'term', id: randomBytes(8).toString('hex'), from,
    t: new Date().toISOString(), text: JSON.stringify(payload) }
}
export function decodeTermRow(row) {
  if (!row || row.v !== 1 || row.channel !== 'term' || typeof row.from !== 'string' ||
      typeof row.text !== 'string' || Buffer.byteLength(row.text) > TERM_LIMITS.maxFrameBytes) return null
  try {
    const data = JSON.parse(row.text)
    if (!data || typeof data !== 'object' || Array.isArray(data) || data.v !== 1 || !isTermId(data.requestId)) return null
    if (!['hello', 'ready', 'exec', 'cancel', 'data', 'exit', 'refused'].includes(data.type)) return null
    return data
  } catch { return null }
}

// Read only already-inherited environment values, never credential files. This
// is best-effort redaction: unknown values, encodings and derived secrets remain
// possible output of an unrestricted shell and must not be described as safe.
export function knownSecrets(env = process.env) {
  return [...new Set(Object.entries(env).filter(([key, value]) =>
    /(?:TOKEN|PASSWORD|SECRET|API.?KEY|AUTHORIZATION|PRIVATE.?KEY)/i.test(key) && typeof value === 'string' && value.length)
    .map(([, value]) => value))].sort((a, b) => b.length - a.length)
}
export function redactKnown(text, secrets = knownSecrets()) {
  let result = String(text)
  for (const secret of secrets) result = result.split(secret).join('[REDACTED]')
  return result
}
export function createSecretRedactor(env = process.env) {
  const secrets = Array.isArray(env) ? env : knownSecrets(env)
  const longest = Math.max(1, ...secrets.map(value => value.length))
  let pending = ''
  return {
    secrets,
    contains: text => secrets.some(value => String(text).includes(value)),
    redact: text => redactKnown(text, secrets),
    write(text) {
      pending += text
      let cut = Math.max(0, pending.length - longest + 1)
      for (const secret of secrets) {
        let at = pending.indexOf(secret)
        while (at !== -1 && at < cut) {
          if (at + secret.length > cut) { cut = at; break }
          at = pending.indexOf(secret, at + 1)
        }
      }
      if (cut && /[\uD800-\uDBFF]/.test(pending[cut - 1]) && (cut === pending.length || /[\uDC00-\uDFFF]/.test(pending[cut]))) cut--
      const output = redactKnown(pending.slice(0, cut), secrets)
      pending = pending.slice(cut)
      return output
    },
    flush() { const output = redactKnown(pending, secrets); pending = ''; return output },
  }
}
