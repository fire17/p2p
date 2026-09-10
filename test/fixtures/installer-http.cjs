// Loopback-only release-asset fixture. Inert when discovered by node --test.
const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const root = process.env.P2P_INSTALLER_HTTP_ROOT
const ready = process.env.P2P_INSTALLER_HTTP_READY
if (root && ready) {
  const allowed = new Set(['asset.zip', 'SHASUMS256.txt', 'bad-sums.txt', 'text-sums.txt'])
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname
    if (pathname === '/SHASUMS256.txt') {
      res.writeHead(302, { location: '/assets/SHASUMS256.txt' }); res.end(); return
    }
    const name = pathname.replace(/^\/assets\//, '')
    if (!allowed.has(name)) { res.writeHead(404); res.end(); return }
    try {
      const bytes = fs.readFileSync(path.join(root, name))
      res.writeHead(200, {
        'content-type': name === 'text-sums.txt' ? 'text/plain; charset=utf-8' : 'application/octet-stream',
        'content-length': bytes.length,
      })
      res.end(bytes)
    } catch { res.writeHead(404); res.end() }
  })
  server.listen(0, '127.0.0.1', () => {
    fs.writeFileSync(ready, JSON.stringify({ url: `http://127.0.0.1:${server.address().port}` }))
  })
}
