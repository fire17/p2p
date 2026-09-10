// Real portable-runtime archive and binary manifests, served only on loopback.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = process.env.P2P_BUN_HTTP_ROOT;
const ready = process.env.P2P_BUN_HTTP_READY;
const archiveName = process.env.P2P_BUN_HTTP_ARCHIVE;
if (root && ready && archiveName) {
  const server = http.createServer((req, res) => {
    const match = /^\/(good|bad)\/(SHASUMS256\.txt|[^/]+\.zip)$/.exec(req.url);
    if (!match || !['SHASUMS256.txt', archiveName].includes(match[2])) { res.writeHead(404); res.end(); return; }
    const name = match[2] === 'SHASUMS256.txt' && match[1] === 'bad' ? 'bad-sums.txt' : match[2];
    const file = path.join(root, name);
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': fs.statSync(file).size });
    fs.createReadStream(file).pipe(res);
  });
  server.listen(0, '127.0.0.1', () => {
    fs.writeFileSync(ready, JSON.stringify({ url: `http://127.0.0.1:${server.address().port}` }));
  });
}
