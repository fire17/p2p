// test/fixtures/udp-error-survive.mjs — RUNTIME leg for SOCKERR-1 (see test/transport-socket-error.test.js).
// Run as a plain script under node AND under bun: create an endpoint, fire the dgram 'error' event
// the VPS produced (`recvmsg ENETUNREACH`, Bun 1.4.2), and prove the PROCESS IS STILL ALIVE with a
// usable endpoint afterwards. On base (no 'error' listener) this is an uncaught EventEmitter error
// and the runtime kills the process — the whole defect, in one exit code.
import { createEndpoint } from '../../src/transport.js';

const ep = await createEndpoint({});
const family = ep.sock6 ? 6 : 4;
const sock = ep.sock6 || ep.sock4;
console.error('[fixture] armed on udp' + family + ' (sock4=' + !!ep.sock4 + ' sock6=' + !!ep.sock6 + ')');
sock.emit('error', Object.assign(new Error('recvmsg ENETUNREACH'), { code: 'ENETUNREACH', syscall: 'recvmsg' }));
// Survived the throw. Only ONE family was errored, so a correct endpoint keeps the other one.
const alive = !!(ep.sock4 || ep.sock6);
console.error('[fixture] survived; sock4=' + !!ep.sock4 + ' sock6=' + !!ep.sock6 + ' port=' + ep.port);
try { ep.close(); } catch { /* ignore */ }
process.exit(alive ? 0 : 3);
