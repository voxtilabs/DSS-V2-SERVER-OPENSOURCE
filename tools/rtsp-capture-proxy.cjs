// E-161: transparent RTSP capture proxy for MDP.exe -> gateway relay.
// Listens on 9199 (or CAP_PORT), forwards to the gateway relay, and writes a
// readable transcript of BOTH directions: RTSP text + interleaved frame
// summaries (first bytes of each RTP payload) to CAP_LOG.
const net = require('net');
const fs = require('fs');
const path = require('path');

const LISTEN_PORT = Number(process.env.CAP_PORT || 9199);
const UP_HOST = process.env.CAP_UP_HOST || '10.10.20.120';
const UP_PORT = Number(process.env.CAP_UP_PORT || 9100);
const LOG = process.env.CAP_LOG || path.join(process.env.TEMP || '.', 'opencode', 'rtsp-capture.log');

let sink = fs.createWriteStream(LOG, { flags: 'a' });
function out(tag, s) {
  const line = `[${new Date().toISOString()}] ${tag} ${s}`;
  sink.write(line + '\n');
}

const hex = (b, n) => b.subarray(0, Math.min(n, b.length)).toString('hex').replace(/(..)/g, '$1 ').trim();

let connId = 0;
const server = net.createServer((cli) => {
  const id = ++connId;
  out('==', `#${id} client ${cli.remoteAddress}:${cli.remotePort} -> ${UP_HOST}:${UP_PORT}`);
  const up = net.connect(UP_PORT, UP_HOST);
  let c2u = Buffer.alloc(0), u2c = Buffer.alloc(0);
  let rtpFromUp = 0, rtpToCli = 0, firstUp = true, firstCli = true;

  function pump(buf, dir, tag) {
    // dir: 'u2c' (server->client) or 'c2u'
    for (;;) {
      if (buf.length < 4) return buf;
      if (buf[0] === 0x24) {
        const ch = buf[1];
        const len = buf.readUInt16BE(2);
        if (buf.length < 4 + len) return buf;
        const pay = buf.subarray(4, 4 + len);
        const rest = buf.subarray(4 + len);
        if (dir === 'u2c') {
          rtpFromUp++;
          if (firstUp || rtpFromUp % 40 === 0) {
            const rtp = pay.subarray(0, 12);
            const pt = pay.length > 1 ? (pay[1] & 0x7f) : -1;
            out(tag, `RTP#${rtpFromUp} ch=${ch} len=${len} pt=${pt} hdr=${hex(rtp, 12)} payload=${hex(pay.subarray(12), 40)}`);
            firstUp = false;
          }
        } else {
          rtpToCli++;
          if (rtpToCli <= 3) out(tag, `CLI-RTP#${rtpToCli} ch=${ch} len=${len} ${hex(pay, 24)}`);
        }
        buf = rest;
        continue;
      }
      const i = buf.indexOf('\r\n\r\n');
      if (i === -1) return buf;
      let end = i + 4;
      const head = buf.subarray(0, i).toString('latin1');
      const cl = /Content-Length:\s*(\d+)/i.exec(head);
      const bodyLen = cl ? Number(cl[1]) : 0;
      if (buf.length < end + bodyLen) return buf;
      const body = buf.subarray(end, end + bodyLen);
      out(tag, 'RTSP ' + head.replace(/\r\n/g, ' | ') + (bodyLen ? ' | body=' + hex(body, 64) : ''));
      buf = buf.subarray(end + bodyLen);
    }
  }

  cli.on('data', (d) => { c2u = Buffer.concat([c2u, d]); c2u = pump(c2u, 'c2u', `#${id} C->S`); up.write(d); });
  up.on('data', (d) => { u2c = Buffer.concat([u2c, d]); u2c = pump(u2c, 'u2c', `#${id} S->C`); cli.write(d); });
  const close = (why) => () => {
    out('==', `#${id} closed (${why}) rtpUp=${rtpFromUp} rtpCli=${rtpToCli}`);
    try { cli.destroy(); } catch {}
    try { up.destroy(); } catch {}
  };
  cli.on('close', close('client close'));
  up.on('close', close('upstream close'));
  cli.on('error', (e) => out('#', `#${id} client err ${e.message}`));
  up.on('error', (e) => out('#', `#${id} upstream err ${e.message}`));
});
server.on('error', (e) => { console.error('capture proxy error', e.message); process.exit(1); });
server.listen(LISTEN_PORT, '0.0.0.0', () => {
  console.log(`[CAP] listening ${LISTEN_PORT} -> ${UP_HOST}:${UP_PORT} log=${LOG}`);
  fs.appendFileSync(LOG, `\n=== capture proxy start ${new Date().toISOString()} ${LISTEN_PORT}->${UP_HOST}:${UP_PORT} ===\n`);
});
