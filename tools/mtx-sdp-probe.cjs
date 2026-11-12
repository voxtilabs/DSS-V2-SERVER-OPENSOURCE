// Dump the MediaMTX SDP for a path so we can compare the real codec params
// (H.265 profile/level/resolution hints) with the DHAV TLV we synthesize.
const net = require('net');
const path = process.argv[2] || 'cam_D0238JDG3016';
const host = process.env.MTX_HOST || 'mediamtx';
const port = Number(process.env.MTX_PORT || 8554);

function msg(method, url, cseq, extra = '') {
  return `${method} ${url} RTSP/1.0\r\nCSeq: ${cseq}\r\nUser-Agent: dss-probe\r\n${extra}\r\n`;
}
const c = net.connect(port, host, () => c.write(msg('DESCRIBE', `rtsp://${host}:${port}/${path}`, 1, 'Accept: application/sdp\r\n')));
let buf = Buffer.alloc(0);
c.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  const s = buf.toString('latin1');
  const i = s.indexOf('\r\n\r\n');
  if (i === -1) return;
  const m = /Content-Length:\s*(\d+)/i.exec(s.slice(0, i));
  const n = m ? Number(m[1]) : 0;
  if (buf.length < i + 4 + n) return;
  console.log('--- SDP ---');
  console.log(s.slice(i + 4, i + 4 + n));
  c.destroy(); process.exit(0);
});
c.on('error', (e) => { console.log('ERR', e.message); process.exit(1); });
setTimeout(() => { console.log('TIMEOUT'); process.exit(2); }, 5000);
