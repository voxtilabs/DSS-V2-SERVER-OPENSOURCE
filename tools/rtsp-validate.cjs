// E-168: independent RTSP client that mimics MDP (no DESCRIBE, TCP interleaved
// 0-1, SETUP on the Dahua URL then PLAY on the same URL) and validates the
// H.265 Annex-B output of our relay: AU boundaries, NAL types, param sets.
//
// usage: node rtsp-validate.cjs            (defaults to the lab channel)
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const API = process.env.API || 'http://127.0.0.1:11443';
const CHANNEL = process.env.CHANNEL || 'D0238JDG3016$1$0$0';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

async function login() {
  const j1 = await fetch(API + '/brms/api/v1.0/accounts/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userName: 'admin', ipAddress: '', clientType: 'WINPC_V2' })
  }).then((r) => r.json());
  const { realm, randomKey } = j1.data;
  const sig = md5(md5(md5('admin:' + realm + ':' + md5('admin' + md5('admin123'))) + ':' + randomKey));
  const j2 = await fetch(API + '/brms/api/v1.0/accounts/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userName: 'admin', ipAddress: '', clientType: 'WINPC_V2', randomKey, signature: sig })
  }).then((r) => r.json());
  return j2.data.token;
}

function nalTypes(annex) {
  const out = [];
  let i = 0;
  while (i + 4 < annex.length) {
    if (annex[i] === 0 && annex[i + 1] === 0 && annex[i + 2] === 1) {
      const b0 = annex[i + 3];
      out.push({ type: (b0 >> 1) & 0x3f, len: annex.length - i });
      i += 3;
    } else i++;
  }
  return out.map((n) => n.type);
}

(async () => {
  const token = await login();
  const sv = await fetch(API + '/admin/API/MTS/Video/StartVideo', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
    body: JSON.stringify({ project: 'PSDK', method: 'MTS.Video.StartVideo', data: { channelId: CHANNEL, streamType: '1', dataType: '2' } })
  }).then((r) => r.json());
  const url = sv.data && sv.data.url;
  if (!url) { console.log('no url', JSON.stringify(sv)); process.exit(1); }
  console.log('url:', url);
  const u = new URL(url);
  const c = net.connect(Number(u.port), u.hostname);
  c.on('error', (e) => console.log('SOCKET ERR', e.message));
  c.on('close', () => console.log('socket closed'));
  let buf = Buffer.alloc(0);
  let state = 'options';
  let aus = 0, frames = [];
  let au = [];
  const t0 = Date.now();

  function send(m) { c.write(m); }

  c.on('connect', () => {
    send(`OPTIONS ${url} RTSP/1.0\r\nCSeq: 1\r\n\r\n`);
    send(`SETUP ${url} RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;interleaved=0-1;playmode=playback\r\n\r\n`);
  });

  c.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 4) return;
      if (buf[0] === 0x24) {
        const len = buf.readUInt16BE(2);
        if (buf.length < 4 + len) return;
        const pay = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        if (pay.length < 12) continue;
        const marker = (pay[1] & 0x80) !== 0;
        const pt = pay[1] & 0x7f;
        const body = pay.subarray(12);
        // relay output is Annex-B AU inside the RTP payload
        if (body[0] === 0x44 && body[1] === 0x48) {
          // DHAV container (RELAY_DHAV=1): skip header 24+extraLen
          const extraLen = body[22];
          const recLen = body.readUInt32LE(12);
          au.push(body.subarray(24 + extraLen, Math.min(body.length, Math.max(24 + extraLen, recLen - 8))));
        } else {
          au.push(body);
        }
        if (marker) {
          const annex = Buffer.concat(au);
          au = [];
          aus++;
          if (frames.length < 6) frames.push({ n: aus, pt, bytes: annex.length, nals: nalTypes(annex) });
        }
        continue;
      }
      const i = buf.indexOf('\r\n\r\n');
      if (i === -1) return;
      const head = buf.subarray(0, i).toString('latin1');
      buf = buf.subarray(i + 4);
      console.log('[RTSP] ' + head.split('\r\n').slice(0, 3).join(' | '));
      if (state === 'options' && /^RTSP\/1\.0 200/.test(head)) { state = 'setup'; }
      else if (state === 'setup' && /^RTSP\/1\.0 200/.test(head)) {
        state = 'playing';
        send(`PLAY ${url} RTSP/1.0\r\nCSeq: 3\r\nRange: npt=0.000-\r\n\r\n`);
      } else if (/^RTSP\/1\.0 [45]\d\d/.test(head)) {
        console.log('ERROR response:\n' + head);
      }
    }
  });

  setTimeout(() => {
    const secs = (Date.now() - t0) / 1000;
    console.log(`AUs=${aus} in ${secs.toFixed(1)}s (${(aus / secs).toFixed(1)} fps)`);
    for (const f of frames) console.log(`  AU#${f.n} pt=${f.pt} ${f.bytes}B nals=[${f.nals.join(',')}]`);
    const hasParam = frames.some((f) => f.nals.includes(32) || f.nals.includes(33) || f.nals.includes(34));
    const hasI = frames.some((f) => f.nals.includes(19) || f.nals.includes(20));
    console.log(`param-sets in first AUs: ${hasParam} | IDR in first AUs: ${hasI}`);
    c.destroy();
    process.exit(0);
  }, 5000);
})().catch((e) => { console.log('FATAL', e.message); process.exit(1); });
