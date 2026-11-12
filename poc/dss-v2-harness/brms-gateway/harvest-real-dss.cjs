// E-145: READ-ONLY harvest of the real DSS Pro server contract surface.
// Credentials come ONLY from env vars (never written to disk/commits).
// Usage: DSS_REAL_HOST=200.54.10.50 DSS_REAL_PORT=1443 DSS_REAL_USER=... DSS_REAL_PASS=... node harvest-real-dss.cjs
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HOST = process.env.DSS_REAL_HOST || '200.54.10.50';
const PORT = Number(process.env.DSS_REAL_PORT || 1443);
const USER = process.env.DSS_REAL_USER;
const PASS = process.env.DSS_REAL_PASS;
if (!USER || !PASS) { console.error('missing DSS_REAL_USER / DSS_REAL_PASS env'); process.exit(2); }

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });
const OUT = path.join(__dirname, '..', '..', 'research', 'real-server');
fs.mkdirSync(OUT, { recursive: true });

const SENSITIVE = /^(token|randomKey|secretKey|secretVector|credential|password|passWord|session|sessionId|challengeKey|signature)$/i;
function sanitize(obj) {
  if (Array.isArray(obj)) return obj.map(sanitize);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = SENSITIVE.test(k) ? '<redacted>' : sanitize(v);
    return out;
  }
  return obj;
}

function req(method, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = https.request({ host: HOST, port: PORT, path: p, method, agent, rejectUnauthorized: false, headers: { 'Content-Type': 'application/json', ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}), ...headers } }, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  const log = [];
  const save = (name, txt) => {
    fs.writeFileSync(path.join(OUT, name), txt);
    log.push(`${name} (${txt.length}B)`);
  };

  // 1) challenge
  const ch = await req('POST', '/brms/api/v1.0/accounts/authorize', { userName: USER, clientType: 'WINPC_V2', ipAddress: '' });
  console.log('challenge:', ch.status, ch.body.slice(0, 300));
  save('00-challenge.json', sanitize(JSON.parse(ch.body || '{}')) instanceof Object ? JSON.stringify(sanitize(JSON.parse(ch.body || '{}')), null, 1) : ch.body);
  const cd = JSON.parse(ch.body || '{}');
  const info = cd.data || cd;
  const realm = info.realm || '';
  const randomKey = info.randomKey || '';
  if (!realm || !randomKey) { console.log('no realm/randomKey — dumping raw and stopping'); process.exit(1); }

  // 2) signature — EXACT formula derived empirically from three live client
  // captures against our gateway (E-147): the client hashes the digest twice.
  //   temp = md5(user + md5(pass))
  //   inner = md5(`${user}:${realm}:${temp}`)
  //   sig = md5(md5(inner + ':' + randomKey))
  const temp = md5(USER + md5(PASS));
  const inner = md5(`${USER}:${realm}:${temp}`);
  const sig = md5(md5(inner + ':' + randomKey));
  // Body shape must match the real client byte-for-byte (captured live):
  // {userName, ipAddress:"", clientType:"WINPC_V2", randomKey, signature}
  const auth = await req('POST', '/brms/api/v1.0/accounts/authorize', { userName: USER, ipAddress: '', clientType: 'WINPC_V2', randomKey, signature: sig });
  console.log('authorize:', auth.status, auth.body.slice(0, 400));
  const authJson = JSON.parse(auth.body || '{}');
  save('01-authorize.json', JSON.stringify(sanitize(authJson), null, 1));
  const token = (authJson.data || {}).token;
  if (!token) { console.log('NO TOKEN — stopping (see 01-authorize.json)'); process.exit(1); }
  const H = { 'X-Subject-Token': token };

  // 3) read-only endpoint sweep (v1.0 / v1.1 contracts we must match)
  const eps = [
    ['GET', '/brms/api/v1.0/accounts/current'],
    ['POST', '/brms/api/v1.0/tree/orgs', {}],
    ['POST', '/brms/api/v1.0/tree/devices', {}],
    ['POST', '/brms/api/v1.0/tree/channels', {}],
    ['POST', '/brms/api/v1.0/tree/deviceOrg', {}],
    ['GET', '/brms/api/v1.0/tree/gdt'],
    ['GET', '/brms/api/v1.1/tree/full/grade-device-tree?sourceType=&protocolType=&orgCode=&addType=&domain=&roleId=1'],
    ['GET', '/brms/api/v1.0/device/page?page=1&pageSize=100'],
    ['GET', '/brms/api/v1.1/device/page?page=1&pageSize=100'],
    ['GET', '/omms/api/v1.1/device/page?page=1&pageSize=100'],
    ['GET', '/brms/api/v1.1/device/statistics/count-by-device-category/list'],
    ['GET', '/brms/api/v1.1/monitor/view/view-tree'],
    ['GET', '/brms/api/v1.1/menu/available/list'],
    ['GET', '/brms/api/v1.1/config/function'],
    ['GET', '/brms/api/v1.1/account/user/level'],
  ];
  let i = 2;
  for (const [method, p, body] of eps) {
    const r = await req(method, p, body, H);
    let pretty;
    try { pretty = JSON.stringify(sanitize(JSON.parse(r.body)), null, 1); } catch { pretty = r.body; }
    const name = `${String(i).padStart(2, '0')}-${p.replace(/[^a-z0-9]+/gi, '_').slice(0, 60)}.json`;
    save(name, pretty || '');
    console.log('sweep', method, p, '->', r.status, (pretty || '').length + 'B');
    i++;
  }

  fs.writeFileSync(path.join(OUT, 'README.md'), `# Real DSS Pro server (read-only harvest)\n\nHost: <production host>\nCaptured contract payloads from the official DSS Pro server so the open-source gateway can match its shapes 1:1.\nAll credentials and tokens are redacted. Read-only: only authorize + GET/read POSTs were issued.\n\nFiles:\n${log.map((l) => '- ' + l).join('\n')}\n`);
  console.log('done ->', OUT);
})().catch((e) => { console.error('FATAL', e.message); process.exit(3); });
