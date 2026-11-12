// E-147: fetch the REAL DSS web client-module (static, unauthenticated) and
// locate the login/signature formula. READ-ONLY.
const https = require('https');
const fs = require('fs');
const path = require('path');
const HOST = process.env.DSS_REAL_HOST || '200.54.10.50';
const PORT = Number(process.env.DSS_REAL_PORT || 1443);
const OUT = path.join(__dirname, '..', '..', 'research', 'real-server', 'web');
fs.mkdirSync(OUT, { recursive: true });

function get(p) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: HOST, port: PORT, path: p, method: 'GET', rejectUnauthorized: false, timeout: 20000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    r.on('error', reject);
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.end();
  });
}

(async () => {
  const idx = await get('/web/client-module/?userId=1&locale=en&skin=black&logLevel=4&displaytimezone=0');
  console.log('index', idx.status, idx.body.length);
  const html = idx.body.toString('utf8');
  fs.writeFileSync(path.join(OUT, 'index.html'), html);
  const jsRe = /([A-Za-z0-9._\-/]+\.js)/g;
  const refs = new Set();
  let m;
  while ((m = jsRe.exec(html))) refs.add(m[1]);
  const list = [...refs];
  console.log('js refs in html:', list.length);
  const saved = [];
  for (const ref of list) {
    let p = ref.startsWith('http') ? new URL(ref).pathname : ref;
    if (!p.startsWith('/')) p = '/' + p;
    if (!p.startsWith('/web/')) p = '/web/client-module/' + p.replace(/^\/+/, '');
    try {
      const r = await get(p);
      if (r.status === 200 && r.body.length > 1000) {
        const name = p.split('/').pop();
        fs.writeFileSync(path.join(OUT, name), r.body);
        saved.push(`${name} (${r.body.length}B)`);
      } else console.log('skip', p, r.status, r.body.length);
    } catch (e) { console.log('err', p, e.message); }
  }
  console.log('saved:', saved.join(', '));
  // search saved bundles for the login formula pieces
  const pats = ['challengeKey', 'randomKey', 'signature', 'digestPassword', 'encryptType', 'md5', 'MD5'];
  for (const f of fs.readdirSync(OUT)) {
    if (!f.endsWith('.js')) continue;
    const txt = fs.readFileSync(path.join(OUT, f), 'utf8');
    for (const p of pats) {
      const i = txt.indexOf(p);
      if (i >= 0) {
        console.log(`\n== ${f} :: ${p} @${i} ==`);
        console.log(txt.slice(Math.max(0, i - 300), i + 500).replace(/\s+/g, ' '));
        break;
      }
    }
  }
})().catch((e) => console.log('FATAL', e.message));
