// E-028 lab tool: mirror the REAL production DSS web bundle served by a
// production DSS server into brms-gateway/web-module/ (gitignored, shipped in
// the Docker image only - no vendor asset is ever committed to the repo).
//
// Usage (from the repo root):
//   node poc/dss-v2-harness/brms-gateway/tools/mirror-web-module.mjs
//
// Why this exists: the DSS Client 8.006 loads /web/client-module/ in CefRender
// and renders the production Vue bundle that a real DSS server serves. Serving
// a gateway-invented page there is prohibited (operator directive, E-027/E-028).
//
// v2 (E-028) fixes the first mirror: relative import specifiers must resolve
// against the REFERENCER's directory ("js/index-*.js" importing "./en-*.js"
// lives in js/), while "css/x" / "js/x" style references are bundle-root
// relative. v1 resolved everything against the bundle root, so the lazy chunks
// were fetched from the wrong URL, came back 404 and were silently dropped ->
// the client saw 404 on js/en-*.js and js/WebVersion-*.js and the Device Config
// / Storage Plan views spun forever ("loading").
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';

const HOST = process.env.DSS_WEB_HOST || '200.54.10.50';
const PORT = Number(process.env.DSS_WEB_PORT || 1443);
const BASE = '/web/client-module/';
const OUT = path.resolve(process.cwd(), 'poc/dss-v2-harness/brms-gateway/web-module');
const MAX_FILES = 4000;

function fetchBin(urlPath) {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: HOST, port: PORT, path: urlPath, method: 'GET',
      rejectUnauthorized: false, timeout: 20000,
      headers: { accept: '*/*', 'user-agent': 'Mozilla/5.0' }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('error', () => resolve({ status: 0, body: Buffer.alloc(0) }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: Buffer.alloc(0) }); });
    req.end();
  });
}

const EXT = '(?:mjs|js|css|json|svg|png|jpe?g|gif|ico|woff2?|ttf|webp)';
function specifiers(text) {
  const out = new Set();
  const re = new RegExp(`["'(]([^"'\\s()]+\\.${EXT})(?:\\?[^"'\\s()]*)?["')]`, 'g');
  let m;
  while ((m = re.exec(text))) out.add(m[1]);
  const re2 = new RegExp(`([A-Za-z0-9_./-]+\\.${EXT})`, 'g');
  while ((m = re2.exec(text))) {
    const s = m[1];
    if (s.includes('..') || s.startsWith('/') || s.includes('://')) continue;
    out.add(s);
  }
  return [...out];
}

const BUNDLE_DIRS = ['js/', 'css/', 'images/', 'icons/', 'woff/', 'ttf/', 'assets/', 'static/'];
function resolveSpec(spec, referrerRel) {
  let s = spec;
  if (s.startsWith('data:') || s.includes('://')) return null;
  if (s.startsWith(BASE)) return s.slice(BASE.length);
  if (s.startsWith('/')) return null;
  if (s.startsWith('./')) s = s.slice(2);
  if (BUNDLE_DIRS.some((d) => s.startsWith(d))) {
    const root = path.posix.normalize(s);
    if (root.startsWith('..')) return null;
    return root.replace(/^\/+/, '');
  }
  const referrerDir = path.posix.dirname(referrerRel === '' ? '/' : referrerRel);
  const joined = path.posix.normalize(path.posix.join(referrerDir === '.' ? '' : referrerDir, s));
  if (joined.startsWith('..')) return null;
  return joined.replace(/^\/+/, '');
}

const done = new Set();
const queue = ['index.html'];
const extsToText = new Set(['.js', '.mjs', '.css', '.html', '.json']);
let totalBytes = 0;
const failed = [];

while (queue.length && done.size < MAX_FILES) {
  const rel = queue.shift();
  if (!rel || done.has(rel)) continue;
  done.add(rel);
  const file = path.join(OUT, rel);
  let body = null;
  if (fs.existsSync(file) && fs.statSync(file).size > 0) {
    body = fs.readFileSync(file); // resume mode
  } else {
    const res = await fetchBin(BASE + rel);
    if (res.status !== 200 || res.body.length === 0) {
      failed.push(`${res.status} ${rel}`);
      continue;
    }
    body = res.body;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
    totalBytes += body.length;
  }
  const ext = path.extname(rel).toLowerCase();
  if (extsToText.has(ext)) {
    const text = body.toString('utf8');
    for (const spec of specifiers(text)) {
      const r = resolveSpec(spec, rel);
      if (r && !done.has(r) && !queue.includes(r)) queue.push(r);
    }
  }
}

const files = [...done].filter((r) => fs.existsSync(path.join(OUT, r)));
console.log('mirrored files:', files.length, '| downloaded MB:', (totalBytes / 1048576).toFixed(1));
console.log('index.html present:', fs.existsSync(path.join(OUT, 'index.html')));
console.log('failed fetches:', failed.length, '(virtual Vite module keys are expected)');
for (const p of ['js/en-BWpsHIjg.js', 'js/en-BTUO-wYD.js', 'js/en-Kzu71W-O.js', 'js/WebVersion-CK50iK5l.js']) {
  console.log('probe', p, fs.existsSync(path.join(OUT, p)) ? 'OK' : 'MISSING');
}
