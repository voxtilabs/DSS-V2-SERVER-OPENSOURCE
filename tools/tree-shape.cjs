const crypto = require('crypto');
const API = 'https://10.10.20.120:1443';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
async function post(p, b, t) {
  const r = await fetch(API + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(t ? { 'x-subject-token': t } : {}) }, body: JSON.stringify(b || {}) });
  return r.json().catch(() => ({}));
}
async function login(u, pw) {
  let j = await post('/brms/api/v1.0/accounts/authorize', { userName: u, ipAddress: '', clientType: 'WINPC_V2' });
  const d = j.data || {};
  if (d.token) return d.token;
  const sig = md5(md5(md5(u + ':' + (d.realm || 'DSS-V2-LAB') + ':' + md5(u + md5(pw))) + ':' + d.randomKey));
  j = await post('/brms/api/v1.0/accounts/authorize', { userName: u, ipAddress: '', clientType: 'WINPC_V2', randomKey: d.randomKey, signature: sig });
  return (j.data && j.data.token) || null;
}
function walk(node, depth, out) {
  if (!node || typeof node !== 'object' || depth > 4) return;
  for (const [k, v] of Object.entries(node)) {
    if (Array.isArray(v)) {
      if (v.length) out.push('  '.repeat(depth) + k + '[' + v.length + '] keys=' + Object.keys(v[0] || {}).slice(0, 6).join(','));
      for (const item of v) walk(item, depth + 1, out);
    }
  }
}
(async () => {
  const t = await login('admin', 'admin123');
  for (const org of ['001', 'VIGILAB']) {
    const r = await post('/brms/api/v1.1/tree/full/grade-device-tree', { scope: 'full', orgCode: org }, t);
    const out = [];
    walk(r.data, 0, out);
    console.log('--- orgCode=' + org + ' ---');
    console.log(out.slice(0, 14).join('\n'));
  }
})();
