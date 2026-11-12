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
(async () => {
  for (const [u, pw] of [['admin', 'admin123'], ['operador1', 'op123']]) {
    const t = await login(u, pw);
    const r = await post('/brms/api/v1.1/tree/full/grade-device-tree', { scope: 'full', orgCode: 'VIGILAB' }, t);
    const d = r.data || {};
    const inner = d.data && typeof d.data === 'object' ? d.data : {};
    const get = (k) => (Array.isArray(d[k]) ? d[k] : Array.isArray(inner[k]) ? inner[k] : []);
    console.log(u, 'keys:', Object.keys(d).slice(0, 12).join(','));
    console.log('  devices:', get('devices').length, 'channels:', get('channels').length, 'orgs:', get('organizations').length,
      '| dev codes:', get('devices').map((x) => x.deviceCode || x.id).join(','));
    console.log('  channels:', get('channels').map((x) => x.channelId || x.id).join(','));
  }
})();
