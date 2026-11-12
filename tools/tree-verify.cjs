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
function collect(node, devs, chans) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node.devices)) for (const d of node.devices) devs.push(d.deviceCode || d.id);
  if (Array.isArray(node.channels)) for (const c of node.channels) chans.push(c.channelId || c.id);
  for (const k of ['organizations', 'children']) if (Array.isArray(node[k])) for (const o of node[k]) collect(o, devs, chans);
  if (Array.isArray(node.devices)) for (const d of node.devices) collect(d, devs, chans);
}
(async () => {
  for (const [u, pw] of [['admin', 'admin123'], ['operador1', 'op123']]) {
    const t = await login(u, pw);
    const r = await post('/brms/api/v1.1/tree/full/grade-device-tree', { scope: 'full', orgCode: '001' }, t);
    const devs = [], chans = [];
    collect(r.data || {}, devs, chans);
    console.log(u.padEnd(10), 'devices:', devs.length, '[' + devs.join(',') + ']', 'channels:', chans.length, '[' + chans.join(',') + ']');
  }
  const r = await fetch(API + '/upgradeable/version').then((x) => x.json()).catch((e) => ({ err: String(e) }));
  console.log('GET /upgradeable/version ->', JSON.stringify(r).slice(0, 180));
})();
