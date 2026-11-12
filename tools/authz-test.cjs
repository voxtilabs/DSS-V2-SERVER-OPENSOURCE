#!/usr/bin/env node
// E-180 verification: role limited to ONE camera + restricted user.
const crypto = require('crypto');
const API = process.env.API || 'https://10.10.20.120:1443';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const ALLOWED = process.env.ALLOWED_CH || 'D0238JDG3016$1$0$0';
const OTHER = process.env.OTHER_CH || 'ARS-PRUEBANVR120261211$1$0$0';

async function post(path, body, token) {
  const r = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { 'x-subject-token': token } : {}) },
    body: JSON.stringify(body || {})
  });
  return r.json().catch(() => ({}));
}
async function get(path, token) {
  const r = await fetch(API + path, { headers: token ? { 'x-subject-token': token } : {} });
  return r.json().catch(() => ({}));
}

async function login(user, pass) {
  let j = await post('/brms/api/v1.0/accounts/authorize', { userName: user, ipAddress: '', clientType: 'WINPC_V2' });
  const d = (j && j.data) || {};
  if (d.token) return d.token;
  const realm = d.realm || 'DSS-V2-LAB';
  const randomKey = d.randomKey;
  const sig = md5(md5(md5(user + ':' + realm + ':' + md5(user + md5(pass))) + ':' + randomKey));
  j = await post('/brms/api/v1.0/accounts/authorize', { userName: user, ipAddress: '', clientType: 'WINPC_V2', randomKey, signature: sig });
  if (j && j.data && j.data.token) return j.data.token;
  j = await post('/brms/api/v1.0/accounts/authorize', { userName: user, ipAddress: '', clientType: 'WINPC_V2', randomKey, signature: 'x', password: pass });
  return (j && j.data && j.data.token) || null;
}

(async () => {
  const adminTok = await login('admin', 'admin123');
  console.log('admin token:', adminTok ? 'ok' : 'FAILED');

  const role = await post('/brms/api/v1.1/role', {
    roleName: 'Cam1 Only', roleCode: 'cam1only', roleType: '2', orgCode: 'VIGILAB',
    channelIds: [ALLOWED], deviceCodes: ['D0238JDG3016'],
    functionCodes: ['8', '9', '13', '17']
  }, adminTok);
  const roleId = (role.data && (role.data.roleId || role.data.id)) || '3';
  console.log('role created:', roleId, JSON.stringify(role.data && role.data.channelIds));

  const user = await post('/brms/api/v1.1/user', {
    username: 'operador1', name: 'Operador 1', password: 'op123',
    roleIds: [roleId], orgCode: 'VIGILAB', status: '1', userType: '0'
  }, adminTok);
  console.log('user created:', JSON.stringify(user.data && user.data.username));

  const uTok = await login('operador1', 'op123');
  console.log('operador1 token:', uTok ? 'ok' : 'FAILED');
  if (!uTok) return;

  const page = await get('/brms/api/v1.1/device/page?page=1&pageSize=50&orgCode=001', uTok);
  const rows = (page.data && (page.data.pageData || page.data.list)) || [];
  console.log('device/page for operador1:', rows.length, rows.map((r) => r.deviceCode).join(','));

  const a = await get('/brms/api/v1.1/account/function/channel/check?channelCode=' + encodeURIComponent(ALLOWED), uTok);
  const b = await get('/brms/api/v1.1/account/function/channel/check?channelCode=' + encodeURIComponent(OTHER), uTok);
  const pick = (j) => {
    const d = (j && j.data) || {};
    return { checkResult: d.checkResult, hasRight: d.hasRight, codes: (d.functionCodes || []).length };
  };
  console.log('check ALLOWED:', JSON.stringify(pick(a)));
  console.log('check OTHER  :', JSON.stringify(pick(b)));

  const apage = await get('/brms/api/v1.1/device/page?page=1&pageSize=50&orgCode=001', adminTok);
  const arows = (apage.data && (apage.data.pageData || apage.data.list)) || [];
  console.log('device/page for admin:', arows.length, arows.map((r) => r.deviceCode).join(','));

  const tree = await post('/brms/api/v1.1/tree/full/grade-device-tree', { scope: 'full' }, uTok);
  const td = (tree.data && (tree.data.devices || (tree.data.data && tree.data.data.devices))) || [];
  const tc = (tree.data && (tree.data.channels || (tree.data.data && tree.data.data.channels))) || [];
  console.log('grade-tree for operador1: devices', td.length, td.map((d) => d.deviceCode || d.id).join(','),
    '| channels', tc.length, tc.map((c) => c.channelId || c.id).join(','));
})();
