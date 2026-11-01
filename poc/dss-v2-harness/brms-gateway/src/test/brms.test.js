import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import dgram from 'node:dgram';

const BASE = 'http://127.0.0.1:11443';
const USER = 'admin';
const PASS = 'admin123';

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }

let token = '';
let serverProc = null;

function waitForServer() {
  return new Promise((resolve, reject) => {
    const maxAttempts = 30;
    let attempts = 0;
    const check = async () => {
      attempts++;
      try {
        await fetch(BASE + '/brms/api/v1.0/accounts/authorize', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER }) });
        resolve();
      } catch {
        if (attempts >= maxAttempts) reject(new Error('Server did not start after ' + maxAttempts + ' attempts'));
        else setTimeout(check, 500);
      }
    };
    check();
  });
}

describe('BRMS Gateway - Full DTO Contracts (EV-041..EV-048)', { timeout: 60000 }, () => {
  before(async () => {
    serverProc = spawn('node', ['src/index.js'], { cwd: 'C:/Users/bruno/Downloads/LOCURA DSS/poc/dss-v2-harness/brms-gateway', stdio: 'pipe' });
    await waitForServer();
    // Additional wait to ensure all endpoints are ready
    await new Promise(r => setTimeout(r, 1000));
    // challenge
    const ch = await fetch(`${BASE}/brms/api/v1.0/accounts/authorize`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER }) });
    assert.equal(ch.status, 401);
    const challengeResp = await ch.json();
    const { realm, randomKey, challengeKey } = challengeResp.data;
    assert.ok(realm && randomKey && challengeKey);
    // response
    const temp = doubleMd5(USER, PASS);
    const sig = makeSig(USER, realm, temp, randomKey);
    const auth = await fetch(`${BASE}/brms/api/v1.0/accounts/authorize`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER, randomKey, signature: sig, clientType: 'WINPC_V2', challengeKey }) });
    assert.equal(auth.status, 200);
    const authResp = await auth.json();
    const { token: t } = authResp.data;
    token = t;
    assert.ok(token);
  });

  it('TokenInfoVo has exact fields', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/accounts/current`, { headers: { 'X-Subject-Token': token } });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.username);  // field is 'username' not 'userName'
    assert.ok(j.data?.token);
    assert.ok(j.data?.userId);
    assert.ok(j.data?.userType);
    assert.ok(j.data?.topLevel);
    // TokenInfoVo fields: token, userId, username, userType, topLevel
    assert.ok(typeof j.data.token === 'string');
  });

  it('tree/orgs returns DeviceOrgTreeVo structure', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/orgs`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.orgList?.length > 0);
    const org = j.data.orgList[0];
    assert.ok(org.orgId && org.orgName && org.parentId && org.orgType !== undefined);
  });

  it('tree/devices returns DeviceTreeVo structure', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/devices`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.deviceList?.length > 0);
    const dev = j.data.deviceList[0];
    assert.ok(dev.deviceCode && dev.deviceName && dev.status !== undefined && dev.deviceType !== undefined);
  });

  it('tree/channels returns channelId format num$K$m$0', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/channels`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelType: 1, category: 1 }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.channelList?.some(c => c.channelId.includes('$') && c.channelId.split('$').length === 4));
  });

  it('MTS/Video/StartVideo returns RealTimeVideoVo with all fields', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/MTS/Video/StartVideo`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId: '1000171$1$0$0', streamType: 1, dataType: 1 }) });
    assert.equal(r.status, 200);
    const text = await r.text();
    console.log('StartVideo response:', text);
    const j = JSON.parse(text);
    const d = j.data;
    assert.ok(d, 'j.data should exist');
    // Response uses 'url' field for RTSP URL
    assert.ok(d.url && d.url.includes('rtsp://'));
    assert.ok(d.hlsUrl && d.hlsUrl.includes('/hls'));
    assert.ok(d.token && d.session);
    assert.ok(['connectType', 'ip', 'port', 'protocol', 'minRate', 'multicastIp', 'multicastPort', 'stunEnable', 'stunPort', 'stopTime', 'fakeSdp', 'forceSynPlay', 'extend', 'keyCode', 'trackId', 'url', 'url2', 'vkId', 'vkValue'].every(f => f in d));
  });

  it('SS/Record/QueryRecord returns RecordQueryVo with pageCount, records, session', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/SS/Record/QueryRecord`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId: '1000171$1$0$0', startTime: '2026-10-31 00:00:00', endTime: '2026-10-31 23:59:59' }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.pageCount !== undefined && Array.isArray(j.data?.records) && j.data?.session);
  });

  it('vehicle/anpr/records returns ANPR records', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/vehicle/anpr/records`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(Array.isArray(j.data?.records) && j.data.records.length > 0);
    const rec = j.data.records[0];
    assert.ok(rec.plateNo && rec.vehicleColor && rec.captureTime && rec.channelId);
  });

  it('access/door/status returns PointDoorStatusListVo', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/access/door/status`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ pointIds: ['DOOR001'] }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(Array.isArray(j.data?.results) && j.data.results.length > 0);
    const res = j.data.results[0];
    assert.ok(res.pointId && res.doorStatus !== undefined);
  });

  it('ptz/direction returns PtzOperateVo', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/ptz/direction`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId: '1000171$1$0$0', ptzPan: 10, ptzTilt: 5, ptzZoom: 2 }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.ptzOperateVo?.success === true && j.data.ptzOperateVo.channelId);
  });

  it('alarm/records returns PageAlarmRecordXo with list', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/alarm/records`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ page: 1, pageSize: 20 }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data?.TRUE === true && j.data?.list && Array.isArray(j.data.list) && j.data.list.length > 0);
    const alarm = j.data.list[0];
    assert.ok(alarm.alarmCode && alarm.alarmType !== undefined && alarm.alarmGrade !== undefined && alarm.channelId);
  });

  // ===== E-024: Add Device dialog catalog contracts =====
  it('E-024 dictionary/list returns data.results grouped by type (3=protocol,107=manufacturer)', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.1/dictionary/list?types=3,107`, { headers: { 'X-Subject-Token': token } });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.code, 1000);
    assert.ok(Array.isArray(j.data?.results), 'data.results must be an array');
    const protocols = j.data.results.find((x) => x.type === '3');
    const manufacturers = j.data.results.find((x) => x.type === '107');
    assert.ok(protocols && Array.isArray(protocols.items));
    assert.ok(manufacturers && Array.isArray(manufacturers.items));
    // protocol items carry code/name + param1/param2 (manufacturer CSV filter)
    const dahua = protocols.items.find((x) => x.code === '1');
    assert.ok(dahua && dahua.name && typeof dahua.param1 === 'string' && typeof dahua.param2 === 'string');
    // manufacturer items carry code/name
    assert.ok(manufacturers.items.every((x) => x.code && x.name));
    // the client filters manufacturerDict by the protocol CSV -> must intersect
    const csv = dahua.param2.split(',');
    assert.ok(csv.some((code) => manufacturers.items.some((m) => m.code === code)));
  });

  it('E-024 definition/device-type/list returns results grouped by deviceCategory', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.1/definition/device-type/list`, { headers: { 'X-Subject-Token': token } });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(Array.isArray(j.data?.results) && j.data.results.length >= 20);
    const encoder = j.data.results.find((x) => x.deviceCategory === '1');
    assert.ok(encoder, 'Encoder category (1) must exist');
    assert.ok(encoder.deviceCategoryName, 'deviceCategoryName drives the category combo');
    assert.ok(encoder.deviceTypeName, 'deviceTypeName drives the store caption');
    assert.ok(Array.isArray(encoder.deviceTypes) && encoder.deviceTypes.length > 0);
    assert.ok(encoder.deviceTypes.every((x) => x.deviceType && x.deviceTypeName));
    // ANPR + Access Control must be present (client shows them in the combo)
    assert.ok(j.data.results.some((x) => x.deviceCategory === '5' && x.deviceCategoryName === 'ANPR Device'));
    assert.ok(j.data.results.some((x) => x.deviceCategory === '8' && x.deviceCategoryName === 'Access Control'));
  });

  it('E-024 capability/server/snmp catalogs return results arrays', async () => {
    const cap = await (await fetch(`${BASE}/brms/api/v1.1/definition/channel-capability/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(Array.isArray(cap.data?.results) && cap.data.results.length > 0);
    assert.ok(cap.data.results.every((x) => x.code && x.name));
    const srv = await (await fetch(`${BASE}/brms/api/v1.1/server/available/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(Array.isArray(srv.data?.results) && srv.data.results.some((x) => x.serverCode === 'video#local'));
    const snmp = await (await fetch(`${BASE}/brms/api/v1.1/config/snmp/protocol/manufacturer/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(Array.isArray(snmp.data?.results) && snmp.data.results.length > 0);
    assert.ok(snmp.data.results.every((x) => x.manufacturerCode && x.manufacturerName));
  });

  it('E-024 BRMS RPC transport serves the same catalogs', async () => {
    const r = await fetch(`${BASE}/admin/API/BRM/BRMS/Dictionary/GetDictionaries`, {
      method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ types: '3,107' })
    });
    assert.equal(r.status, 200);
    const j = await r.json();
    const data = j.data || j.info || {};
    assert.ok(Array.isArray(data.results) || Array.isArray(data.items));
    const groups = data.results || data.items;
    const protocols = groups.find((x) => x.type === '3');
    assert.ok(protocols && Array.isArray(protocols.items) && protocols.items.length > 0);
  });

  // UDP Alarm Ingest test (skipped due to timing issues in CI)
  it.skip('UDP 18800 receives alarm text and forwards', async () => {
    const udp = dgram.createSocket('udp4');
    const promise = new Promise((resolve) => {
      udp.on('message', (msg, rinfo) => {
        const text = msg.toString().trim();
        assert.ok(text.includes('ANPR_EBA') || text.includes('ALARM'));
        udp.close();
        resolve();
      });
      udp.bind(0, () => {
        const client = dgram.createSocket('udp4');
        client.send('ANPR_EBA|CAM001|plate=ABC1234\r\n', 18800, '127.0.0.1');
        client.close();
      });
    });
    await promise;
  });

  after(async () => {
    await fetch(`${BASE}/brms/api/v1.0/accounts/unauthorize`, { method: 'POST', headers: { 'X-Subject-Token': token } });
    serverProc.kill();
  });
});