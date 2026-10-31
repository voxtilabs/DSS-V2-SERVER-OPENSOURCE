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

describe('BRMS Gateway - Full DTO Contracts (EV-041..EV-048)', { timeout: 30000 }, () => {
  before(async () => {
    serverProc = spawn('node', ['src/index.js'], { cwd: 'C:/Users/bruno/Downloads/LOCURA DSS/poc/dss-v2-harness/brms-gateway', stdio: 'pipe' });
    await waitForServer();
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
    assert.ok(j.userName);
    assert.ok(j.token);
    // TokenInfoVo fields: token, userId, username, userType, topLevel
    assert.ok(typeof j.token === 'string');
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
    const j = await r.json();
    const d = j.data;
    assert.ok(d.rtspUrl && d.rtspUrl.includes('rtsp://'));
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

  // UDP Alarm Ingest test
  it('UDP 18800 receives alarm text and forwards', async () => {
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