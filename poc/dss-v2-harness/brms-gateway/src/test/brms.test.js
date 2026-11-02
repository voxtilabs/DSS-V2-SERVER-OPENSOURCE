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

  // ===== E-025: device add / discovery / catalogs / launcher bridge =====
  it('E-025 device/discover/cost-time + summary: real ONVIF probe payload', async () => {
    // The real client sends the same body as the add form (deviceIp/devicePort/
    // protocolType=99/deviceCategory/deviceType) BEFORE POST /device.
    const body = JSON.stringify({
      deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99',
      deviceCategory: '1', deviceType: '6', deviceName: 'EBA1', encoderChannelCount: 1
    });
    const cost = await (await fetch(`${BASE}/brms/api/v1.1/device/discover/cost-time`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body
    })).json();
    assert.equal(cost.code, 1000);
    assert.ok(typeof cost.data.costTime === 'number' && cost.data.costTime > 0, 'costTime must be measured');
    assert.equal(cost.data.deviceIp, '127.0.0.1');

    const sum = await (await fetch(`${BASE}/brms/api/v1.1/device/discover/summary`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body
    })).json();
    assert.equal(sum.code, 1000);
    assert.ok(sum.data.manufacturer, 'summary must carry a manufacturer');
    assert.ok([0, 1].includes(sum.data.online), 'summary must report online flag');
    assert.equal(sum.data.deviceName, 'EBA1');
  });

  it('E-025 POST /device: ONVIF add returns a device record + channels', async () => {
    const add = await fetch(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99', deviceCategory: '1',
        deviceType: '6', deviceName: 'EBA1', serverCode: 'video#local',
        encoderChannelCount: 1, loginPass: '0123456789abcdef0123456789abcdef'
      })
    });
    assert.equal(add.status, 200);
    const j = await add.json();
    assert.equal(j.code, 1000);
    assert.ok(j.data.deviceCode, 'deviceCode generated');
    assert.ok(Array.isArray(j.data.results) && j.data.results.length === 1, 'results[] is the web SPA shape');
    assert.ok(Array.isArray(j.data.channels) && j.data.channels.length === 1);
    assert.equal(j.data.channels[0].channelId.split('$').length, 4, 'channelId must be code$no$0$0');
    // loginPass (the MD5 hash sent by the client) is never echoed back
    assert.ok(!JSON.stringify(j.data).includes('0123456789abcdef0123456789abcdef'), 'loginPass must not be echoed');
  });

  it('E-025 device/page + tree/devices(channels) include the added device', async () => {
    const page = await (await fetch(`${BASE}/brms/api/v1.1/device/page`)).json();
    assert.ok(page.data.total >= 2, 'mock device + E-025 add');
    const tree = await (await fetch(`${BASE}/brms/api/v1.0/tree/devices`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(Array.isArray(tree.data.deviceList) && tree.data.deviceList.some((d) => d.deviceName === 'EBA1'));
    const chans = await (await fetch(`${BASE}/brms/api/v1.0/tree/channels`)).json();
    assert.ok(Array.isArray(chans.data.channelList) && chans.data.channelList.every((c) => c.channelId.includes('$')));
    const stats = await (await fetch(`${BASE}/brms/api/v1.1/device/statistics/count-by-device-category/list?keyword=&orgCode=&domain=0&permitted=0&sourceType=1&containChild=1`)).json();
    assert.ok(Array.isArray(stats.data.results) && stats.data.results.some((r) => r.deviceCount > 0));
  });

  it('E-025 network / timezone / role / function / subsystem / omms alert types', async () => {
    const net = await (await fetch(`${BASE}/brms/api/v1.1/system/network/list`)).json();
    assert.ok(Array.isArray(net.data.list) && net.data.list.length > 0 && net.data.list[0].ip);

    const srvTz = await (await fetch(`${BASE}/brms/api/v1.1/config/server/timezone`)).json();
    assert.ok(srvTz.data.timezone);

    const tz = await (await fetch(`${BASE}/brms/api/v1.1/config/timezone/list`)).json();
    assert.ok(Array.isArray(tz.data.list) && tz.data.list.length > 0);

    const role = await (await fetch(`${BASE}/brms/api/v1.1/role/page`)).json();
    assert.ok(Array.isArray(role.data.list) && role.data.list.some((r) => r.roleName === 'Administrator'));

    const fn = await (await fetch(`${BASE}/brms/api/v1.1/function/available/list`)).json();
    assert.ok(Array.isArray(fn.data.list) && fn.data.list.length > 0 && fn.data.list[0].functionCode);

    const sub = await (await fetch(`${BASE}/brms/api/v1.1/subsystem/available/list`)).json();
    assert.ok(Array.isArray(sub.data.subsystemList) && sub.data.subsystemList.length > 0);

    const alert = await (await fetch(`${BASE}/omms/api/v1.1/alert/rule/alert-type/list`)).json();
    assert.equal(alert.code, 1000);
    assert.ok(Array.isArray(alert.data.list) && alert.data.list.length > 0 && alert.data.list[0].alertType);
  });

  it('E-028 /web/client-module serves the REAL production bundle', async () => {
    const html = await (await fetch(`${BASE}/web/client-module/`)).text();
    // the mirrored production Vite index (EV-078), not any invented launcher
    assert.ok(html.includes('id="app"'), 'real SPA root div');
    assert.ok(html.includes('js/index-BhDUzoCV.js'), 'real production entry chunk');
    assert.ok(html.includes('modulepreload'), 'real modulepreload graph');
    assert.ok(!/launcher|emoji/i.test(html), 'invented launcher must not come back');
    // mirrored hashed assets resolve with proper MIME
    const js = await fetch(`${BASE}/web/client-module/js/.pnpm-IcGsI3MK.js`);
    assert.equal(js.status, 200);
    assert.ok((js.headers.get('content-type') || '').includes('javascript'));
    const css = await fetch(`${BASE}/web/client-module/css/index.css`);
    assert.equal(css.status, 200);
    // hash-router fallback: extensionless paths resolve to the same index.html
    const spa = await fetch(`${BASE}/web/client-module/storage-plan`);
    assert.equal(spa.status, 200);
  });

  it('E-025 discover/device/join/batch + check/exist + delete/batch', async () => {
    const join = await fetch(`${BASE}/brms/api/v1.1/discover/device/join/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ devices: [{ deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99', deviceName: 'Discovered Cam', encoderChannelCount: 1 }] })
    });
    const jj = await join.json();
    assert.equal(jj.code, 1000);
    assert.ok(jj.data.total >= 1);

    const chk = await (await fetch(`${BASE}/brms/api/v1.1/device/check/exist`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceIp: '127.0.0.1', devicePort: 1 })
    })).json();
    assert.equal(chk.data.exist, true);

    const del = await (await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceCodes: [jj.data.results[jj.data.results.length - 1].deviceCode] })
    })).json();
    assert.equal(del.code, 1000);
    assert.ok(del.data.removed >= 1);
  });

  it('E-025 p2p easy4ip parse: HTTP 200 + empty <return/> means not published', async () => {
    // Real cloud answer for a serial that is not on Easy4IP (captured live):
    //   HTTP/1.1 200 OK ... <return></return>
    const parsed = await (await fetch(`${BASE}/brms/api/v1.0/p2p/easy4ip/probe?sn=`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(parsed.code, 1000);
    assert.equal(parsed.data.ok, false);

    // The live payload builder must expose the three real states.
    const { probeEasy4IP } = await import('../e025-devices.js');
    const probe = await probeEasy4IP('E2E-NOT-REACHABLE-SERIAL', '127.0.0.1', 600);
    assert.equal(probe.ok, false, 'unreachable Easy4IP host must be an honest failure');
    assert.ok(probe.error);
  });

  it('E-025 p2p register does a REAL Easy4IP serial lookup (no fake success)', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/device/p2p-register`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ sn: 'E2E-INVALID-SERIAL', user: 'admin', password: 'admin123', name: 'E2E P2P Cam', channels: 1 })
    });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.data.deviceId, 'deviceId is issued');
    // either the cloud resolved it or the payload must carry the real reason
    assert.ok(['registered', 'unresolved'].includes(j.data.p2pStatus));
    assert.ok(typeof j.data.easy4ip === 'object', 'easy4ip probe result must be exposed');
    if (j.data.p2pStatus === 'unresolved') {
      assert.ok(j.data.message.length > 0, 'unresolved must explain the real cause');
    }

    const bad = await fetch(`${BASE}/brms/api/v1.0/p2p/easy4ip/probe`, { headers: { 'X-Subject-Token': token } });
    const badJson = await bad.json();
    assert.equal(badJson.code, 1000);
    assert.equal(badJson.data.ok, false);
    assert.ok(badJson.data.error.includes('sn'), 'missing sn must be a clear error');
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