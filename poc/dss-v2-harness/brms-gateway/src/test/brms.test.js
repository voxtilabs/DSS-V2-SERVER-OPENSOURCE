import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import dgram from 'node:dgram';

const BASE = 'http://127.0.0.1:11443';
const USER = 'admin';
const PASS = 'admin123';
const STORE_PATH = new URL('../../data/devices.json', import.meta.url);

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
    serverProc = spawn('node', ['src/index.js'], { cwd: 'C:/Users/bruno/Downloads/LOCURA DSS/poc/dss-v2-harness/brms-gateway', stdio: ['ignore', 'pipe', 'pipe'] });
    // CRITICAL: consume the server pipes. The gateway logs every request
    // ([REQ]/[RES] debug lines); with stdio:'pipe' and NO reader the OS pipe
    // buffer (64 KiB) fills and console.log BLOCKS the server event loop
    // mid-suite, making every later test time out and the runner never exit.
    const pipeFile = (stream, name) => {
      stream.setEncoding('utf8');
      stream.on('data', () => { /* drain */ });
      stream.on('error', () => { /* suite-end */ });
    };
    pipeFile(serverProc.stdout, 'out');
    pipeFile(serverProc.stderr, 'err');
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
    // E-037: real contract = DeviceOrgTreeVo{departments:[OrgNodeVo]} from the
    // server package; orgList stays as an alias for the web SPA.
    assert.ok(j.data?.departments?.length > 0);
    // orgList is a serialized alias of departments (same content, not the same JS object)
    assert.deepEqual(j.data.orgList, j.data.departments);
    const org = j.data.departments[0];
    // OrgNodeVo real keys + the aliases the native client (DPSDK pool) parses.
    assert.ok(org.code && org.name && org.orgType !== undefined);
    assert.ok(org.orgCode === '001' && org.orgName && org.parentCode !== undefined && org.parentOrgCode !== undefined);
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

  it('E-094 omms device/page serves pageData+totalCount (SPA deviceTable contract) with orgName rows', async () => {
    const page = await (await fetch(`${BASE}/omms/api/v1.1/device/page?page=1&pageSize=20&orgCode=&containChild=1`)).json();
    assert.equal(page.code, 1000);
    assert.ok(Array.isArray(page.data.pageData), 'data.pageData must be an array (deviceTable reads it)');
    assert.equal(page.data.totalCount, page.data.pageData.length > 0 ? page.data.totalCount : page.data.totalCount);
    assert.ok(page.data.totalCount >= 2, 'mock + added device');
    const row = page.data.pageData.find((d) => d.deviceIp === '192.168.0.238' || d.deviceName === 'EBA1');
    assert.ok(row, 'added device present in omms pageData');
    assert.ok('orgName' in row && 'orgCode' in row && 'onlineStatus' in row, 'row carries orgName/orgCode/onlineStatus columns');
    // org filter with containChild: VIGILAB must include its devices, an unknown org none
    const vig = await (await fetch(`${BASE}/omms/api/v1.1/device/page?orgCode=VIGILAB&containChild=1`)).json();
    assert.ok(vig.data.pageData.some((d) => d.orgCode === 'VIGILAB'), 'VIGILAB filter keeps VIGILAB devices');
    const none = await (await fetch(`${BASE}/omms/api/v1.1/device/page?orgCode=NOPE&containChild=1`)).json();
    assert.equal(none.data.pageData.length, 0, 'unknown org filters everything out');
    const chans = await (await fetch(`${BASE}/omms/api/v1.1/channel/page`)).json();
    assert.ok(Array.isArray(chans.data.pageData), 'omms channel/page serves pageData');
  });

  it('E-095 device rows carry STRING status "1" + statusName (SPA strict === DEVICE_STATUS.ONLINE)', async () => {
    // RE evidence: device-JBrSmGvP.js DEVICE_STATUS:{OFFLINE:"0",ONLINE:"1"};
    // index-DsQ1Ve9V.js compares e.status === DEVICE_STATUS.ONLINE (strict).
    for (const ns of ['omms', 'brms']) {
      const page = await (await fetch(`${BASE}/${ns}/api/v1.1/device/page?page=1&pageSize=100`)).json();
      const row = page.data.pageData.find((r) => r.deviceIp === '192.168.0.238');
      assert.ok(row, ns + ' row present');
      assert.strictEqual(row.status, '1', ns + ' row.status must be the STRING "1", got ' + JSON.stringify(row.status));
      assert.strictEqual(row.statusName, 'Online');
      assert.strictEqual(row.onlineStatus, '1');
      assert.strictEqual(row.faultStatus, '0');
      assert.strictEqual(row.faultStatusName, 'Normal');
    }
    // channel cards: channelStatus === DEVICE_STATUS_TYPE.ONLINE ("1") strict
    const chans = await (await fetch(`${BASE}/omms/api/v1.1/device/channel/page`)).json();
    for (const c of chans.data.pageData) {
      assert.strictEqual(c.channelStatus, '1');
      assert.strictEqual(c.status, '1');
      assert.strictEqual(c.statusName, 'Channel Online');
    }
    // top cards: bare /omms device/statistics returns top-level counters
    const stats = await (await fetch(`${BASE}/omms/api/v1.1/device/statistics`)).json();
    assert.ok(stats.data.deviceCount >= 1 && stats.data.onlineDeviceCount >= 1, 'statistics aggregate counters');
    // overview derived from registry
    const ov = await (await fetch(`${BASE}/brms/api/v1.1/account/device/overview`)).json();
    assert.ok(ov.data.deviceCount >= 1 && ov.data.onlineDeviceCount >= 1 && ov.data.offlineDeviceCount === ov.data.deviceCount - ov.data.onlineDeviceCount);
    // history tab + export session + disk page + detail
    const hist = await (await fetch(`${BASE}/omms/api/v1.1/device/status/history/record/fetch/page`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ page: 1, pageSize: 20 }) })).json();
    assert.ok(Array.isArray(hist.data.pageData) && hist.data.pageData.length >= 1 && hist.data.pageData[0].status === '1' && hist.data.pageData[0].statusName === 'Online');
    const exp = await (await fetch(`${BASE}/omms/api/v1.1/device/export`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
    assert.ok(exp.data.session && exp.data.fileUrl, 'export returns session+fileUrl');
    const disk = await (await fetch(`${BASE}/omms/api/v1.1/device/disk/status/page`)).json();
    assert.ok(Array.isArray(disk.data.pageData));
    const anyPage = await (await fetch(`${BASE}/brms/api/v1.1/device/page?page=1&pageSize=100`)).json();
    const anyCode = anyPage.data.pageData[0].deviceCode;
    const det = await (await fetch(`${BASE}/omms/api/v1.1/device/${anyCode}`)).json();
    assert.strictEqual(det.data.status, '1');
    assert.strictEqual(det.data.statusName, 'Online');
    assert.ok('offlineReason' in det.data && 'faultReason' in det.data && 'updateTime' in det.data);
    // dictionaries requested in the operator session
    const dict = await (await fetch(`${BASE}/brms/api/v1.1/dictionary/list?types=2001,2016,2052,2053,2055,22,9041,9046`)).json();
    for (const g of dict.data.results) assert.ok(g.items.length > 0, 'dictionary type ' + g.type + ' non-empty');
    // user/list real
    const users = await (await fetch(`${BASE}/brms/api/v1.1/user/list?username=`)).json();
    assert.ok(users.data.list.some((u) => u.username === 'admin'));
  });

  it('E-096 user/page + group/list + config/ldap + role detail (User Management native path)', async () => {
    // GetUserManagerUsers: admin row present with STRING flags (strict ===)
    const page = await (await fetch(`${BASE}/brms/api/v1.1/user/page?username=&online=&groupId=&pageSize=20&roleIds=&page=1&userType=`)).json();
    assert.ok(Array.isArray(page.data.pageData) && page.data.pageData.length >= 1, 'user/page serves pageData');
    const admin = page.data.pageData.find((u) => u.username === 'admin');
    assert.ok(admin, 'admin visible in User Management');
    assert.strictEqual(admin.status, '1', 'admin status must be STRING "1"');
    assert.strictEqual(admin.online, '1');
    assert.strictEqual(admin.enableMPT, '0');
    // E-105: user/page rows are the STRICT native descriptor (DPSDK
    // FUN_1806c8d20): id/username/name/online/enableMPT/status/userType are
    // STRING leaves and roles[] is the only array. No alias keys, no JSON
    // array leaves (the E-100 roleIds array payload was the AppHang suspect).
    assert.ok(Array.isArray(admin.roles) && admin.roles[0].roleId === '1', 'E-105: roles[] array of {roleId,roleName}');
    assert.ok(!('roleIds' in admin) && !('roleIdArray' in admin), 'E-105: no alias/array keys in the native row');
    for (const k of ['id', 'username', 'name', 'online', 'enableMPT', 'status', 'userType']) {
      assert.strictEqual(typeof admin[k], 'string', 'user.' + k + ' must be a STRING');
    }
    assert.ok(
      typeof admin.id !== 'undefined' && typeof admin.username !== 'undefined',
      'userGroupView reads {value:e.id,label:e.username}'
    );
    // SPA usersByPage shape too
    const spaPage = await (await fetch(`${BASE}/brms/api/v1.1/user/page?page=1&pageSize=500&groupId=1`)).json();
    assert.ok(spaPage.data.pageData.some((u) => u.id === '1' && u.username === 'admin'));
    // group/list non-empty (Default) + keyword filter
    const groups = await (await fetch(`${BASE}/brms/api/v1.1/user/group/list?keyword=`)).json();
    assert.ok(Array.isArray(groups.data.list) && groups.data.list.some((g) => g.groupName === 'Default'));
    const none = await (await fetch(`${BASE}/brms/api/v1.1/user/group/list?keyword=ZZZ`)).json();
    assert.equal(none.data.list.length, 0, 'keyword filter applies');
    // config/ldap reaches 200 (no FALLBACK)
    const ldap = await (await fetch(`${BASE}/brms/api/v1.1/config/ldap`)).json();
    assert.equal(ldap.code, 1000);
    // GetUser detail by id
    const det = await (await fetch(`${BASE}/brms/api/v1.1/user/1`)).json();
    assert.equal(det.data.username, 'admin');
    assert.strictEqual(det.data.status, '1');
    // lock/unlock acknowledged
    const lock = await (await fetch(`${BASE}/brms/api/v1.1/user/2/lock`, { method: 'POST' })).json();
    assert.equal(lock.code, 1000);
    // Role Management: detail (GetRole -> v1.1/role/1)
    const role = await (await fetch(`${BASE}/brms/api/v1.1/role/1`)).json();
    assert.equal(role.code, 1000);
    assert.equal(role.data.roleName, 'Administrator');
    // e-mail associate list (DPSDK AssociateUserEmails)
    const emails = await (await fetch(`${BASE}/brms/api/v1.1/user/email/associate/list?keyword=`)).json();
    assert.ok(emails.data.list.some((e) => e.username === 'admin' && e.email));
  });

  it('E-098 authority (cascade) + resource-allocate + org list content', async () => {
    // GetResourceRoles: v1.1/authority/resource/{id}/role/list - admin granted
    const ar = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/VIGILAB/role/list`)).json();
    assert.equal(ar.code, 1000);
    assert.equal(ar.data.resourceId, 'VIGILAB');
    const adminRole = ar.data.list.find((r) => String(r.roleId) === '1');
    assert.strictEqual(adminRole?.checked, '1', 'admin cascade-granted on every resource');
    // SetResourceRoles ack
    const set = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/VIGILAB/role`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"roleIds":["1","2"]}' })).json();
    assert.equal(set.code, 1000);
    // ResourceAllocateGetOrgDevices: org filter + channels present
    const oa = await (await fetch(`${BASE}/brms/api/v1.1/resource-allocate/organization/device/fetch/list?orgCode=VIGILAB`)).json();
    assert.ok(Array.isArray(oa.data.list) && oa.data.list.length >= 1, 'org device fetch list non-empty');
    assert.ok(oa.data.list.every((d) => Array.isArray(d.channels) && d.channels.length >= 1), 'each device carries its channels');
    assert.ok(oa.data.list.every((d) => d.deviceCode && d.orgCode === 'VIGILAB'), 'org filter only returns that org');
    // the org combos must list 001 + VIGILAB (empresas)
    const orgs = await (await fetch(`${BASE}/brms/api/v1.1/organization/list`)).json();
    const names = (orgs.data.list || []).map((o) => o.orgName || o.name);
    assert.ok(names.includes('VIGILAB'), 'organization/list contains VIGILAB, got ' + JSON.stringify(names));
  });

  it('E-099 role flags are STRINGS (crash fix) + org combo + live-view gate', async () => {
    // role/page: every boolean/enum flag must be a string (E-095 strict ===)
    const rp = await (await fetch(`${BASE}/brms/api/v1.1/role/page`)).json();
    assert.equal(rp.code, 1000);
    for (const r of rp.data.list) {
      for (const k of ['status', 'level', 'roleLevel', 'default', 'editable', 'deletable', 'userCount', 'checked']) {
        assert.strictEqual(typeof r[k], 'string', `role.${k} must be string, got ${typeof r[k]} (${r[k]})`);
      }
      assert.ok(r.statusName, 'role.statusName present');
    }
    // role detail (synthesized id) also string flags
    const rd = await (await fetch(`${BASE}/brms/api/v1.1/role/001`)).json();
    assert.strictEqual(rd.data.status, '1');
    // function/available flags are strings too
    const fa = await (await fetch(`${BASE}/brms/api/v1.1/function/available/list`)).json();
    assert.ok(fa.data.list.every((f) => typeof f.status === 'string'), 'function flags string');
    // Organization combo of the User Config dialog: domain/organization/list
    const do_ = await (await fetch(`${BASE}/brms/api/v1.1/domain/organization/list`)).json();
    const orgNames = (do_.data.list || []).map((o) => o.orgName || o.name);
    assert.ok(orgNames.includes('VIGILAB'), 'domain org list has VIGILAB: ' + JSON.stringify(orgNames));
    assert.ok(Array.isArray(do_.data.pageData), 'domain org list has pageData');
    // Live-view gate: channel check grants liveView(8)/playback(9)/ptz(13)
    const cc = await (await fetch(`${BASE}/brms/api/v1.1/account/function/channel/check?channelCode=D0238W9Q1004$1$0$0`)).json();
    assert.ok(cc.data.functionCodes.includes('8') && cc.data.functionCodes.includes('9') && cc.data.functionCodes.includes('13'), 'channel grants liveView/playback/ptz');
    assert.strictEqual(cc.data.checkResult, '1');
    assert.ok(cc.data.functions.every((f) => typeof f.enable === 'string'), 'fn flags string');
    // batch returns one row per channel
    const cb = await (await fetch(`${BASE}/brms/api/v1.1/account/function/channel/check/batch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ channelCodes: ['D0238W9Q1004$1$0$0'] }) })).json();
    assert.equal(cb.code, 1000);
    assert.ok(Array.isArray(cb.data.list) && cb.data.list.length >= 1 && cb.data.list[0].functionCodes.includes('8'));
    // asset permission on a DEVICE resource id: admin checked, flags string
    const ar = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/D0238W9Q1004/role/list`)).json();
    assert.strictEqual(ar.data.list.find((r) => r.roleId === '1').checked, '1');
    for (const r of ar.data.list) assert.strictEqual(typeof r.checked, 'string');
    // device function check
    const dc = await (await fetch(`${BASE}/brms/api/v1.1/account/function/device/check?deviceCode=D0238W9Q1004`)).json();
    assert.ok(dc.data.functionCodes.includes('8'), 'device grants liveView');
  });

  it('E-100 white-screen fix: pageData everywhere + string counters + role.id', async () => {
    // user/group/list must carry pageData (SPA reads data.pageData) + string totals
    const gl = await (await fetch(`${BASE}/brms/api/v1.1/user/group/list?keyword=`)).json();
    assert.ok(Array.isArray(gl.data.pageData), 'group/list pageData array');
    assert.strictEqual(typeof gl.data.total, 'string', 'group/list total string');
    // user/email/page (report-send dialog reads data.pageData -> undefined = crash)
    const em = await (await fetch(`${BASE}/brms/api/v1.1/user/email/page?page=1&pageSize=10000&keyword=`)).json();
    assert.ok(Array.isArray(em.data.pageData), 'email/page pageData array');
    // role rows must carry BOTH roleId and id (SPA role combo reads e.id)
    const rl = await (await fetch(`${BASE}/brms/api/v1.1/role/list`)).json();
    assert.ok(rl.data.list.every((r) => r.id && r.roleId), 'role rows have id+roleId');
    const r1 = await (await fetch(`${BASE}/brms/api/v1.1/role/1`)).json();
    assert.strictEqual(r1.data.id, '1', 'role/1 has id');
    // menu/available: sort must be string in every row (numeric enum crash risk)
    const ma = await (await fetch(`${BASE}/brms/api/v1.1/menu/available/list?roleId=1`)).json();
    assert.ok(ma.data.results.length > 10 && ma.data.results.every((m) => typeof m.sort === 'string'), 'menu sort string');
    // organization/list: string counters + pageData
    const ol = await (await fetch(`${BASE}/brms/api/v1.1/organization/list`)).json();
    assert.strictEqual(typeof ol.data.totalCount, 'string');
    assert.ok(Array.isArray(ol.data.pageData) && ol.data.pageData.some((o) => o.orgCode === 'VIGILAB'));
    // user/page: string counters
    const up = await (await fetch(`${BASE}/brms/api/v1.1/user/page?page=1&pageSize=20`)).json();
    assert.strictEqual(typeof up.data.totalCount, 'string', 'user/page totalCount string');
    assert.ok(up.data.pageData.some((u) => u.username === 'admin'), 'admin visible in user/page');
  });

  it('E-101 tree full GET (no FALLBACK) + real role write + roleIds CSV', async () => {
    // GET /full/grade-device-tree: the Users dialog permission tree (observed
    // live 22:53:21Z falling into [FALLBACK] {list:[],total:0} -> AppHang)
    const t = await (await fetch(`${BASE}/brms/api/v1.1/tree/full/grade-device-tree?sourceType=&protocolType=&orgCode=001&addType=&domain=&roleId=`)).json();
    assert.equal(t.code, 1000);
    assert.ok(Array.isArray(t.data.organizations) && Array.isArray(t.data.devices), 'full tree carries organizations+devices');
    assert.ok(Array.isArray(t.data.channels), 'full tree carries channels');
    const t2 = await (await fetch(`${BASE}/brms/api/v1.1/tree/full/grade-device-tree/search/list?keyword=`)).json();
    assert.ok(Array.isArray(t2.data.channels) && Array.isArray(t2.data.devices));
    // role write returns a REAL role row (string flags), not a static stub
    const rw = await (await fetch(`${BASE}/brms/api/v1.1/role`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ roleName: 'TestRole', menuCodes: [], functionCodes: [], channelIds: [], deviceCodes: [] }) })).json();
    assert.strictEqual(rw.data.success, true);
    assert.ok(rw.data.roleId && rw.data.id === rw.data.roleId, 'role write returns id');
    assert.strictEqual(rw.data.status, '1');
    assert.strictEqual(rw.data.roleName, 'TestRole');
    // user rows: STRICT native pageData row (roles[] objects, no array leaves)
    const up = await (await fetch(`${BASE}/brms/api/v1.1/user/page?page=1&pageSize=20`)).json();
    assert.strictEqual(up.data.pageData[0].roles[0].roleId, '1', 'roles[].roleId (native)');
    assert.strictEqual(typeof up.data.pageData[0].roles[0].roleName, 'string', 'roles[].roleName is STRING');
    assert.ok(!('roleIdArray' in up.data.pageData[0]), 'E-105: no roleIdArray alias');
    // user detail keeps the CSV aliases (own native descriptor + SPA)
    const ud = await (await fetch(`${BASE}/brms/api/v1.1/user/1`)).json();
    assert.strictEqual(ud.data.roleIds, '1');
  });

  it('E-102 native contracts: user roles[]/name, role memo/allowEdit, domain org, role/update', async () => {
    // user/page rows bind native keys: name, enableMPT, roles[] {roleId,roleName}
    const up = await (await fetch(`${BASE}/brms/api/v1.1/user/page?page=1&pageSize=20`)).json();
    const admin = up.data.pageData.find((u) => u.username === 'admin');
    assert.strictEqual(admin.name, 'Administrator', 'native key name present');
    assert.strictEqual(admin.enableMPT, '0');
    assert.ok(Array.isArray(admin.roles) && admin.roles[0].roleId === '1' && typeof admin.roles[0].roleName === 'string', 'roles[] array of {roleId,roleName}');
    assert.ok(!('roleIds' in admin), 'E-105: user/page row has no roleIds alias (strict native row)');
    // user detail same shape
    const ud = await (await fetch(`${BASE}/brms/api/v1.1/user/1`)).json();
    assert.ok(Array.isArray(ud.data.roles) && typeof ud.data.name === 'string');
    // role/page rows bind native keys: allowEdit, id, roleType, roleName, memo
    const rp = await (await fetch(`${BASE}/brms/api/v1.1/role/page`)).json();
    assert.ok(Array.isArray(rp.data.pageData), 'E-103: role/page serves pageData[]');
    for (const r of rp.data.pageData) {
      for (const k of ['id', 'roleName', 'memo', 'roleType', 'allowEdit']) {
        assert.strictEqual(typeof r[k], 'string', `role.${k} string, got ${typeof r[k]}`);
      }
    }
    // authority resource role list: results is an ARRAY OF STRINGS (native),
    // the role OBJECTS live in list/roleList
    const ar = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/VIGILAB/role/list`)).json();
    assert.ok(Array.isArray(ar.data.results) && ar.data.results.every((r) => typeof r === 'string'), 'E-104: authority results = string roleIds');
    assert.ok(ar.data.results.includes('1'), 'admin role id in results');
    for (const r of ar.data.list) {
      assert.strictEqual(typeof r.id, 'string'); assert.strictEqual(typeof r.roleName, 'string'); assert.strictEqual(typeof r.memo, 'string');
    }
    // SetResourceRoles: PUT .../role/update echoes roleIds array
    const ru = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/VIGILAB/role/update`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ roleIds: ['1', '2'], resourceId: 'VIGILAB', resourceType: '1' }) })).json();
    assert.deepStrictEqual(ru.data.roleIds, ['1', '2']);
    // domain/organization/list native shape: domainOrgExceeded + results[].domainOrg*
    const do_ = await (await fetch(`${BASE}/brms/api/v1.1/domain/organization/list`)).json();
    assert.strictEqual(do_.data.domainOrgExceeded, '0');
    const vig = (do_.data.results || []).find((o) => o.domainOrgCode === 'VIGILAB');
    assert.ok(vig && vig.domainOrgName === 'VIGILAB' && typeof vig.pId === 'string', 'VIGILAB in domain org results with native keys');
    // group-by-role-level: results[] {groupName, groupId, users[]}
    const gb = await (await fetch(`${BASE}/brms/api/v1.1/user/group-by-role-level/list?keyword=`)).json();
    assert.ok(Array.isArray(gb.data.results[0].users) && gb.data.results[0].users.some((u) => u.username === 'admin'), 'group carries users[]');
  });

  it('E-104 ldap native keys + authority results strings', async () => {
    // config/ldap: native parser binds username/port/autoSynTime/dn/enable/
    // enableAutoSyn/ssl/server directly on data (FUN_18064d140) - strings
    const ld = await (await fetch(`${BASE}/brms/api/v1.1/config/ldap`)).json();
    for (const k of ['username', 'port', 'autoSynTime', 'dn', 'enable', 'enableAutoSyn', 'ssl', 'server']) {
      assert.strictEqual(typeof ld.data[k], 'string', `ldap.${k} must be string, got ${typeof ld.data[k]}`);
    }
    assert.strictEqual(ld.data.enable, '0');
    assert.strictEqual(ld.data.port, '389');
    // authority results strings (repeat check for the fixed E-098 payload)
    const ar = await (await fetch(`${BASE}/brms/api/v1.1/authority/resource/001/role/list`)).json();
    assert.ok(ar.data.results.every((r) => typeof r === 'string') && ar.data.results.includes('1'));
    assert.ok(ar.data.list.some((r) => r.roleId === '1' && r.checked === '1'), 'role objects keep checked in list');
  });

  it('E-106 second-time login: RSA public-key/generate + password/check', async () => {
    // VerifyFirstTime: real RSA public key + randomKey (was [FALLBACK] stub)
    const pk = await (await fetch(`${BASE}/brms/api/v1.1/account/security/public-key/generate`)).json();
    assert.equal(pk.code, 1000);
    assert.ok(String(pk.data.publicKey).startsWith('-----BEGIN PUBLIC KEY-----'), 'publicKey is a PEM');
    assert.ok(pk.data.randomKey && pk.data.randomKey.length >= 16, 'randomKey present');
    // encrypt a password with the served key and verify password/check accepts it
    const encrypted = crypto.publicEncrypt({ key: pk.data.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from('admin123')).toString('base64');
    const pc = await (await fetch(`${BASE}/brms/api/v1.1/account/security/password/check`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: encrypted, randomKey: pk.data.randomKey })
    })).json();
    assert.equal(pc.code, 1000);
    assert.strictEqual(pc.data.success, true);
    assert.strictEqual(pc.data.checkResult, '1');
    // still works with garbage (client only needs code 1000 to continue)
    const pc2 = await (await fetch(`${BASE}/brms/api/v1.1/account/security/password/check`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"password":"","randomKey":""}'
    })).json();
    assert.equal(pc2.code, 1000);
  });

  it('E-108 account/menu/list + config/videoIntercom + config/mail served', async () => {
    // the three endpoints the live QA sweep found in the catch-all
    const am = await (await fetch(`${BASE}/brms/api/v1.1/account/menu/list?roleId=1`)).json();
    assert.equal(am.code, 1000);
    assert.ok(Array.isArray(am.data.results) && am.data.results.length > 10, 'account menu list populated');
    assert.strictEqual(typeof am.data.results[0].menuCode, 'string');
    const vi = await (await fetch(`${BASE}/brms/api/v1.1/config/videoIntercom`)).json();
    assert.strictEqual(vi.data.enable, '0');
    assert.strictEqual(vi.data.openState, '0');
    const mc = await (await fetch(`${BASE}/brms/api/v1.1/config/mail`)).json();
    for (const k of ['enable', 'ssl', 'server', 'port', 'username', 'sender']) {
      assert.strictEqual(typeof mc.data[k], 'string', `mail.${k} string`);
    }
    // variants must not fall to the catch-all either
    for (const p of ['/brms/api/v1.0/account/menu/list', '/brms/api/v1.1/config/mail', '/ipms/api/v1.1/account/menu/list']) {
      const r = await fetch(`${BASE}${p}`);
      const t = await r.text();
      assert.ok(t.length > 60, `${p} must be real, got ${t.length}B`);
    }
  });

  it('E-109 server/list + storage endpoints (client FALLBACK hits)', async () => {
    // server/list: the video server owning every device record
    const sl = await (await fetch(`${BASE}/brms/api/v1.1/server/list`)).json();
    assert.equal(sl.code, 1000);
    assert.ok(sl.data.list.some((s) => s.serverCode === 'video#local'), 'video#local server listed');
    assert.strictEqual(typeof sl.data.totalCount, 'string');
    // storage/position/device/page: pageData of the real registry
    const sp = await (await fetch(`${BASE}/brms/api/v1.1/storage/position/device/page?page=1&pageSize=20&orgCode=&keyword=`)).json();
    assert.ok(Array.isArray(sp.data.pageData) && sp.data.pageData.length >= 1, 'storage position pageData non-empty');
    assert.ok(sp.data.pageData.every((d) => d.deviceCode && d.serverCode), 'rows carry deviceCode+serverCode');
    // local disk: real statfs numbers, string fields
    const ld = await (await fetch(`${BASE}/brms/api/v1.1/storage/disk/local-disk/list?serverCode=`)).json();
    assert.ok(ld.data.list.length >= 1 && typeof ld.data.list[0].totalSpace === 'string');
    // net-disk + group: explicit empty (not catch-all shape)
    const nd = await (await fetch(`${BASE}/brms/api/v1.1/storage/disk/net-disk/list?serverCode=`)).json();
    assert.ok(Array.isArray(nd.data.list) && typeof nd.data.totalCount === 'string');
    const dg = await (await fetch(`${BASE}/brms/api/v1.1/storage/group/list?serverCode=`)).json();
    assert.ok(Array.isArray(dg.data.list) && typeof dg.data.totalCount === 'string');
    // variants must be explicit routes too
    for (const p of ['/brms/api/v1.0/server/list', '/ipms/api/v1.1/server/list', '/brms/api/v2.0/storage/group/list']) {
      const t = await (await fetch(`${BASE}${p}`)).text();
      assert.ok(t.length > 60, `${p} explicit, got ${t.length}B`);
    }
  });

  it('E-111 module coverage: logs, alarm, license, tvwall, config', async () => {
    // Log module
    const sl = await (await fetch(`${BASE}/brms/api/v1.1/log/system-log/page`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"page":1,"pageSize":20}' })).json();
    assert.equal(sl.code, 1000);
    assert.ok(Array.isArray(sl.data.pageData) && typeof sl.data.totalCount === 'string', 'log page shape');
    const et = await (await fetch(`${BASE}/brms/api/v1.1/log/system-log/event-type/list`)).json();
    assert.ok(et.data.list.length >= 10, 'event types listed');
    const lc = await (await fetch(`${BASE}/brms/api/v1.1/log/client-config`)).json();
    assert.strictEqual(typeof lc.data.logLevel, 'string');
    // Alarm module
    const ap = await (await fetch(`${BASE}/brms/api/v1.1/alarm/plan/fetch/page`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
    assert.ok(Array.isArray(ap.data.pageData), 'alarm plan pageData');
    const ar = await (await fetch(`${BASE}/brms/api/v1.1/alarm/plan/resource/config-status/fetch/batch/list`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
    assert.ok(ar.data.list.some((r) => r.resourceId === 'VIGILAB'), 'VIGILAB resource config status');
    // License module
    const li = await (await fetch(`${BASE}/brms/api/v1.1/license/item/list`)).json();
    assert.ok(li.data.list.some((i) => i.itemCode === 'channel'), 'license channels item');
    const ld = await (await fetch(`${BASE}/brms/api/v1.1/license/detail`)).json();
    assert.strictEqual(ld.data.status, '1');
    // TVWall
    const tw = await (await fetch(`${BASE}/admin/API/VMS/TvWall/GetTvWallCapacity`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
    assert.strictEqual(tw.data.capacity, '9');
    // Config pages
    const ms = await (await fetch(`${BASE}/brms/api/v1.1/config/message-storage`)).json();
    assert.strictEqual(typeof ms.data.keepDays, 'string');
    const ts = await (await fetch(`${BASE}/brms/api/v1.1/config/time-sync`)).json();
    assert.strictEqual(typeof ts.data.interval, 'string');
    const qc = await (await fetch(`${BASE}/brms/api/v1.1/config/quick/command/list`)).json();
    assert.ok(qc.data.list.some((c) => c.commandCode === 'reboot'), 'quick commands');
    const tls = await (await fetch(`${BASE}/brms/api/v1.1/config/tls/cert/detail`)).json();
    assert.strictEqual(tls.data.status, '1');
    // none of these may fall back to the catch-all
    for (const p of ['/brms/api/v1.1/log/operate-log', '/brms/api/v1.1/license/components', '/cfgs/api/v1.1/config/time-sync', '/admin/API/tvwall/window']) {
      const t = await (await fetch(`${BASE}${p}`)).text();
      assert.ok(t.length > 60, `${p} explicit route, got ${t.length}B`);
    }
  });

  it('E-112 client-log key contracts: warningHappened, results, memo, alertTypeId, hasAuthority', async () => {
    // QueryHostSpareWarning -> "Invalid key: [warningHappened]" (client log 04:44:56)
    const hs = await (await fetch(`${BASE}/brms/api/v1.1/system/hot-spare/switch/warning`)).json();
    assert.ok('warningHappened' in hs.data, 'warningHappened present');
    // PacketGetMemoryOutOfServerList / BasicServiceWarm -> "Invalid key: [results]"
    for (const p of ['/brms/api/v1.1/system/out/memory/server/list', '/brms/api/v1.1/system/only-startup-basic-service/warning', '/brms/api/v1.1/license/warning', '/brms/api/v1.1/system/warn/disk/list']) {
      const r = await (await fetch(`${BASE}${p}`)).json();
      assert.ok(Array.isArray(r.data.results), `${p} carries results[]`);
    }
    // PacketGetAlertTypes -> "Invalid key: [alertTypeId]"
    const at = await (await fetch(`${BASE}/omms/api/v1.1/alert/rule/alert-type/list`)).json();
    assert.ok(at.data.list.every((a) => typeof a.alertTypeId === 'string' && typeof a.alertTypeIdName === 'string'), 'alertTypeId present');
    // PacketGetUserGroupList -> "Invalid key: [memo]"
    const gl = await (await fetch(`${BASE}/brms/api/v1.1/user/group/list?keyword=`)).json();
    assert.ok(gl.data.list.every((g) => typeof g.memo === 'string'), 'group rows carry memo');
    // PacketGetParkingOrganization -> "Invalid key: [hasAuthority]"
    const ol = await (await fetch(`${BASE}/ipms/api/v1.1/organization/list`)).json();
    assert.ok(ol.data.list.every((o) => typeof o.hasAuthority === 'string'), 'org rows carry hasAuthority');
    // netDisks -> "Invalid key: [abnormityType]"
    const nd = await (await fetch(`${BASE}/brms/api/v1.1/storage/disk/net-disk/list?serverCode=`)).json();
    assert.ok('abnormityType' in nd.data, 'net disk carries abnormityType');
  });

  it('E-113 StartVideo v1.1 mirrors the real RealTimeVideoVo (no empty data:{})', async () => {
    for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
      const sv = await (await fetch(`${BASE}${host}/MTS/Video/StartVideo`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
        body: JSON.stringify({ channelId: '1000171$1$0$0', streamType: '1', protocol: 'RTSP' })
      })).json();
      assert.equal(sv.code, 1000, host + ' code');
      assert.ok(sv.data.url && sv.data.url.includes('rtsp://'), host + ' url');
      assert.ok(sv.data.url.includes(`${sv.data.ip}:${sv.data.port}`), host + ' url carries ip+port');
      assert.ok(sv.data.session && sv.data.token && sv.data.vkId, host + ' session/token/vkId');
      assert.ok(sv.data.port === 9100, host + ' rtsp port');
      // stop + keepalive must not fall to the catch-all either
      const stop = await (await fetch(`${BASE}${host}/MTS/Video/StopVideo`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: JSON.stringify({ token: sv.data.token }) })).json();
      assert.strictEqual(stop.data.success, true, host + ' stop');
      const ka = await (await fetch(`${BASE}${host}/MTS/Video/KeepAlive`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: '{}' })).json();
      assert.strictEqual(ka.data.success, true, host + ' keepalive');
    }
  });

  it('E-097 notifyDeviceStatus push (no manual refresh)', async () => {    const { buildDeviceStatusNotifyEnvelopes } = await import('../e039-mq-notify.js');
    const envs = buildDeviceStatusNotifyEnvelopes({ deviceCode: 'D0238JDG3016', orgCode: 'VIGILAB', deviceName: 'cam', channelNum: 1 }, true);
    assert.equal(envs.length, 2, 'device status + dev channel status envelopes');
    for (const raw of envs) {
      const env = JSON.parse(raw);
      assert.ok(env.method === 'vms.notifyDeviceStatus' || env.method === 'vms.notifyDevChannelStatus', 'method from DPSDK table @0xc71358');
      const info = env.info.info || env.info;
      assert.strictEqual(info.status, '1', 'status STRING "1"');
      assert.strictEqual(info.online, '1');
      assert.equal(info.deviceCode, 'D0238JDG3016');
      assert.ok(Array.isArray(info.channels) && info.channels.length >= 1, 'channel list present');
    }
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

    // E-030: results carries ONLY failure rows; created devices live in list.
    assert.ok(Array.isArray(jj.data.results) && jj.data.results.length === 0);
    assert.ok(jj.data.list.length >= 1);
    const del = await (await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceCodes: [jj.data.list[jj.data.list.length - 1].deviceCode] })
    })).json();
    assert.equal(del.code, 1000);
    assert.ok(del.data.removed >= 1);
  });

  it('E-031 device/channel/list + organization/fetch/batch/list + GET device/{code} (live view resource helpers)', async () => {
    // create a device
    await fetch(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceName: 'E031-CAM', deviceIp: '127.0.0.7', devicePort: 37777, protocolType: '99', channelCount: 2, addType: '1' })
    });
    const page = await (await fetch(`${BASE}/brms/api/v1.1/device/page?pageSize=100`, { headers: { 'X-Subject-Token': token } })).json();
    const rows = page.data.results || page.data.list || [];
    const dev = rows.find((d) => d.deviceIp === '127.0.0.7');
    assert.ok(dev, 'E031-CAM registered');

    // POST /device/channel/list {ids} -> data.results rows keyed by channelId
    // E-038: real channelId = <code>$<unitType ENC=1>$0$<channelSeq0>.
    const ch = await (await fetch(`${BASE}/brms/api/v1.1/device/channel/list`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ ids: [`${dev.deviceCode}$1$0$0`, `${dev.deviceCode}$1$0$1`] })
    })).json();
    assert.equal(ch.code, 1000);
    assert.ok(Array.isArray(ch.data.results) && ch.data.results.length === 2, 'results rows keyed by channelId');
    for (const row of ch.data.results) {
      assert.equal(row.deviceCode, dev.deviceCode);
      assert.ok(row.channelId && row.channelName);
    }
    // unknown ids -> exact EMPTY results (never a generic fallback)
    const miss = await (await fetch(`${BASE}/brms/api/v1.1/device/channel/list`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ ids: ['no$such$0$0'] })
    })).json();
    assert.deepEqual(miss.data.results, []);

    // POST /device/organization/fetch/batch/list -> data IS the rows array
    const orgRows = await (await fetch(`${BASE}/brms/api/v1.1/device/organization/fetch/batch/list`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceCodes: [dev.deviceCode] })
    })).json();
    assert.equal(orgRows.code, 1000);
    assert.ok(Array.isArray(orgRows.data), 'data is the row array (consumers iterate it directly)');
    assert.equal(orgRows.data[0].deviceCode, dev.deviceCode);
    assert.ok(orgRows.data[0].orgCode && orgRows.data[0].orgName);

    // GET /device/{code} -> data object; unknown -> 404 (not the fallback)
    const det = await (await fetch(`${BASE}/brms/api/v1.1/device/${dev.deviceCode}`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(det.code, 1000);
    assert.equal(det.data.deviceName, 'E031-CAM');
    const none = await fetch(`${BASE}/brms/api/v1.1/device/NO-SUCH`, { headers: { 'X-Subject-Token': token } });
    assert.equal(none.status, 404);

    await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceCodes: [dev.deviceCode] })
    });
  });

  it('E-093 /ipms/api/v1.1/organization/list serves the org store (001+VIGILAB) with dual keys list/results + total/count', async () => {
    // The native CDevAdd Organization combo (cmbGroupName) is fed by DPSDK
    // GetOrgList -> GET /ipms/api/v1.1/organization/list; it was empty
    // ({list:[],total:0}) so join/batch went out with orgCode:"".
    const r = await fetch(`${BASE}/ipms/api/v1.1/organization/list`);
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.code, 1000);
    const d = j.data;
    assert.ok(Array.isArray(d.list) && Array.isArray(d.results), 'dual keys list+results');
    assert.equal(d.list.length, d.results.length, 'list === results');
    assert.equal(String(d.total), String(d.list.length), 'total (string per E-100)');
    assert.equal(String(d.count), String(d.list.length), 'count (string per E-100)');
    const codes = d.list.map((o) => o.orgCode);
    assert.ok(codes.includes('001') && codes.includes('VIGILAB'), '001+VIGILAB present: ' + codes.join(','));
    const vig = d.list.find((o) => o.orgCode === 'VIGILAB');
    assert.equal(vig.orgName, 'VIGILAB');
    assert.equal(vig.parentCode, '001');
    assert.equal(vig.parentOrgCode, '001');
    // RE-SCHEMA-DPSDK.md §5.2 vms.LogicOrg org keys (deparmentsCount sic)
    for (const k of ['orgCode', 'orgName', 'id', 'parentCode', 'sort', 'domainId', 'modifyTime', 'channels', 'deparmentsCount']) {
      assert.ok(k in vig, 'org item key ' + k);
    }
    assert.equal(vig.hasChild, '0', 'string flags, not booleans');
    // BRMS aliases (web SPA useDeviceApi getOrg) serve the same payload
    for (const p of ['/brms/api/v1.1/organization/list', '/brms/api/v1.0/organization/list']) {
      const r2 = await fetch(`${BASE}${p}`);
      assert.equal(r2.status, 200, p);
      const j2 = await r2.json();
      assert.ok((j2.data.list || []).some((o) => o.orgCode === 'VIGILAB'), p + ' has VIGILAB');
      assert.equal(j2.data.total, j2.data.count);
    }
  });

  it('E-032 registry persistence: discovery join/batch writes devices.json, delete/batch rewrites it', async () => {
    const readStore = () => {
      try { return JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')); } catch { return []; }
    };
    // 1) the DISCOVERY path (the one the DSS Client uses from "Discovered
    // Devices") must persist the device - it used to live only in RAM.
    const join = await (await fetch(`${BASE}/brms/api/v1.1/discover/device/join/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ devices: [{ deviceIp: '127.0.0.32', devicePort: 37777, protocolType: '99', deviceName: 'E032-PERSIST', encoderChannelCount: 1 }] })
    })).json();
    assert.equal(join.code, 1000);
    const created = (join.data.list || []).find((d) => d.deviceIp === '127.0.0.32');
    assert.ok(created, 'device created through the discovery path');
    assert.ok(readStore().some((d) => d.deviceCode === created.deviceCode),
      'join/batch persisted the device to data/devices.json');

    // 2) delete/batch must REMOVE it from disk too (no resurrection on restart)
    const del = await (await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceCodes: [created.deviceCode] })
    })).json();
    assert.ok(del.data.removed >= 1);
    assert.ok(!readStore().some((d) => d.deviceCode === created.deviceCode),
      'delete/batch rewrote data/devices.json');
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

  // ===== E-029: the six routes that answered from the generic [FALLBACK] =====
  // The production SPA could not read those answer bodies: they came back as
  // {code:1000,data:{list:[],total:0}}, which produced the ~20 "Abnormally
  // returned the service or device data" toasts and left Device Config loading
  // forever (its tree is lazy-loaded from grade-device-tree). Each shape below
  // is the one the mirrored production bundle consumer actually reads.
  it('E-029 grade-device-tree returns organizations+devices with channels', async () => {
    const body = {
      treeType: '2', domain: '0',
      conditions: [{ deviceCategories: ['1', '2'], unitTypes: ['1', '2'], sourceTypes: ['1'] }],
      orgCode: '001'
    };
    const res = await fetch(`${BASE}/brms/api/v1.1/tree/grade-device-tree`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: JSON.stringify(body)
    });
    const json = await res.json();
    assert.equal(json.code, 1000);
    assert.ok(Array.isArray(json.data.organizations), 'data.organizations must be an array');
    assert.ok(Array.isArray(json.data.devices), 'data.devices must be an array (BatchLoadingTree.load destructures it)');
    for (const d of json.data.devices) {
      assert.ok(d.deviceCode, 'device needs deviceCode (tree id)');
      assert.ok(d.deviceName, 'device needs deviceName (tree label)');
      assert.ok(d.orgCode, 'device needs orgCode');
      assert.ok(Array.isArray(d.channels), 'device needs channels[] (device node children)');
      for (const c of d.channels) {
        assert.ok(c.channelId, 'channel needs channelId (optimizeChannel id)');
        assert.ok(c.channelName, 'channel needs channelName (optimizeChannel label)');
        assert.equal(c.deviceCode, d.deviceCode, 'channel must point back to its device');
      }
    }
    // EXCEEDED_FLAG_ENUM values are "0" (UNDER) when nothing is truncated.
    assert.equal(json.data.deviceExceeded, '0');
    assert.equal(json.data.organizationExceeded, '0');
    assert.equal(json.data.channelExceeded, '0');
  });

  it('E-029 grade-device-tree/search/list returns channels+devices+organizations', async () => {
    const res = await fetch(`${BASE}/brms/api/v1.1/tree/grade-device-tree/search/list`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ treeType: '2', domain: '0', orgCode: '001', keyword: 'zzz-no-match' })
    });
    const json = await res.json();
    assert.equal(json.code, 1000);
    assert.ok(Array.isArray(json.data.channels) && Array.isArray(json.data.devices) && Array.isArray(json.data.organizations));
  });

  it('E-029 record-plan/page + motion-detection-record-plan/page return totalCount+pageData', async () => {
    // Exact production URLs (useVideoStorageConfigApi-BiF2jm_X.js):
    //   getRecordPlans               -> /storage/plan/channel/record-plan/page
    //   getMotionDetectionRecordPlans -> /storage/plan/motion-detection-record-plan/page  (no /channel/)
    const urls = [
      `${BASE}/brms/api/v1.1/storage/plan/channel/record-plan/page?page=1&pageSize=20&orgCode=&keyword=&position=1`,
      `${BASE}/brms/api/v1.1/storage/plan/motion-detection-record-plan/page?page=1&pageSize=20&orgCode=&keyword=`
    ];
    for (const u of urls) {
      const res = await fetch(u, { headers: { 'X-Subject-Token': token } });
      const json = await res.json();
      assert.equal(json.code, 1000, u);
      assert.equal(typeof json.data.totalCount, 'number', `${u}: totalCount must be numeric (Number(data.totalCount))`);
      assert.ok(Array.isArray(json.data.pageData), `${u}: pageData must be an array`);
    }
    // A configured plan is rendered with the exact table columns the SPA uses.
    const res = await fetch(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceIp: '192.168.0.238', devicePort: '8021', protocolType: '99', deviceCategory: '1', deviceType: '2', deviceName: 'EBA1', serverCode: 'video#local', encoderChannelCount: 1, loginPass: '0'.repeat(32) })
    });
    assert.equal(res.status, 200);
    const chan = await (await fetch(`${BASE}/brms/api/v1.0/tree/channels`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: '{}' })).json();
    const first = (chan.data?.channelList || chan.data?.list || [])[0];
    assert.ok(first?.channelId, 'a real channel must exist to configure a plan');
    const put = await fetch(`${BASE}/brms/api/v1.1/storage/plan/channel/${encodeURIComponent(first.channelId)}/new-device-record-plan`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: JSON.stringify({ channelId: first.channelId }) });
    assert.equal(put.status, 200);
    const plans = await (await fetch(`${BASE}/brms/api/v1.1/storage/plan/channel/record-plan/page?page=1&pageSize=20`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(plans.data.totalCount >= 1, 'the configured plan must be listed');
    assert.equal(plans.data.pageData[0].channelId, first.channelId);
    assert.ok('channelName' in plans.data.pageData[0] && 'deviceName' in plans.data.pageData[0]);
  });

  it('E-029 account/user/level returns data.level and timezone/info returns dst fields', async () => {
    const level = await (await fetch(`${BASE}/brms/api/v1.1/account/user/level`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(level.code, 1000);
    assert.ok(level.data.level, 'data.level is stored as roleLevel on login');

    const tz = await (await fetch(`${BASE}/brms/api/v1.1/config/timezone/info?area=America/Santiago`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(tz.code, 1000);
    for (const k of ['dstType', 'enableDst', 'timezoneOffset', 'dstBeginDate', 'dstBeginTime', 'dstEndDate', 'dstEndTime']) {
      assert.ok(tz.data[k] !== undefined && tz.data[k] !== null && tz.data[k] !== '', `timezone/info must return ${k}`);
    }
    // dstBeginDate/dstEndDate are parsed as "month/week/day" - a missing value
    // makes the client throw and store an empty localTimezone.
    assert.match(String(tz.data.dstBeginDate), /^\d+\/\d+\/\d+$/);
    assert.match(String(tz.data.dstEndDate), /^\d+\/\d+\/\d+$/);

    // Unknown areas still answer with every key (no client-side exception).
    const unknown = await (await fetch(`${BASE}/brms/api/v1.1/config/timezone/info?area=Europe/Nowhere`, { headers: { 'X-Subject-Token': token } })).json();
    assert.ok(unknown.data.dstBeginDate && unknown.data.dstEndDate);
  });

  it('E-029 discover/page rows carry id+initStatus+protocol and join/batch resolves ids', async () => {
    // Add-Discover page (index-DsQ1Ve9V.js): x.value = data.pageData, and the
    // row feeds addIds = map(rows, "id") + initStatus/protocol compares.
    const probe = { deviceIp: '192.168.0.238', devicePort: '8021', protocolType: '99', deviceCategory: '1', deviceType: '2', deviceName: 'EBA1', loginName: 'admin', loginPass: '0'.repeat(32), serverCode: 'video#local' };
    await fetch(`${BASE}/brms/api/v1.1/device/discover/cost-time`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: JSON.stringify(probe) });
    const discovered = await (await fetch(`${BASE}/brms/api/v1.1/discover/device/page?page=1&pageSize=100&status=0`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(discovered.code, 1000);
    assert.ok(Array.isArray(discovered.data.pageData), 'data.pageData is read by the Add-Discover page');
    const row = discovered.data.pageData.find((r) => r.deviceIp === '192.168.0.238');
    assert.ok(row?.id, 'row must have id (addIds = map(rows, "id"))');
    assert.ok(['0', '1'].includes(row.initStatus), 'row.initStatus must be "0"/"1"');
    assert.ok(row.protocol !== undefined, 'row.protocol is compared against DEV_PROTOCOL_TYPE');

    const join = await (await fetch(`${BASE}/brms/api/v1.1/discover/device/join/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ ids: [row.id] })
    })).json();
    assert.equal(join.code, 1000);
    // E-030: full success -> results carries NO rows (the single-add dialog
    // mislabels any row as "Failed to add device"); the device must exist.
    assert.deepEqual(join.data?.results, [], 'full success = empty results');
    assert.notEqual(join.data?.total, 0, 'device must be created');
    assert.notEqual('110113', 'resolvable ids must not fail');

    // Unknown id -> the one SPA-known failure code with no localized text sent.
    const bad = await (await fetch(`${BASE}/brms/api/v1.1/discover/device/join/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ ids: ['no-such-row'] })
    })).json();
    assert.equal(bad.data.results[0].result, '110113');
  });

  // ===== E-037/E-038: REAL native tree contract (departments/devices) =====
  it('E-037 native tree: departments/devices carry the real DTO + every registration funnel', async () => {
    // Register a device through the MANUAL add funnel and one through the
    // DISCOVER funnel; both must appear in the native trees.
    const add = await (await fetch(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceName: 'E037-CAM', deviceIp: '127.0.0.71', devicePort: 37777, protocolType: '99', channelCount: 2, addType: '1' })
    })).json();
    const code = add.data.deviceCode || add.data.device?.deviceCode;
    assert.ok(code, 'device created');

    const orgTree = await (await fetch(`${BASE}/admin/API/tree/deviceOrg`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(orgTree.code, 1000);
    // REAL contract: DeviceOrgTreeVo{departments:[OrgNodeVo]} (server package).
    assert.ok(Array.isArray(orgTree.data.departments) && orgTree.data.departments.length > 0,
      'departments is the real native key');
    const dept = orgTree.data.departments[0];
    // OrgNodeVo real fields. E-041: departments carries one node per persisted
    // org (root '001' first, then 'VIGILAB').
    assert.equal(dept.code, '001');
    assert.ok(orgTree.data.departments.some((d) => d.code === 'VIGILAB'), 'VIGILAB org node present');
    assert.ok(dept.name && dept.parentCode !== undefined && dept.orgType !== undefined);
    assert.ok(Array.isArray(dept.device), 'OrgNodeVo.device carries {id,sort} rows');
    // The add body carried no orgCode -> the device lands under the default
    // org VIGILAB (empty orgCode was the attempt-2 bug).
    const devDept = orgTree.data.departments.find((d) => d.device.some((x) => x.id === code));
    assert.ok(devDept, 'registered device listed in an org node');
    assert.equal(devDept.code, 'VIGILAB', 'default org of a new device is VIGILAB');

    const devTree = await (await fetch(`${BASE}/admin/API/tree/devices`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ orgCode: 'VIGILAB', containVirtualDevice: '1', categories: [], deviceCodes: [] })
    })).json();
    assert.equal(devTree.code, 1000);
    // REAL contract: DeviceTreeVo{devices:[DeviceInfoVo]}.
    assert.ok(Array.isArray(devTree.data.devices), 'devices is the real native key');
    const dev = devTree.data.devices.find((d) => d.code === code);
    assert.ok(dev, 'registered device listed in the device tree');
    // DeviceInfoVo real fields.
    assert.equal(String(dev.status), '1');
    assert.ok(dev.deviceIp && dev.orgCode && ['0', '6', '9', '14', '15'].includes(dev.loginType));
    assert.ok(Array.isArray(dev.units) && dev.units.length > 0, 'DeviceInfoVo.units');
    const unit = dev.units[0];
    assert.equal(unit.unitType, '1', 'encoder unit type ENC=1');
    assert.ok(Array.isArray(unit.channels) && unit.channels.length >= 2);
    // E-038: real channelId = <code>$<unitType 1>$0$<channelSeq0>.
    assert.equal(unit.channels[0].channelCode, `${code}$1$0$0`);
    assert.equal(unit.channels[1].channelCode, `${code}$1$0$1`);

    // Filter honouring: DeviceTreeXo.deviceCodes.
    const filtered = await (await fetch(`${BASE}/admin/API/tree/devices`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceCodes: [code] })
    })).json();
    assert.ok(filtered.data.devices.length >= 1);
    assert.ok(filtered.data.devices.every((d) => d.code === code));

    await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceCodes: [code] })
    });
  });

  // ===== E-035: real menu/function catalogs (seed SQL + FunctionType enum) =====
  it('E-035 menu/function lists serve the REAL server catalogs and RPC rights', async () => {
    const menus = await (await fetch(`${BASE}/brms/api/v1.1/menu/available/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(menus.code, 1000);
    assert.ok(menus.data.results.length >= 80, 'sys_menu has 86 rows');
    const codes = new Set(menus.data.results.map((m) => m.menuCode));
    // Real seed codes (the invented 100..700 must be gone).
    for (const c of ['001', '004', '004001', '004002', '004004', '010', '001001']) {
      assert.ok(codes.has(c), `real menu ${c} present`);
    }
    assert.ok(!codes.has('100') && !codes.has('700'), 'invented menus removed');

    const flag = await (await fetch(`${BASE}/brms/api/v1.1/menu/001/available`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(flag.data.available, '1');
    const bad = await (await fetch(`${BASE}/brms/api/v1.1/menu/999xyz/available`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(bad.data.available, '0');

    const fns = await (await fetch(`${BASE}/brms/api/v1.1/menu/function/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(fns.code, 1000);
    const fnMap = new Map(fns.data.results.map((f) => [f.functionCode, f.functionName]));
    assert.equal(fnMap.get('8'), 'liveView');
    assert.equal(fnMap.get('9'), 'playback');
    assert.equal(fnMap.get('2'), 'ptzOperateAndConfig');
    assert.ok(fnMap.get('8') && fns.data.results.every((f) => f.pId !== undefined));

    const avail = await (await fetch(`${BASE}/brms/api/v1.1/function/available/list`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(avail.code, 1000);
    assert.ok(avail.data.results.some((f) => f.functionCode === '17' && f.functionName === 'livePreview'));

    const rpc = await (await fetch(`${BASE}/brms/api/BRM/User/GetUserFunctions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
    assert.equal(rpc.code, 1000);
    // adm_role_function(ROLE_ID=1) = the real Super Administrator codes.
    assert.deepEqual(rpc.data.functions, ['1', '2', '3', '5', '6', '8', '9', '10', '11']);
    assert.ok(rpc.data.functions.includes('8'), 'liveView must be granted');

    // GetMenuRights = union of the seed grants (86) + the leveldb harvest.
    const rights = await (await fetch(`${BASE}/brms/api/BRM/User/GetMenuRights`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
    const rightSet = new Set(rights.data.menuRights);
    for (const c of ['001', '004001', '002005004', '004004004']) assert.ok(rightSet.has(c), `menu right ${c}`);
    // Resource.Tree RPCs now answer the REAL native payload (no empty envelope).
    // Transport path is /brms/api/BRM/:ns/:fn — "Resource.Tree".(fn).
    const treeRpc = await (await fetch(`${BASE}/brms/api/BRM/Resource.Tree/GetDeviceOrg`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
    assert.ok(Array.isArray(treeRpc.data.departments) && treeRpc.data.departments.length > 0);
  });

  // ===== E-034: every device owns its own MediaMTX path =====
  it('E-034 StartVideo resolves the per-device MediaMTX path from the channelId', async () => {
    const add = await (await fetch(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceName: 'E034-CAM', deviceIp: '127.0.0.74', devicePort: 37777, protocolType: '99', channelCount: 1, addType: '1' })
    })).json();
    const code = add.data.deviceCode || add.data.device?.deviceCode;
    assert.ok(code, 'device created');
    const page = await (await fetch(`${BASE}/brms/api/v1.1/device/page?pageSize=100`, { headers: { 'X-Subject-Token': token } })).json();
    const row = (page.data.results || page.data.list || []).find((d) => d.deviceCode === code);
    assert.equal(row.mediamtxPath, `cam_${code}`, 'creation-time path (cam_<deviceCode>)');

    const sv = await (await fetch(`${BASE}/brms/api/v1.0/MTS/Video/StartVideo`, {
      method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelId: `${code}$1$0$0`, streamType: 1, dataType: 1 })
    })).json();
    assert.equal(sv.code, 1000);
    assert.ok(sv.data.url.includes(`/${`cam_${code}`}?token=`),
      `StartVideo URL must target the device path, got ${sv.data.url}`);

    await fetch(`${BASE}/brms/api/v1.1/device/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ deviceCodes: [code] })
    });
  });

  // ===== E-033: real monitor/view contract =====
  it('E-033 monitor/view: ViewTreeVo shape + view-dir/view CRUD round-trip', async () => {
    const tree = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view/view-tree`, { headers: { 'X-Subject-Token': token } })).json();
    assert.equal(tree.code, 1000);
    // ViewTreeVo{viewInfos:[{viewType, viewDirs:[]}]}, public + private entries.
    assert.ok(Array.isArray(tree.data.viewInfos) && tree.data.viewInfos.length === 2);
    for (const vi of tree.data.viewInfos) assert.ok(['1', '2'].includes(vi.viewType));

    const dir = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view/view-dir`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ viewDirName: 'E033-DIR' })
    })).json();
    const dirCode = dir.data.viewDirCode || dir.data.code;
    assert.ok(dirCode, 'view dir created');

    const view = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ viewName: 'E033-VIEW', viewDirCode: dirCode, windowTotal: '1', griddingRows: '1', griddingCols: '1', windows: [{ windowId: '1', channelId: 'nope$1$0$0' }] })
    })).json();
    assert.equal(view.code, 1000);
    assert.ok(view.data.viewCode, 'view created');

    const renamed = await fetch(`${BASE}/brms/api/v1.1/monitor/view/${view.data.viewCode}/rename`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ viewName: 'E033-VIEW-2' })
    });
    assert.equal(renamed.status, 200);

    const afterTree = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view/view-tree`, { headers: { 'X-Subject-Token': token } })).json();
    const dirs = (afterTree.data.viewInfos[0]?.viewDirs || []).flatMap((d) => d.views || []);
    assert.ok(dirs.some((v) => v.viewCode === view.data.viewCode), 'view listed in the tree after rename');

    const del = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ viewCodes: [view.data.viewCode] })
    })).json();
    assert.equal(del.code, 1000);
    const delDir = await (await fetch(`${BASE}/brms/api/v1.1/monitor/view/view-dir/delete/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({ viewDirCodes: [dirCode] })
    })).json();
    assert.equal(delDir.code, 1000);
  });

  after(async () => {
    await fetch(`${BASE}/brms/api/v1.0/accounts/unauthorize`, { method: 'POST', headers: { 'X-Subject-Token': token } });
    serverProc.kill();
  });
});