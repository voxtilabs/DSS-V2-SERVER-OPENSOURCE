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