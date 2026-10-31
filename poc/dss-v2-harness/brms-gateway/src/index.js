import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
console.log('CWD:', process.cwd());
console.log('__dirname:', __dirname);
console.log('__filename:', __filename);

const app = Fastify({ logger: true });
await app.register(cors, { origin: true });

const REALM = 'DSS-V2-LAB';
const TOKENS = new Map();
const PENDING = new Map();

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genRandomKey() { return crypto.randomBytes(16).toString('hex'); }

function envelope(data, code = 1000, desc = 'Success') {
  return { code, desc, data };
}

// ===== AUTH =====
app.post('/brms/api/v1.0/accounts/authorize', async (req, reply) => {
  const { userName, randomKey, signature, clientType, challengeKey } = req.body;
  if (userName && !randomKey && !signature) {
    const rk = genRandomKey();
    const key = 'pending-' + Date.now();
    PENDING.set(key, { realm: REALM, randomKey: rk, expires: Date.now() + 60000 });
    return reply.code(401).send(envelope({ realm: REALM, randomKey: rk, challengeKey: key }, 401, 'Unauthorized'));
  }
  const pending = PENDING.get(challengeKey);
  if (!pending || pending.randomKey !== randomKey) return reply.code(401).send(envelope(null, 401, 'invalid challenge'));
  const temp = doubleMd5(userName, 'admin123');
  const expected = makeSig(userName, REALM, temp, randomKey);
  if (signature !== expected) return reply.code(401).send(envelope(null, 401, 'bad signature'));
  const token = genToken();
  TOKENS.set(token, { userName, expires: Date.now() + 86400000 });
  PENDING.delete(challengeKey);
  return envelope({ token, duration: 86400 });
});

function auth(req, reply, done) {
  const token = req.headers['x-subject-token'];
  if (!token || !TOKENS.has(token)) return reply.code(401).send(envelope(null, 401, 'unauthorized'));
  const t = TOKENS.get(token);
  if (Date.now() > t.expires) { TOKENS.delete(token); return reply.code(401).send(envelope(null, 401, 'expired')); }
  req.user = t; done();
}

app.post('/brms/api/v1.0/accounts/keepalive', { preHandler: auth }, async () => envelope({ success: true }));
app.get('/brms/api/v1.0/accounts/current', { preHandler: auth }, async (req) => envelope({
  token: req.headers['x-subject-token'],
  userId: '1',
  username: req.user.userName,
  userType: '1',
  topLevel: '1'
}));
app.post('/brms/api/v1.0/accounts/unauthorize', { preHandler: auth }, async (req) => { TOKENS.delete(req.headers['x-subject-token']); return envelope({ success: true }); });

// ===== TREE =====
app.post('/brms/api/v1.0/tree/orgs', { preHandler: auth }, async () => envelope({
  orgList: [{ orgId: '1', orgName: 'Root', parentId: '0', orgType: 1, sort: 1 }]
}));

app.post('/brms/api/v1.0/tree/devices', { preHandler: auth }, async () => envelope({
  deviceList: [{
    deviceCode: 'CAM001', deviceName: 'Test Camera', status: 1, deviceType: 2,
    ip: '192.168.1.100', port: 37777, protocol: 'Dahua', userName: 'admin',
    channelNum: 1, alarmInNum: 1, alarmOutNum: 1, diskNum: 0,
    supportP2P: true, supportRTSPS: true, supportMulticast: true
  }]
}));

app.post('/brms/api/v1.0/tree/channels', { preHandler: auth }, async () => envelope({
  channelList: [{
    channelId: '1000171$1$0$0', channelName: 'Ch1', status: 1, channelType: 1,
    videoType: 0, audioType: 0, bitRate: 1024, resolution: '1920x1080', fps: 25
  }]
}));

// ===== MTS VIDEO =====
app.post('/brms/api/v1.0/MTS/Video/StartVideo', { preHandler: auth }, async (req) => {
  const { channelId, streamType, dataType, enableMulticast, enableRtsps, extend, fakeSdp, forceSynPlay, keyCode, operateType, planId, trackId } = req.body;
  const token = genToken();
  const session = genToken().slice(0, 16);
  const vkId = 'vk-' + genToken().slice(0, 8);
  const url = `rtsp://127.0.0.1:9100/${channelId}?token=${token}`;
  return envelope({
    connectType: 999, ip: '127.0.0.1', minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: 9100, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1', vkId, vkValue: genToken().slice(0, 16),
    hlsUrl: `https://127.0.0.1:11443/brms/api/v1.1/video/live/channel/${channelId}/hls?test=7`,
    fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || '',
    _debug: 'v7_FORCE_READ'
  });
// THROW ERROR IF FILE READ: throw new Error('FILE READ VERIFICATION');
// SYNTAX ERROR IF FILE NOT READ: const x = ;
});

app.post('/brms/api/v1.0/MTS/Video/StopVideo', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/MTS/Video/KeepAlive', { preHandler: auth }, async () => envelope({ success: true }));

// ===== SS RECORD =====
app.post('/brms/api/v1.0/SS/Record/QueryRecord', { preHandler: auth }, async (req) => {
  return envelope({
    pageCount: 1,
    session: genToken().slice(0, 16),
    records: [{
      channelId: '1000171$1$0$0', startTime: '2026-10-31 00:00:00',
      endTime: '2026-10-31 01:00:00', recordType: 1,
      streamType: 1, fileSize: 1024000, diskPath: '/mnt/record',
      startIndex: 0, endIndex: 3600, recordSource: 1, streamIds: ['main']
    }]
  });
});

app.post('/brms/api/v1.0/SS/Record/StartRecord', { preHandler: auth }, async () => envelope({ now: '2026-10-31 00:00:00', planId: '' }));
app.post('/brms/api/v1.0/SS/Record/StopRecord', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/SS/Record/LockRecord', { preHandler: auth }, async () => envelope({ id: genToken().slice(0, 8) }));
app.post('/brms/api/v1.0/SS/Record/UnlockRecord', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/SS/Record/QueryLock', { preHandler: auth }, async () => envelope({ lockInfos: [] }));
app.post('/brms/api/v1.0/SS/Record/DeleteRecord', { preHandler: auth }, async () => envelope({ success: true }));

// ===== EVENTS / ALARM =====
app.post('/brms/api/v1.0/event/subscription', { preHandler: auth }, async () => envelope({ subscriptionId: 'sub-' + genToken().slice(0, 8) }));
app.post('/brms/api/v1.0/event/query', { preHandler: auth }, async () => envelope({ events: [] }));

// ===== VEHICLE / ANPR =====
app.post('/brms/api/v1.0/vehicle/anpr/records', { preHandler: auth }, async () => envelope({
  records: [{
    id: genToken().slice(0, 16), plateNo: 'ABC1234', plateColor: 'blue', vehicleColor: 'white',
    vehicleBrand: 'Toyota', vehicleType: 'car', captureTime: '2026-10-31 12:00:00',
    channelId: '1000171$1$0$0', channelName: 'Ch1', deviceCode: 'CAM001', confidence: 95,
    plateImgUrl: '', vehicleImgUrl: '', direction: 1
  }]
}));

app.post('/brms/api/v1.0/vehicle/whitelist', { preHandler: auth }, async () => envelope({ success: true, repeatOrExistCarsNewVo: { repeatCars: [], existCars: [] } }));
app.post('/brms/api/v1.0/vehicle/list', { preHandler: auth }, async () => envelope({
  pageVo: { currentPage: 1, pageSize: 20, total: 1, list: [{
    id: genToken().slice(0, 8), personId: 'P001', plateNo: 'ABC1234', carNumColor: 'blue',
    carType: 'car', carMark: 'Toyota', vehicleColor: 'white', carStatus: 1,
    orgCode: '1', orgName: 'Root', companyName: 'DSS Lab', personName: 'Test User',
    entranceGroups: [], surveyGroups: [], carCode: 'CAR001', bindingDeviceCode: 'CAM001',
    carStatus: 1, createTime: '2026-10-31 00:00:00', updateTime: '2026-10-31 00:00:00'
  }] }
}));

app.post('/brms/api/v1.0/vehicle/add', { preHandler: auth }, async (req) => envelope({ repeatOrExistCarsNewVo: { repeatCars: [], existCars: [] } }));
app.post('/brms/api/v1.0/vehicle/entrance/info', { preHandler: auth }, async () => envelope({ vehicleEntranceAccessAuthInfo: { canEnter: true, reason: '', entranceGroupIds: [] } }));

// ===== ACCESS CONTROL =====
app.post('/brms/api/v1.0/access/door/status', { preHandler: auth }, async (req) => envelope({
  results: [{ pointId: req.body.pointIds?.[0] || 'DOOR001', doorStatus: 1, alarmStatus: 0, openTime: '', closeTime: '' }]
}));

app.post('/brms/api/v1.0/access/door/control', { preHandler: auth }, async () => envelope({ success: true }));

app.post('/brms/api/v1.0/access/records', { preHandler: auth }, async (req) => envelope({
  pageBean: { currentPage: 1, pageSize: 20, total: 1, list: [{
    id: genToken().slice(0, 8), areaName: 'Area1', pointId: 'DOOR001', pointName: 'Main Door',
    personId: 'P001', personName: 'Test User', cardNo: 'CARD001', accessTime: '2026-10-31 12:00:00',
    accessResult: 1, verifyMode: 1, doorStatus: 1, snapshotUrl: ''
  }] }
}));

app.post('/brms/api/v1.0/access/alarm/status', { preHandler: auth }, async (req) => envelope({
  results: [{ pointId: req.body.pointIds?.[0] || 'DOOR001', alarmStatus: 0, alarmTime: '', alarmType: '' }]
}));

app.post('/brms/api/v1.0/access/record/export', { preHandler: auth }, async () => envelope({ exportFileVo: { fileUrl: '', fileName: 'access_records.xlsx' } }));

// ===== PTZ =====
app.post('/brms/api/v1.0/ptz/direction', { preHandler: auth }, async (req) => {
  const { channelId, ptzPan, ptzTilt, ptzZoom } = req.body;
  return envelope({ ptzOperateVo: { success: true, channelId, ptzPan: ptzPan || 0, ptzTilt: ptzTilt || 0, ptzZoom: ptzZoom || 0 } });
});

app.post('/brms/api/v1.0/ptz/preset', { preHandler: auth }, async (req) => envelope({
  ptzPresetPointVo: { channelId: req.body.channelId || '', presetPoints: [{ presetId: 1, presetName: 'Home' }] }
}));

app.post('/brms/api/v1.0/ptz/goto/home', { preHandler: auth }, async (req) => envelope({ success: true, channelId: req.body.channelId || '' }));
app.post('/brms/api/v1.0/ptz/set/home', { preHandler: auth }, async (req) => envelope({ success: true, channelId: req.body.channelId || '' }));
app.post('/brms/api/v1.0/ptz/device/location', { preHandler: auth }, async (req) => envelope({ devAndPtzLocation: { deviceCode: '', ptzLocation: '' } }));
app.post('/brms/api/v1.0/ptz/correct/scene', { preHandler: auth }, async () => envelope({ success: true }));

// ===== ALARM RECORDS =====
app.post('/brms/api/v1.0/alarm/records', { preHandler: auth }, async (req) => envelope({
  TRUE: true, currentPage: 1, page: 1, pageSize: 20, splitId: '', splitTime: '',
  list: [{
    id: genToken().slice(0, 8), alarmCode: 'ALM001', alarmType: 1, alarmGrade: 1,
    alarmDate: '2026-10-31 12:00:00', alarmStat: 1, handleStat: 0, handleType: 0,
    channelId: '1000171$1$0$0', channelName: 'Ch1', deviceCode: 'CAM001', deviceName: 'Test Cam',
    alarmPic: '', alarmPicSize: 0, gpsX: 0, gpsY: 0, handleDate: '', handleMessage: '',
    handleUserName: '', handleUserGroupName: '', linkRecordChannels: '', mailReceivers: '',
    memo: '', eventRemark: '', extData: '', handleUserGroupUsers: '', handleUserGroupName: ''
  }]
}));

app.post('/brms/api/v1.0/alarm/handle', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/alarm/procedures', { preHandler: auth }, async () => envelope({ alarmProcedureVo: { procedures: [] } }));
app.post('/brms/api/v1.0/alarm/dprecord', { preHandler: auth }, async () => envelope({ alarmDprecordVo: { alarmCode: '', alarmTime: '', carColor: '', carImgUrl: '', carNum: '', carSpeed: 0, carType: '', carWayCode: '', channelId: '', channelName: '', peccancyType: '' } }));
app.post('/brms/api/v1.0/alarm/picrecord/wanted', { preHandler: auth }, async () => envelope({ alarmPicrecordWantedVo: { alarmCode: '', alarmTime: '', blacklistType: '', carColor: '', carImgUrl: '', carNum: '', carNumcolor: '', carType: '', channelId: '', channelName: '' } }));


// ===== HEALTH =====
app.get('/health', async () => ({ status: 'ok', version: '0.1.0', realm: REALM }));

const PORT = parseInt(process.env.PORT || '11443');

app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) throw err;
  console.log(`BRMS Gateway listening on http://0.0.0.0:${PORT}`);
  
  // UDP Alarm Ingest (port 18800)
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    const text = msg.toString().trim();
    console.log(`[UDP 18800] ${rinfo.address}:${rinfo.port} -> ${text}`);
    app.inject({ method: 'POST', url: '/brms/api/v1.0/event/push', payload: { raw: text, from: rinfo.address }, headers: { 'X-Subject-Token': 'internal' } });
  });
  udp.bind(18800, '0.0.0.0', () => console.log('UDP Alarm Ingest listening on 0.0.0.0:18800'));
  
  // Backup UDP 19800
  const udp2 = dgram.createSocket('udp4');
  udp2.bind(19800, '0.0.0.0', () => console.log('UDP Alarm Backup listening on 0.0.0.0:19800'));
});