import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = Fastify({ logger: true });
await app.register(cors, { origin: true });

// ===== REQUEST INSPECTOR MIDDLEWARE (Catch-All) =====
app.addHook('onRequest', async (req, reply) => {
  const start = Date.now();
  req.startTime = start;
  
  // Log incoming request
  const logEntry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: {
      'content-type': req.headers['content-type'],
      'x-subject-token': req.headers['x-subject-token'] ? 'PRESENT' : 'ABSENT',
      'user-agent': req.headers['user-agent'],
      host: req.headers.host
    },
    query: req.query,
    body: req.body
  };
  
  console.log('[REQ]', JSON.stringify(logEntry));
  
  // Store for response logging
  req.logEntry = logEntry;
});

app.addHook('onResponse', async (req, reply) => {
  const duration = Date.now() - (req.startTime || Date.now());
  const logEntry = {
    ...req.logEntry,
    statusCode: reply.statusCode,
    durationMs: duration,
    responseHeaders: reply.getHeaders()
  };
  console.log('[RES]', JSON.stringify(logEntry));
});

const REALM = process.env.REALM || 'DSS-V2-LAB';
const PORT = parseInt(process.env.PORT || '11443', 10);
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '1443', 10);
const RTSP_PORT = parseInt(process.env.RTSP_PORT || '9100', 10);
const PUBLIC_HOST = process.env.PUBLIC_HOST || '127.0.0.1';
const MEDIAMTX_URL = process.env.MEDIAMTX_URL || 'rtsp://mediamtx:8554';
const SSL_KEY = process.env.SSL_KEY || '/certs/key.pem';
const SSL_CERT = process.env.SSL_CERT || '/certs/cert.pem';
const USE_HTTPS = process.env.HTTPS === 'true';

const TOKENS = new Map();
const PENDING = new Map();

// RTSP session management
const RTSP_SESSIONS = new Map();
const WS_CLIENTS = new Set();

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

// ===== BOOTSTRAP ENDPOINTS (called after login) =====
app.get('/brms/api/v1.0/accounts/menus', { preHandler: auth }, async () => envelope({
  menus: [
    { id: '1', name: 'Monitor', parentId: '0', sort: 1, icon: 'monitor', url: '/monitor' },
    { id: '2', name: 'Playback', parentId: '0', sort: 2, icon: 'playback', url: '/playback' },
    { id: '3', name: 'Alarm', parentId: '0', sort: 3, icon: 'alarm', url: '/alarm' },
    { id: '4', name: 'Device', parentId: '0', sort: 4, icon: 'device', url: '/device' },
    { id: '5', name: 'Config', parentId: '0', sort: 5, icon: 'config', url: '/config' }
  ]
}));

app.get('/brms/api/v1.1/accounts/menus', { preHandler: auth }, async () => envelope({
  menuList: [
    { menuId: '1', menuName: 'Monitor', parentId: '0', sort: 1, icon: 'monitor', url: '/monitor', children: [] },
    { menuId: '2', menuName: 'Playback', parentId: '0', sort: 2, icon: 'playback', url: '/playback', children: [] },
    { menuId: '3', menuName: 'Alarm', parentId: '0', sort: 3, icon: 'alarm', url: '/alarm', children: [] },
    { menuId: '4', menuName: 'Device', parentId: '0', sort: 4, icon: 'device', url: '/device', children: [] },
    { menuId: '5', menuName: 'Config', parentId: '0', sort: 5, icon: 'config', url: '/config', children: [] }
  ]
}));

app.get('/brms/api/v1.0/accounts/userinfo', { preHandler: auth }, async (req) => envelope({
  userId: '1',
  username: req.user.userName,
  userType: '1',
  topLevel: '1',
  realName: 'Administrator',
  email: 'admin@dss-v2.lab',
  phone: '',
  remark: '',
  createTime: '2026-01-01 00:00:00',
  lastLoginTime: new Date().toISOString(),
  lastLoginIp: req.ip
}));

app.get('/brms/api/v1.0/system/time', { preHandler: auth }, async () => envelope({
  serverTime: Math.floor(Date.now() / 1000),
  timezone: 'UTC',
  ntpServer: 'pool.ntp.org'
}));

app.get('/brms/api/v1.0/version', { preHandler: auth }, async () => envelope({
  version: 'V8.008.0000000.0',
  buildDate: '2026-09-30',
  buildNumber: 'R.20260930',
  productName: 'DSS Ultimate',
  protocolVersion: '1.0'
}));

app.get('/brms/api/v1.0/system/version', { preHandler: auth }, async () => envelope({
  version: 'V8.008.0000000.0',
  buildDate: '2026-09-30',
  buildNumber: 'R.20260930',
  productName: 'DSS Ultimate'
}));

app.get('/brms/api/v1.0/capability', { preHandler: auth }, async () => envelope({
  capabilities: {
    maxDevices: 1000,
    maxChannels: 2000,
    maxUsers: 100,
    supportP2P: true,
    supportRTSPS: true,
    supportHLS: true,
    supportMulticast: true,
    supportPTZ: true,
    supportAlarm: true,
    supportANPR: true,
    supportAccessControl: true,
    supportFaceRecognition: true,
    supportVehicle: true,
    supportMap: true,
    supportVideoWall: false
  }
}));

app.get('/brms/api/v1.0/license', { preHandler: auth }, async () => envelope({
  licenseInfo: {
    type: 'trial',
    maxDevices: 1000,
    maxChannels: 2000,
    expireTime: '2027-12-31 23:59:59',
    features: ['base', 'p2p', 'rtsp', 'hls', 'ptz', 'alarm', 'anpr', 'access', 'face', 'vehicle']
  }
}));

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
  // Use MediaMTX for real H.265 streaming
  // MediaMTX path names must be alphanumeric/underscore/dot/minus/slash
  // Use a simple path "test" for all channels (MediaMTX limitation)
  const mediamtxPath = 'test';
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${mediamtxPath}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  // Store session for token validation
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now() });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1', vkId, vkValue: genToken().slice(0, 16),
    hlsUrl, fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
  });
});
app.post('/brms/api/v1.0/MTS/Video/StopVideo', { preHandler: auth }, async (req) => {
  // Clean up RTSP session if token provided
  const { token } = req.body;
  if (token) RTSP_SESSIONS.delete(token);
  return envelope({ success: true });
});
app.post('/brms/api/v1.0/MTS/Video/KeepAlive', { preHandler: auth }, async () => envelope({ success: true }));

// ===== SS RECORD =====
app.post('/brms/api/v1.0/SS/Record/QueryRecord', { preHandler: auth }, async (req) => envelope({
  pageCount: 1,
  session: genToken().slice(0, 16),
  records: [{
    channelId: '1000171$1$0$0', startTime: '2026-10-31 00:00:00',
    endTime: '2026-10-31 01:00:00', recordType: 1,
    streamType: 1, fileSize: 1024000, diskPath: '/mnt/record',
    startIndex: 0, endIndex: 3600, recordSource: 1, streamIds: ['main']
  }]
}));
app.post('/brms/api/v1.0/SS/Record/StartRecord', { preHandler: auth }, async () => envelope({ now: '2026-10-31 00:00:00', planId: '' }));
app.post('/brms/api/v1.0/SS/Record/StopRecord', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/SS/Record/LockRecord', { preHandler: auth }, async () => envelope({ id: genToken().slice(0, 8) }));
app.post('/brms/api/v1.0/SS/Record/UnlockRecord', { preHandler: auth }, async () => envelope({ success: true }));
app.post('/brms/api/v1.0/SS/Record/QueryLock', { preHandler: auth }, async () => envelope({ lockInfos: [] }));
app.post('/brms/api/v1.0/SS/Record/DeleteRecord', { preHandler: auth }, async () => envelope({ success: true }));

// ===== EVENTS =====
app.post('/brms/api/v1.0/event/subscription', { preHandler: auth }, async () => envelope({ subscriptionId: 'sub-' + genToken().slice(0, 8) }));
app.post('/brms/api/v1.0/event/query', { preHandler: auth }, async () => envelope({ events: [] }));
app.post('/brms/api/v1.0/event/push', async (req) => {
  // Internal endpoint for UDP -> event bridge
  const { raw, from } = req.body;
  const event = {
    type: 'ALARM',
    source: from,
    raw,
    timestamp: new Date().toISOString()
  };
  // Broadcast to all WebSocket clients
  const msg = JSON.stringify(event);
  for (const ws of WS_CLIENTS) {
    if (ws.readyState === 1) ws.send(msg);
  }
  return envelope({ success: true, event });
});

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

// ===== P2P STATUS & REGISTER =====
app.get('/brms/api/v1.0/p2p/status', { preHandler: auth }, async () => envelope({
  status: 'available',
  easy4ip: 'www.easy4ip.com',
  profile: 'tools'
}));

// P2P Device Register by SN
// Called by DSS Client to register a device by Serial Number
// Body: { sn, user, password, name, channels }
// Returns: { deviceId, channelIds, p2pStatus }
const P2P_DEVICES = new Map();

app.post('/brms/api/v1.0/device/p2p-register', { preHandler: auth }, async (req, reply) => {
  const { sn, user, password, name, channels = 1 } = req.body;
  if (!sn) return reply.code(400).send(envelope(null, 400, 'Missing SN'));
  
  // Check if already registered
  if (P2P_DEVICES.has(sn)) {
    const existing = P2P_DEVICES.get(sn);
    return envelope({
      deviceId: existing.deviceId,
      channelIds: existing.channelIds,
      p2pStatus: 'already_registered',
      message: 'Device already registered'
    });
  }
  
  // Generate device ID and channel IDs
  const deviceId = 'P2P-' + genToken().slice(0, 12);
  const channelIds = [];
  for (let i = 1; i <= channels; i++) {
    channelIds.push(`${deviceId}$${i}$0$0`);
  }
  
  // Store P2P device info
  P2P_DEVICES.set(sn, {
    sn,
    deviceId,
    name: name || `P2P Device ${sn}`,
    user: user || 'admin',
    channelIds,
    registeredAt: Date.now(),
    status: 'online'
  });
  
  // Also add to device tree (simulated)
  // In real implementation, this would trigger SOAP lookup to Easy4IP and PTCP tunnel creation
  
  return envelope({
    deviceId,
    channelIds,
    p2pStatus: 'registered',
    message: 'Device registered successfully. P2P tunnel creation simulated.'
  });
});

// P2P Device Unregister
app.post('/brms/api/v1.0/device/p2p-unregister', { preHandler: auth }, async (req) => {
  const { sn } = req.body;
  if (!sn) return reply.code(400).send(envelope(null, 400, 'Missing SN'));
  
  P2P_DEVICES.delete(sn);
  return envelope({ success: true, message: 'Device unregistered' });
});

// P2P Device List
app.post('/brms/api/v1.0/device/p2p-list', { preHandler: auth }, async () => {
  const devices = Array.from(P2P_DEVICES.values()).map(d => ({
    sn: d.sn,
    deviceId: d.deviceId,
    name: d.name,
    status: d.status,
    channelIds: d.channelIds,
    registeredAt: d.registeredAt
  }));
  return envelope({ devices });
});

// ===== ARS (Auto Register Service) - Device Auto-Registration =====
// Traditional Dahua device auto-registration (device -> server)
// Device sends registration with its info, server adds to device tree
// Works WITHOUT P2P (as Don Omar confirmed)

const ARS_DEVICES = new Map();

// Device registers itself (called by device, not client)
// Body: { deviceId, deviceName, ip, port, username, password, deviceType, channelNum, ... }
app.post('/brms/api/v1.0/ars/register', async (req, reply) => {
  const { deviceId, deviceName, ip, port, username, password, deviceType, channelNum, protocol, ...rest } = req.body;
  
  if (!deviceId || !ip) {
    return reply.code(400).send(envelope(null, 400, 'Missing deviceId or ip'));
  }

  // Check if already registered
  if (ARS_DEVICES.has(deviceId)) {
    const existing = ARS_DEVICES.get(deviceId);
    existing.lastSeen = Date.now();
    existing.ip = ip; // Update IP in case it changed
    return envelope({
      success: true,
      deviceId: existing.deviceId,
      message: 'Device already registered, updated',
      registered: true
    });
  }

  // Generate internal device code if not provided
  const internalDeviceCode = deviceId.startsWith('ARS-') ? deviceId : 'ARS-' + deviceId;

  // Store ARS device info
  const deviceInfo = {
    deviceId: internalDeviceCode,
    originalId: deviceId,
    deviceName: deviceName || `AutoReg Device ${deviceId}`,
    ip,
    port: port || 37777,
    username: username || 'admin',
    password: password || 'admin123',
    deviceType: deviceType || 2, // 2 = IPC
    channelNum: channelNum || 1,
    protocol: protocol || 'Dahua',
    status: 1, // online
    registeredAt: Date.now(),
    lastSeen: Date.now(),
    ...rest
  };

  ARS_DEVICES.set(deviceId, deviceInfo);

  console.log('[ARS] Device registered:', deviceId, 'from', ip);

  return envelope({
    success: true,
    deviceId: internalDeviceCode,
    message: 'Device registered successfully via ARS'
  });
});

// Device heartbeat/keepalive
app.post('/brms/api/v1.0/ars/keepalive', async (req, reply) => {
  const { deviceId } = req.body;
  if (!deviceId) return reply.code(400).send(envelope(null, 400, 'Missing deviceId'));

  const device = ARS_DEVICES.get(deviceId);
  if (!device) {
    return reply.code(404).send(envelope(null, 404, 'Device not registered'));
  }

  device.lastSeen = Date.now();
  device.status = 1; // online

  return envelope({ success: true, deviceId });
});

// Device unregister
app.post('/brms/api/v1.0/ars/unregister', async (req, reply) => {
  const { deviceId } = req.body;
  if (!deviceId) return reply.code(400).send(envelope(null, 400, 'Missing deviceId'));

  ARS_DEVICES.delete(deviceId);
  return envelope({ success: true, message: 'Device unregistered' });
});

// List ARS registered devices
app.post('/brms/api/v1.0/ars/list', { preHandler: auth }, async () => {
  const devices = Array.from(ARS_DEVICES.values()).map(d => ({
    deviceId: d.deviceId,
    originalId: d.originalId,
    deviceName: d.deviceName,
    ip: d.ip,
    port: d.port,
    deviceType: d.deviceType,
    channelNum: d.channelNum,
    status: d.status,
    registeredAt: d.registeredAt,
    lastSeen: d.lastSeen
  }));
  return envelope({ devices });
});

// Get ARS device info for tree integration
app.post('/brms/api/v1.0/ars/device-info', { preHandler: auth }, async (req) => {
  const { deviceId } = req.body;
  const device = ARS_DEVICES.get(deviceId);
  if (!device) {
    return envelope(null, 404, 'Device not found');
  }
  return envelope({
    deviceCode: device.deviceId,
    deviceName: device.deviceName,
    status: device.status,
    deviceType: device.deviceType,
    ip: device.ip,
    port: device.port,
    protocol: device.protocol,
    username: device.username,
    channelNum: device.channelNum,
    alarmInNum: 1,
    alarmOutNum: 1,
    diskNum: 0,
    supportP2P: false,
    supportRTSPS: false,
    supportMulticast: false
  });
});

// ===== HEALTH =====
app.get('/health', async () => ({ status: 'ok', version: '0.3.0', realm: REALM, rtspPort: RTSP_PORT, publicHost: PUBLIC_HOST, mediamtxUrl: MEDIAMTX_URL }));

// ===== WEBSOCKET SERVER =====
function createWebSocketServer(httpsServer) {
  const wss = new WebSocketServer({ server: httpsServer, path: '/brms/api/v1.0/event/ws' });

  wss.on('connection', (ws, req) => {
    // Verify token from query string or headers
    const url = new URL(req.url, `https://${req.headers.host}`);
    const token = url.searchParams.get('token') || req.headers['x-subject-token'];

    if (!token || !TOKENS.has(token)) {
      ws.close(4001, 'Unauthorized');
      return;
    }

    console.log('[WS] Client connected:', req.socket.remoteAddress);
    WS_CLIENTS.add(ws);

    ws.on('close', () => {
      WS_CLIENTS.delete(ws);
      console.log('[WS] Client disconnected');
    });

    ws.on('error', (err) => {
      console.log('[WS] Error:', err.message);
      WS_CLIENTS.delete(ws);
    });

    // Send welcome message
    ws.send(JSON.stringify({ type: 'WELCOME', message: 'Event WebSocket connected' }));
  });

  console.log('WebSocket Server listening on wss://0.0.0.0:' + HTTPS_PORT + '/brms/api/v1.0/event/ws');
  return wss;
}

async function start() {
  try {
    await app.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`BRMS Gateway listening on http://0.0.0.0:${PORT}`);

    let httpsServer = null;
    if (USE_HTTPS) {
      httpsServer = https.createServer({
        key: fs.readFileSync(SSL_KEY),
        cert: fs.readFileSync(SSL_CERT)
      }, async (req, res) => {
        const chunks = [];
        for await (const chunk of req) {
          chunks.push(chunk);
        }
        const body = Buffer.concat(chunks).toString('utf8');

        try {
          const response = await app.inject({
            method: req.method,
            url: req.url,
            payload: body,
            headers: req.headers
          });
          res.statusCode = response.statusCode;
          Object.entries(response.headers).forEach(([k, v]) => res.setHeader(k, v));
          res.end(response.body);
        } catch (err) {
          console.error('HTTPS proxy error:', err);
          res.statusCode = 500;
          res.end('Internal Server Error');
        }
      });

      await new Promise((resolve, reject) => {
        const server = httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
          console.log(`BRMS Gateway listening on https://0.0.0.0:${HTTPS_PORT}`);
          resolve();
        });
        server.on('error', reject);
      });

      // Start WebSocket server on same HTTPS server
      createWebSocketServer(httpsServer);
    }

    const udp = dgram.createSocket('udp4');
    udp.on('message', (msg, rinfo) => {
      const text = msg.toString().trim();
      console.log(`[UDP 18800] ${rinfo.address}:${rinfo.port} -> ${text}`);
      app.inject({ method: 'POST', url: '/brms/api/v1.0/event/push', payload: { raw: text, from: rinfo.address }, headers: { 'X-Subject-Token': 'internal' } });
    });
    udp.bind(18800, '0.0.0.0', () => console.log('UDP Alarm Ingest listening on 0.0.0.0:18800'));

    const udp2 = dgram.createSocket('udp4');
    udp2.bind(19800, '0.0.0.0', () => console.log('UDP Alarm Backup listening on 0.0.0.0:19800'));
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

start();