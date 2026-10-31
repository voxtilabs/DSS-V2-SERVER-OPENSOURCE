import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = Fastify({ logger: true });
await app.register(cors, { origin: true });

const REALM = process.env.REALM || 'DSS-V2-LAB';
const PORT = parseInt(process.env.PORT || '11443', 10);
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '1443', 10);
const RTSP_PORT = parseInt(process.env.RTSP_PORT || '9100', 10);
const PUBLIC_HOST = process.env.PUBLIC_HOST || '127.0.0.1';
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
  // Use PUBLIC_HOST for external clients
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${channelId}?token=${token}`;
  // Store session for RTSP server validation
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now() });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1', vkId, vkValue: genToken().slice(0, 16),
    hlsUrl: `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`,
    fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
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

// ===== P2P STATUS =====
app.get('/brms/api/v1.0/p2p/status', { preHandler: auth }, async () => envelope({
  status: 'available',
  easy4ip: 'www.easy4ip.com',
  profile: 'tools'
}));

// ===== HEALTH =====
app.get('/health', async () => ({ status: 'ok', version: '0.2.0', realm: REALM, rtspPort: RTSP_PORT, publicHost: PUBLIC_HOST }));

// ===== RTSP SERVER =====
function createRtspServer() {
  const server = net.createServer((socket) => {
    let buffer = '';
    console.log('[RTSP] Client connected:', socket.remoteAddress, socket.remotePort);

    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      // Process complete RTSP requests (separated by double CRLF)
      while (buffer.includes('\r\n\r\n')) {
        const endIdx = buffer.indexOf('\r\n\r\n');
        const request = buffer.slice(0, endIdx + 4);
        buffer = buffer.slice(endIdx + 4);

        const lines = request.split('\r\n');
        if (lines.length === 0) continue;
        const requestLine = lines[0];
        const [method, url, version] = requestLine.split(' ');

        // Parse headers
        const headers = {};
        for (let i = 1; i < lines.length - 1; i++) {
          const colonIdx = lines[i].indexOf(':');
          if (colonIdx > 0) {
            const key = lines[i].slice(0, colonIdx).trim().toLowerCase();
            const value = lines[i].slice(colonIdx + 1).trim();
            headers[key] = value;
          }
        }

        // Extract token from URL query
        const urlObj = new URL(`http://localhost${url}`);
        const token = urlObj.searchParams.get('token');
        const channelId = urlObj.pathname.slice(1); // remove leading /

        console.log('[RTSP]', method, url, 'from', socket.remoteAddress);

        let response = '';
        if (method === 'OPTIONS') {
          response = 'RTSP/1.0 200 OK\r\nCSeq: ' + (headers.cseq || '1') + '\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n';
        } else if (method === 'DESCRIBE') {
          // Validate token
          const session = RTSP_SESSIONS.get(token);
          if (!session) {
            response = 'RTSP/1.0 401 Unauthorized\r\nCSeq: ' + (headers.cseq || '1') + '\r\n\r\n';
          } else {
            // Generate SDP with H265
            const sdp = `v=0\r
o=- ${session.session} 1 IN IP4 ${PUBLIC_HOST}\r
s=${channelId}\r
t=0 0\r
a=control:*\r
m=video 0 RTP/AVP 96\r
a=rtpmap:96 H265/90000\r
a=control:track1\r
`;
            response = 'RTSP/1.0 200 OK\r\nCSeq: ' + (headers.cseq || '1') + '\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://' + PUBLIC_HOST + ':' + RTSP_PORT + '/' + channelId + '/\r\nContent-Length: ' + Buffer.byteLength(sdp) + '\r\n\r\n' + sdp;
          }
        } else if (method === 'SETUP') {
          response = 'RTSP/1.0 200 OK\r\nCSeq: ' + (headers.cseq || '1') + '\r\nTransport: RTP/AVP;unicast;client_port=5000-5001;server_port=6000-6001\r\nSession: ' + (session?.session || 'mock') + '\r\n\r\n';
        } else if (method === 'PLAY') {
          response = 'RTSP/1.0 200 OK\r\nCSeq: ' + (headers.cseq || '1') + '\r\nSession: ' + (session?.session || 'mock') + '\r\nRange: npt=0.000-\r\n\r\n';
        } else if (method === 'TEARDOWN') {
          response = 'RTSP/1.0 200 OK\r\nCSeq: ' + (headers.cseq || '1') + '\r\nSession: ' + (session?.session || 'mock') + '\r\n\r\n';
        } else {
          response = 'RTSP/1.0 405 Method Not Allowed\r\nCSeq: ' + (headers.cseq || '1') + '\r\n\r\n';
        }

        socket.write(response);
      }
    });

    socket.on('error', (err) => {
      console.log('[RTSP] Client error:', err.message);
    });

    socket.on('close', () => {
      console.log('[RTSP] Client disconnected');
    });
  });

  server.listen(RTSP_PORT, '0.0.0.0', () => {
    console.log(`RTSP Server listening on 0.0.0.0:${RTSP_PORT}`);
  });

  return server;
}

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

    // Start RTSP server
    createRtspServer();

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