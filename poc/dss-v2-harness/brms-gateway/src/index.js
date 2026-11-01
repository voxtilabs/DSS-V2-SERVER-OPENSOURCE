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
    query: req.query
  };

  console.log('[REQ]', JSON.stringify(logEntry));

  // Store for response logging
  req.logEntry = logEntry;
});

// req.body is parsed after onRequest, so bodies are captured here ([REQ-BODY]).
// This is how we discover the client's exact authorize contract
// (encryptType / digestPassword / publicKey field names) on the next run.
app.addHook('preValidation', async (req) => {
  if (req.body !== undefined) {
    req.logEntry.body = req.body;
    console.log('[REQ-BODY]', JSON.stringify({ method: req.method, url: req.url, body: req.body }));
  }
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
const HTTPS_PORT_2 = parseInt(process.env.HTTPS_PORT_2 || '9443', 10);
const RTSP_PORT = parseInt(process.env.RTSP_PORT || '9100', 10);
const ARS_PORT = parseInt(process.env.ARS_PORT || '9500', 10);
const SIP_PORT = parseInt(process.env.SIP_PORT || '5080', 10);
const PUBLIC_HOST = process.env.PUBLIC_HOST || '127.0.0.1';
const MEDIAMTX_URL = process.env.MEDIAMTX_URL || 'rtsp://mediamtx:8554';
const SSL_KEY = process.env.SSL_KEY || '/certs/key.pem';
const SSL_CERT = process.env.SSL_CERT || '/certs/cert.pem';
const SSL_KEY_2 = process.env.SSL_KEY_2 || '/certs/key.pem';
const SSL_CERT_2 = process.env.SSL_CERT_2 || '/certs/cert_9443.pem';
const USE_HTTPS = process.env.HTTPS === 'true';

const TOKENS = new Map();
const PENDING = new Map();

// RTSP session management
const RTSP_SESSIONS = new Map();
const WS_CLIENTS = new Set();

// ===== ARS TCP Binary Protocol (DVRIP/DHIP) =====
// Dahua Auto Register Service - TCP 9500 (VMS_ARCMS.exe)
// DVRIP/DHIP Protocol: 32-byte header + payload
const DHIP_MAGIC = 0x44484950; // "DHIP" = 0x44484950
const DHIP_CMD = {
  REGISTER: 0x0001,
  HEARTBEAT: 0x0002,
  COMMAND: 0x0003,
  VIDEO_REQUEST: 0x0004,
  LOGOUT: 0x0005,
  CONFIG: 0x0006,
  ALARM: 0x0007,
  PTZ: 0x0008,
  REGISTER_ACK: 0x8001,
  HEARTBEAT_ACK: 0x8002,
  COMMAND_ACK: 0x8003,
  VIDEO_ACK: 0x8004,
  LOGOUT_ACK: 0x8005,
};

// ARS TCP Sessions - persistent connections from NVRs
const ARS_TCP_SESSIONS = new Map();

// Parse DVRIP 32-byte header
function parseDHIPHeader(buffer) {
  if (buffer.length < 32) return null;
  const magic = buffer.readUInt32LE(0);
  const command = buffer.readUInt32LE(4);
  const sequence = buffer.readUInt32LE(8);
  const payloadLen = buffer.readUInt32LE(12);
  const sessionId = buffer.readUInt32LE(16);
  const deviceType = buffer.readUInt32LE(20);
  const flags = buffer.readUInt32LE(24);
  const reserved = buffer.readUInt32LE(28);
  return { magic, command, sequence, payloadLen, sessionId, deviceType, flags, reserved };
}

// Build DVRIP 32-byte header
function buildDHIPHeader(command, sequence, payloadLen, sessionId = 0, deviceType = 0, flags = 0) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(command, 4);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(payloadLen, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return header;
}

// Parse register payload (after 32-byte header)
function parseRegisterPayload(buffer) {
  let pos = 0;
  const readNullTerminated = (buf, start, maxLen = 128) => {
    let end = start;
    while (end < start + maxLen && end < buf.length && buf[end] !== 0) end++;
    const str = buf.slice(start, end).toString('utf8');
    return { str, nextOffset: end + 1 };
  };

  try {
    const deviceId = readNullTerminated(buffer, pos, 64);
    pos = deviceId.nextOffset;
    const deviceName = readNullTerminated(buffer, pos, 64);
    pos = deviceName.nextOffset;
    const deviceType = buffer.readUInt16LE(pos); pos += 2;
    const channelCount = buffer.readUInt16LE(pos); pos += 2;
    const ip = readNullTerminated(buffer, pos, 64);
    pos = ip.nextOffset;
    const port = buffer.readUInt16LE(pos); pos += 2;
    const username = readNullTerminated(buffer, pos, 64);
    pos = username.nextOffset;
    const password = readNullTerminated(buffer, pos, 64);
    pos = password.nextOffset;
    const mac = buffer.slice(pos, pos + 6).toString('hex').match(/.{2}/g)?.join(':') || '';
    pos += 6;
    const firmware = readNullTerminated(buffer, pos, 64);

    return {
      deviceId: deviceId.str || `NVR-${Date.now()}`,
      deviceName: deviceName.str || `NVR-${Date.now()}`,
      deviceType: deviceType || 2,
      channelCount: channelCount || 1,
      ip: ip.str || 'unknown',
      port: port || 37777,
      username: username.str || 'admin',
      password: password.str || 'admin123',
      mac: '',
      firmware: firmware.str || 'unknown'
    };
  } catch (e) {
    console.log('[ARS] Parse payload error:', e.message);
    return {
      deviceId: `NVR-${Date.now()}`,
      deviceName: `NVR-${Date.now()}`,
      deviceType: 2,
      channelCount: 1,
      ip: 'unknown',
      port: 37777,
      username: 'admin',
      password: 'admin123',
      mac: '',
      firmware: 'unknown'
    };
  }
}

// Build DHIP response header
function buildDHIPResponse(command, sequence, payloadLen = 0, sessionId = 0) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(command, 4);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(payloadLen, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return header;
}

// Create register ACK response
function createRegisterAck(sequence, deviceId) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(DHIP_CMD.REGISTER_ACK, 4);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return Buffer.concat([header, Buffer.from(deviceId + '\0', 'utf8')]);
}

// Create heartbeat ACK
function createHeartbeatAck(sequence) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(DHIP_CMD.HEARTBEAT_ACK, 4);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return header;
}

// Create logout ACK
function createLogoutAck(sequence) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(DHIP_CMD.LOGOUT_ACK, 4);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return header;
}

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genRandomKey() { return crypto.randomBytes(16).toString('hex'); }

// RSA keypair generated in memory at boot and handed to the client through the
// 401 challenge (publicKey field). Never written to disk or the repo
// (ADR-0003/0004). generateKeyPairSync with both encodings returns PEM strings.
const SERVER_RSA = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' }
});
const SERVER_PUB_PEM = SERVER_RSA.publicKey;

function envelope(data, code = 1000, desc = 'Success') {
  return { code, desc, data };
}

// ===== AUTH =====
// Authorize-200 contract (DPSDK Account.User.SecondLogin parser): data.token is
// the only required key; real DSS also mirrors the SecondLogin key cluster
// (versionInfo{updateUrl,patchUrl,lastVersion}, serviceAbilty, loginIpChanged,
// passwordRemainValidityPeriod, ...). Unknown keys are ignored by the client.
function buildLoginSuccess(userName) {
  const token = genToken();
  TOKENS.set(token, { userName, expires: Date.now() + 86400000 });
  return {
    token,
    duration: 86400,
    userId: '1',
    versionInfo: { updateUrl: '', patchUrl: '', lastVersion: DEFAULT_SERVER_VERSION },
    lastLoginIp: '',
    loginIpChanged: '0',
    passwordRemainValidityPeriod: '0',
    enablePasswordValidityPeriod: '0',
    tokenRate: '0',
    serviceAbilty: '',
    emapUrl: '',
    sipNum: '',
    sipPassword: ''
  };
}

function purgeExpiredPending() {
  for (const [k, v] of PENDING) if (Date.now() > v.expires) PENDING.delete(k);
}

// Strict mock handshake (e2e / harness): userName-only -> 401 challenge, then a
// signature over md5(md5(user:realm:md5(md5(pwd)))):randomKey. Real-client
// bodies (encryptType/digestPassword shape) are accepted deliberately — the
// exact digest formula is still being captured via [REQ-BODY] logging, and a
// hard rejection would leave the client stuck instead of revealing the field
// names in the next trace.
async function authorizeHandler(req, reply) {
  const b = req.body || {};
  const strict = b.userName && b.challengeKey && b.randomKey && b.signature && PENDING.has(b.challengeKey);
  if (strict) {
    const pending = PENDING.get(b.challengeKey);
    if (pending && pending.randomKey === String(b.randomKey)) {
      const temp = doubleMd5(String(b.userName), 'admin123');
      const expected = makeSig(String(b.userName), REALM, temp, String(b.randomKey));
      if (String(b.signature) === expected) {
        PENDING.delete(b.challengeKey);
        return envelope(buildLoginSuccess(String(b.userName)));
      }
    }
    return reply.code(401).send(envelope(null, 401, 'bad signature'));
  }
  // LoginFirstTime: challenge request (no digest/signature yet). The 401 data
  // contract per the DPSDK parser is {encryptType, randomKey, publicKey, realm}:
  // encryptType starting with "MD5" selects the digest path; anything else
  // selects RSA against publicKey. challengeKey is our legacy harness field
  // (extra keys are ignored by the client parser — dual-key strategy).
  if (b.userName && !b.signature && !b.digestPassword) {
    purgeExpiredPending();
    const rk = genRandomKey();
    const key = 'pending-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    PENDING.set(key, { realm: REALM, randomKey: rk, expires: Date.now() + 60000 });
    return reply.code(401).send(envelope({
      realm: REALM, randomKey: rk, encryptType: 'MD5', publicKey: SERVER_PUB_PEM, challengeKey: key
    }, 401, 'Unauthorized'));
  }
  // LoginSecondTime: accept the client's digest/MAC as-is and mint a session.
  return envelope(buildLoginSuccess(String(b.userName || 'admin')));
}

app.post('/brms/api/v1.0/accounts/authorize', authorizeHandler);
app.post('/videoService/accounts/authorize', authorizeHandler);
// Real client path (observed via [REQ-BODY], E-017): the Qt stack of the DSS
// desktop client logs in through the admin API base with
// {userName, ipAddress, clientType} — the same DPSDK LoginFirstTime chain.
app.post('/admin/API/accounts/authorize', authorizeHandler);
app.post('/admin/api/accounts/authorize', authorizeHandler);

// ===== VERSION / PLATFORM INFO (pre-login contract, DSS Desktop Client WINPC_V2) =====
// Real DSS platform format: V<major>.<minor>.0000000.0.R.<yyyymmdd>.<epoch-seconds>
// The desktop client compares its own version against data.version; a mismatch makes it
// abort with "Client Version does not match" BEFORE sending the authorize handshake.
const CLIENT_VERSIONS = {
  '8.000': 'V8.000.0000000.0.R.20210506.1742860800',
  '8.002': 'V8.002.0000000.0.R.20221222.1742860800',
  '8.004': 'V8.004.0000000.0.R.20240622.1742860800',
  '8.006': 'V8.006.0000000.0.R.20250307.1741354948',
  '8.008': 'V8.008.0000000.0.R.20260326.1774533954',
  '8.009': 'V8.009.0000000.0.R.20261015.1774533954'
};
// Default pinned to the deployed desktop client (DSS Client 8.006.0000000).
const DEFAULT_SERVER_VERSION = process.env.DSS_PROTOCOL_VERSION || CLIENT_VERSIONS['8.006'];

function selectPlatformVersion(req) {
  // 1) explicit query hint (?clientVersion=8.006 / V8.006...)
  // 2) User-Agent scan (desktop client sends no version; other consumers may)
  // 3) env default pinned to the deployed client fleet
  let probe = String((req.query && (req.query.clientVersion || req.query.version)) || '');
  if (!probe) probe = String(req.headers['user-agent'] || '');
  for (const [k, v] of Object.entries(CLIENT_VERSIONS)) {
    if (probe.includes('V' + k) || probe.includes(k.replace('.', ''))) return v;
  }
  return DEFAULT_SERVER_VERSION;
}

app.get('/videoService/version', async (req) => {
  const softwareVersion = selectPlatformVersion(req);
  // DPSDK CheckServerType parser (RestLogicaVSL.cpp). data.platform decides the
  // server type: "DSS Enterprise"=1, "DSS Express"=3, "DSS 4004S2"=4, anything
  // else=2 (DSS Pro default). data.softwareVersion -> platformVersion (About
  // dialog). data.protocolVersion must be "1.0.1" (code 101) or "1.1.0"
  // (code 110); any other value degrades the client to protocol code 0.
  // securityVersion/patchVersion/compatVersion/baseVersion/copyright are
  // parsed-and-logged only. The legacy `version` key stays for our harness.
  return envelope({
    version: softwareVersion,
    platform: 'DSS Pro',
    softwareVersion,
    protocolVersion: '1.1.0',
    copyright: 'Copyright © 2020 Zhejiang Dahua Technology Co., Ltd.',
    patchVersion: '',
    baseVersion: '',
    compatVersion: '',
    securityVersion: ''
  });
});

// Upgrade check endpoint - never forces an upgrade; mirrors the platform version
function upgradeableHandler(req) {
  return envelope({
    upgradeable: false,
    version: selectPlatformVersion(req),
    downloadUrl: '',
    releaseNote: ''
  });
}
// The DPSDK stack probes /v1.1/upgrade/... while the Qt stack probes the same
// check under /brms/api/v1.1/upgrade/... (observed [REQ] E-017).
app.get('/v1.1/upgrade/check/upgradeable', upgradeableHandler);
app.get('/brms/api/v1.1/upgrade/check/upgradeable', upgradeableHandler);

// Config-service environment probe from the Qt pre-login flow (observed with
// body {}). Exact result shape unknown — code 1000 with pass keys; the client
// tolerates extra fields.
app.post('/cfgs/api/v1.1/system/environment/runtime/check', async () => envelope({
  result: 'pass',
  status: 'ok',
  pass: true
}));

// Initialize status: PUBLIC pre-login endpoint in real DSS. The desktop client
// queries it without a token before authorize; a 401 makes the client abort with
// "failed to establish the service address link".
// DPSDK GetUserPWDState: pIsModifyed = (strcmp(data.status, "1") == 0) —
// "1" means the default admin password is already modified, so the client skips
// the first-run wizard (initialize + question/list flow) and goes to login.
app.get('/brms/api/v1.1/account/initialize/status', async () => envelope({
  initialized: true,
  status: '1'
}));

// ===== SECURITY / WIZARD CHAIN (RAM-only, exercised when the wizard runs) =====
const SECURITY_QUESTIONS = [
  { questionId: '1', description: 'What is your mother\'s surname?' },
  { questionId: '2', description: 'Which was your first school?' },
  { questionId: '3', description: 'Which is your favorite city?' }
];
// Wizard-set passwords never leave process memory (ADR-0003/0004).
const PASSWORD_STORE = new Map();

// question/list (Dpsdk::CDpsdkManager::GetUserQuestionList): items are
// [{questionId:"<N>" (string, atoi'd), description:"..."}]; a randomKey
// companion field is expected alongside the list. Both `questionList` and
// `list` wrappers are provided (dual-key strategy).
const QUESTION_LIST_PATHS = [
  '/brms/api/v1.1/account/security/question/list',
  '/brms/api/v1.1/account/question/list',
  '/brms/api/v1.0/account/security/question/list',
  '/brms/api/v1.0/security/question/list'
];
for (const p of QUESTION_LIST_PATHS) {
  app.get(p, async () => envelope({ questionList: SECURITY_QUESTIONS, list: SECURITY_QUESTIONS, randomKey: genRandomKey() }));
}

// public-key/generate (DPSDK UpdatePublicKey/VerifyFirstTime): the response must
// carry a randomKey (string); we mirror the server public key as well.
const PUBKEY_PATHS = [
  '/brms/api/v1.1/account/public-key/generate',
  '/brms/api/v1.0/account/public-key/generate',
  '/brms/api/v1.1/public-key/generate',
  '/brms/api/v1.0/public-key/generate'
];
for (const p of PUBKEY_PATHS) {
  app.post(p, async () => envelope({ randomKey: genRandomKey(), publicKey: SERVER_PUB_PEM }));
}

// Remaining wizard-chain stubs (secret delivery / password check / answers).
// Exact response shapes are still unknown — kept minimal with code 1000.
const WIZARD_SUFFIXES = ['secret/deliver', 'password/check', 'question/answer'];
const WIZARD_BASES = ['/brms/api/v1.1/account/', '/brms/api/v1.0/account/', '/brms/api/v1.1/accounts/', '/brms/api/v1.0/accounts/'];
for (const base of WIZARD_BASES) {
  for (const suffix of WIZARD_SUFFIXES) {
    app.post(base + suffix, async () => envelope({ success: true }));
  }
  app.get(base + 'password/check', async () => envelope({ success: true }));
}

// account/initialize (wizard finish): stash the chosen password in RAM only.
const INIT_PATHS = [
  '/brms/api/v1.1/account/initialize', '/brms/api/v1.0/account/initialize',
  '/brms/api/v1.1/accounts/initialize', '/brms/api/v1.0/accounts/initialize'
];
for (const p of INIT_PATHS) {
  app.post(p, async (req) => {
    const b = req.body || {};
    if (b.userName) PASSWORD_STORE.set(String(b.userName), String(b.password ?? ''));
    return envelope({ status: '1' });
  });
}

// ===== ADMIN/API RPC DISPATCHER (BRM.* family, method-in-body, E-018) =====
// Observed client call:
//   POST /admin/API/BRM/Config/GetMqConfig
//   {clientType, clientMac, clientPushId, project:"PSDK",
//    method:"BRM.Config.GetMqConfig", data:{optional:""}}
// The DPSDK parser of the response (0x180a488e0) exposes the exact keys:
//   method, SessionId, UseMqFlag, MQConfig, MQUser, MQPwd, UserId, GroupId,
//   SSLEnable, UnSSLPort, CertificatePath, ProtocolVersion, TopicInfos.
// UseMqFlag=0 keeps the client on its HTTP event path instead of connecting to
// an MQTT broker we do not run yet. `info` is the observed wrapper key; we
// return it both at root level and inside data (dual-key strategy).
function rpcEnvelope(method, data) {
  return { code: 1000, desc: 'Success', method, info: data, data };
}

async function brmRpcHandler(req) {
  const b = req.body || {};
  const method = b.method || `BRM.${req.params.ns}.${req.params.fn}`;
  if (method === 'BRM.Config.GetMqConfig') {
    return rpcEnvelope(method, {
      method,
      SessionId: String(b.clientPushId || ''),
      UseMqFlag: 0,
      MQConfig: '',
      MQUser: '',
      MQPwd: '',
      UserId: '1',
      GroupId: '',
      SSLEnable: 0,
      UnSSLPort: 0,
      CertificatePath: '',
      ProtocolVersion: 0,
      TopicInfos: []
    });
  }
  return rpcEnvelope(method, {});
}

app.post('/admin/API/BRM/:ns/:fn', brmRpcHandler);
app.post('/admin/api/BRM/:ns/:fn', brmRpcHandler);

function auth(req, reply, done) {
  const token = req.headers['x-subject-token'];
  if (!token || !TOKENS.has(token)) return reply.code(401).send(envelope(null, 401, 'unauthorized'));
  const t = TOKENS.get(token);
  if (Date.now() > t.expires) { TOKENS.delete(token); return reply.code(401).send(envelope(null, 401, 'expired')); }
  req.user = t; done();
}

async function keepaliveHandler() { return envelope({ success: true }); }
async function currentHandler(req) {
  return envelope({
    token: req.headers['x-subject-token'],
    userId: '1',
    username: req.user.userName,
    userType: '1',
    topLevel: '1'
  });
}
async function unauthorizeHandler(req) { TOKENS.delete(req.headers['x-subject-token']); return envelope({ success: true }); }

app.post('/brms/api/v1.0/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.get('/brms/api/v1.0/accounts/current', { preHandler: auth }, currentHandler);
app.post('/brms/api/v1.0/accounts/unauthorize', { preHandler: auth }, unauthorizeHandler);
// Mirrors on the admin API base (client Qt stack may call these after login).
app.post('/admin/API/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.get('/admin/API/accounts/current', { preHandler: auth }, currentHandler);
app.post('/admin/API/accounts/unauthorize', { preHandler: auth }, unauthorizeHandler);

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
  const mediamtxPath = 'test';
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${mediamtxPath}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now() });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1', vkId, vkValue: genToken().slice(0, 16),
    hlsUrl, fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
  });
});
app.post('/brms/api/v1.0/MTS/Video/StopVideo', { preHandler: auth }, async (req) => {
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
  const { raw, from } = req.body;
  const event = { type: 'ALARM', source: from, raw, timestamp: new Date().toISOString() };
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
const P2P_DEVICES = new Map();

app.post('/brms/api/v1.0/device/p2p-register', { preHandler: auth }, async (req, reply) => {
  const { sn, user, password, name, channels = 1 } = req.body;
  if (!sn) return reply.code(400).send(envelope(null, 400, 'Missing SN'));
  
  if (P2P_DEVICES.has(sn)) {
    const existing = P2P_DEVICES.get(sn);
    return envelope({
      deviceId: existing.deviceId,
      channelIds: existing.channelIds,
      p2pStatus: 'already_registered',
      message: 'Device already registered'
    });
  }
  
  const deviceId = 'P2P-' + genToken().slice(0, 12);
  const channelIds = [];
  for (let i = 1; i <= channels; i++) {
    channelIds.push(`${deviceId}$${i}$0$0`);
  }
  
  P2P_DEVICES.set(sn, {
    sn, deviceId, name: name || `P2P Device ${sn}`, user: user || 'admin',
    channelIds, registeredAt: Date.now(), status: 'online'
  });
  
  return envelope({
    deviceId, channelIds, p2pStatus: 'registered',
    message: 'Device registered successfully. P2P tunnel creation simulated.'
  });
});

app.post('/brms/api/v1.0/device/p2p-unregister', { preHandler: auth }, async (req, reply) => {
  const { sn } = req.body;
  if (!sn) return reply.code(400).send(envelope(null, 400, 'Missing SN'));
  P2P_DEVICES.delete(sn);
  return envelope({ success: true, message: 'Device unregistered' });
});

app.post('/brms/api/v1.0/device/p2p-list', { preHandler: auth }, async () => {
  const devices = Array.from(P2P_DEVICES.values()).map(d => ({
    sn: d.sn, deviceId: d.deviceId, name: d.name, status: d.status,
    channelIds: d.channelIds, registeredAt: d.registeredAt
  }));
  return envelope({ devices });
});

// ===== ARS (Auto Register Service) - Device Auto-Registration =====
const ARS_DEVICES = new Map();

app.post('/brms/api/v1.0/ars/register', async (req, reply) => {
  const { deviceId, deviceName, ip, port, username, password, deviceType, channelNum, protocol, ...rest } = req.body;
  if (!deviceId || !ip) return reply.code(400).send(envelope(null, 400, 'Missing deviceId or ip'));
  
  if (ARS_DEVICES.has(deviceId)) {
    const existing = ARS_DEVICES.get(deviceId);
    existing.lastSeen = Date.now();
    existing.ip = ip;
    return envelope({ success: true, deviceId: existing.deviceId, message: 'Device already registered, updated', registered: true });
  }
  
  const internalDeviceCode = deviceId.startsWith('ARS-') ? deviceId : 'ARS-' + deviceId;
  const deviceInfo = {
    deviceId: internalDeviceCode, originalId: deviceId, deviceName: deviceName || `AutoReg Device ${deviceId}`,
    ip, port: port || 37777, username: username || 'admin', password: password || 'admin123',
    deviceType: deviceType || 2, channelNum: channelNum || 1, protocol: protocol || 'Dahua',
    status: 1, registeredAt: Date.now(), lastSeen: Date.now(), ...rest
  };
  
  ARS_DEVICES.set(deviceId, deviceInfo);
  console.log('[ARS] Device registered:', deviceId, 'from', ip);
  return envelope({ success: true, deviceId: internalDeviceCode, message: 'Device registered successfully via ARS' });
});

app.post('/brms/api/v1.0/ars/keepalive', async (req, reply) => {
  const { deviceId } = req.body;
  if (!deviceId) return reply.code(400).send(envelope(null, 400, 'Missing deviceId'));
  const device = ARS_DEVICES.get(deviceId);
  if (!device) return reply.code(404).send(envelope(null, 404, 'Device not registered'));
  device.lastSeen = Date.now(); device.status = 1;
  return envelope({ success: true, deviceId });
});

app.post('/brms/api/v1.0/ars/unregister', async (req, reply) => {
  const { deviceId } = req.body;
  if (!deviceId) return reply.code(400).send(envelope(null, 400, 'Missing deviceId'));
  ARS_DEVICES.delete(deviceId);
  return envelope({ success: true, message: 'Device unregistered' });
});

app.post('/brms/api/v1.0/ars/list', { preHandler: auth }, async () => {
  const devices = Array.from(ARS_DEVICES.values()).map(d => ({
    deviceId: d.deviceId, originalId: d.originalId, deviceName: d.deviceName,
    ip: d.ip, port: d.port, deviceType: d.deviceType, channelNum: d.channelNum,
    status: d.status, registeredAt: d.registeredAt, lastSeen: d.lastSeen
  }));
  return envelope({ devices });
});

app.post('/brms/api/v1.0/ars/device-info', { preHandler: auth }, async (req) => {
  const { deviceId } = req.body;
  const device = ARS_DEVICES.get(deviceId);
  if (!device) return envelope(null, 404, 'Device not found');
  return envelope({
    deviceCode: device.deviceId, deviceName: device.deviceName, status: device.status,
    deviceType: device.deviceType, ip: device.ip, port: device.port,
    protocol: device.protocol, username: device.username, channelNum: device.channelNum,
    alarmInNum: 1, alarmOutNum: 1, diskNum: 0,
    supportP2P: false, supportRTSPS: false, supportMulticast: false
  });
});

// ===== HEALTH =====
app.get('/health', async () => ({ status: 'ok', version: '0.4.0', realm: REALM, rtspPort: RTSP_PORT, publicHost: PUBLIC_HOST, mediamtxUrl: MEDIAMTX_URL, arsPort: ARS_PORT }));

// ===== WEBSOCKET SERVER =====
function createWebSocketServer(httpsServer) {
  const wss = new WebSocketServer({ server: httpsServer, path: '/brms/api/v1.0/event/ws' });
  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const token = url.searchParams.get('token') || req.headers['x-subject-token'];
    if (!token || !TOKENS.has(token)) { ws.close(4001, 'Unauthorized'); return; }
    console.log('[WS] Client connected:', req.socket.remoteAddress);
    WS_CLIENTS.add(ws);
    ws.on('close', () => { WS_CLIENTS.delete(ws); console.log('[WS] Client disconnected'); });
    ws.on('error', (err) => { console.log('[WS] Error:', err.message); WS_CLIENTS.delete(ws); });
    ws.send(JSON.stringify({ type: 'WELCOME', message: 'Event WebSocket connected' }));
  });
  console.log('WebSocket Server listening on wss://0.0.0.0:' + HTTPS_PORT + '/brms/api/v1.0/event/ws');
  return wss;
}

// ===== ARS TCP Binary Server (DVRIP/DHIP) =====
function createARSTCPServer() {
  console.log('[DEBUG] createARSTCPServer called, port:', ARS_PORT);
  const server = net.createServer((socket) => {
    const clientKey = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log('[ARS TCP] Client connected:', clientKey);
    
    let buffer = Buffer.alloc(0);
    let sequence = 0;
    
    const session = {
      socket,
      deviceId: null,
      sequence: 0,
      lastActivity: Date.now(),
      authenticated: false
    };
    
    ARS_TCP_SESSIONS.set(clientKey, session);
    
    socket.on('data', (data) => {
      session.lastActivity = Date.now();
      buffer = Buffer.concat([buffer, data]);
      
      // Process complete DVRIP packets (32-byte header + payload)
      while (buffer.length >= 32) {
        const header = parseDHIPHeader(buffer);
        if (!header) break;
        
        const totalLen = 32 + header.payloadLen;
        if (buffer.length < totalLen) break; // Wait for more data
        
        const payload = buffer.subarray(32, totalLen);
        buffer = buffer.subarray(totalLen);
        
        // Process command
        const { command, sequence, payloadLen, sessionId } = header;
        
        console.log('[ARS TCP] Command:', command.toString(16), 'Seq:', sequence, 'Payload:', payloadLen, 'from', socket.remoteAddress);
        
        switch (command) {
          case DHIP_CMD.REGISTER: {
            session.sequence = header.sequence;
            const deviceInfo = parseRegisterPayload(buffer.subarray(32, 32 + header.payloadLen));
            session.deviceId = deviceInfo.deviceId;
            session.authenticated = true;
            
            // Register device in ARS_DEVICES
            const internalDeviceCode = 'ARS-' + deviceInfo.deviceId;
            ARS_DEVICES.set(deviceInfo.deviceId, {
              deviceId: 'ARS-' + deviceInfo.deviceId,
              originalId: deviceInfo.deviceId,
              deviceName: deviceInfo.deviceName,
              ip: deviceInfo.ip,
              port: deviceInfo.port,
              username: deviceInfo.username,
              password: deviceInfo.password,
              deviceType: deviceInfo.deviceType,
              channelNum: deviceInfo.channelCount,
              protocol: 'Dahua',
              status: 1,
              registeredAt: Date.now(),
              lastSeen: Date.now()
            });
            
            console.log('[ARS TCP] Device registered:', deviceInfo.deviceId, 'from', socket.remoteAddress);
            
            // Send REGISTER_ACK
            const ack = createRegisterAck(header.sequence, deviceInfo.deviceId);
            socket.write(ack);
            break;
          }
          
          case DHIP_CMD.HEARTBEAT: {
            const ack = createHeartbeatAck(header.sequence);
            socket.write(ack);
            if (session.deviceId) {
              const device = ARS_DEVICES.get(session.deviceId);
              if (device) { device.lastSeen = Date.now(); device.status = 1; }
            }
            break;
          }
          
          case DHIP_CMD.LOGOUT: {
            const ack = createLogoutAck(header.sequence);
            socket.write(ack);
            if (session.deviceId) {
              ARS_DEVICES.delete(session.deviceId);
            }
            socket.end();
            break;
          }
          
          default: {
            console.log('[ARS TCP] Unknown command:', command.toString(16));
            // Send generic ACK for unknown commands
            const ackHeader = buildDHIPResponse(command | 0x8000, header.sequence);
            socket.write(ackHeader);
          }
        }
      }
    });
    
    socket.on('error', (err) => {
      console.log('[ARS TCP] Client error:', err.message);
    });
    
    socket.on('close', () => {
      console.log('[ARS TCP] Client disconnected:', clientKey);
      if (session.deviceId) {
        const device = ARS_DEVICES.get(session.deviceId);
        if (device) { device.status = 0; device.lastSeen = Date.now(); }
      }
      ARS_TCP_SESSIONS.delete(clientKey);
    });
    
    // Heartbeat timeout check
    const heartbeatInterval = setInterval(() => {
      if (Date.now() - session.lastActivity > 120000) {
        console.log('[ARS TCP] Client timeout:', clientKey);
        socket.destroy();
        clearInterval(heartbeatInterval);
      }
    }, 30000);
    
    socket.on('close', () => clearInterval(heartbeatInterval));
  });
  
  server.on('error', (err) => {
    console.error('[ARS TCP] Server error:', err);
  });
  
  server.listen(ARS_PORT, '0.0.0.0', () => {
    console.log(`ARS TCP Server (DVRIP) listening on 0.0.0.0:${ARS_PORT}`);
  });
  return server;
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
        for await (const chunk of req) { chunks.push(chunk); }
        const body = Buffer.concat(chunks).toString('utf8');
        if (body) console.log('[REQ-RAW-BODY]', JSON.stringify({ url: req.url, body: body.slice(0, 4000) }));
        try {
          const response = await app.inject({ method: req.method, url: req.url, payload: body, headers: req.headers });
          res.statusCode = response.statusCode;
          Object.entries(response.headers).forEach(([k, v]) => res.setHeader(k, v));
          res.end(response.body);
        } catch (err) {
          console.error('HTTPS proxy error:', err);
          res.statusCode = 500; res.end('Internal Server Error');
        }
      });

      await new Promise((resolve, reject) => {
        const server = httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
          console.log(`BRMS Gateway listening on https://0.0.0.0:${HTTPS_PORT}`);
          resolve();
        });
        server.on('error', reject);
      });
      createWebSocketServer(httpsServer);
    }

    // Second HTTPS Server on port 9443 (Production DSS Server port)
    let httpsServer2 = null;
    if (USE_HTTPS && fs.existsSync(SSL_CERT_2)) {
      httpsServer2 = https.createServer({
        key: fs.readFileSync(SSL_KEY_2),
        cert: fs.readFileSync(SSL_CERT_2)
      }, async (req, res) => {
        const chunks = [];
        for await (const chunk of req) { chunks.push(chunk); }
        const body = Buffer.concat(chunks).toString('utf8');
        if (body) console.log('[REQ-RAW-BODY]', JSON.stringify({ url: req.url, body: body.slice(0, 4000) }));
        try {
          const response = await app.inject({ method: req.method, url: req.url, payload: body, headers: req.headers });
          res.statusCode = response.statusCode;
          Object.entries(response.headers).forEach(([k, v]) => res.setHeader(k, v));
          res.end(response.body);
        } catch (err) {
          console.error('HTTPS 9443 proxy error:', err);
          res.statusCode = 500; res.end('Internal Server Error');
        }
      });

      await new Promise((resolve, reject) => {
        const server = httpsServer2.listen(HTTPS_PORT_2, '0.0.0.0', () => {
          console.log(`BRMS Gateway listening on https://0.0.0.0:${HTTPS_PORT_2} (Production port)`);
          resolve();
        });
        server.on('error', reject);
      });
      createWebSocketServer(httpsServer2);
    }

    // Start ARS TCP Server (DVRIP/DHIP on port 9500)
    console.log('[DEBUG] Starting ARS TCP Server on port', ARS_PORT);
    createARSTCPServer();
    console.log('[DEBUG] ARS TCP Server creation returned');

    // SIP UDP 5080 Server (DSS Client intercom/voice registration)
    const sipUdp = dgram.createSocket('udp4');
    sipUdp.on('message', (msg, rinfo) => {
      const text = msg.toString().trim();
      console.log(`[SIP UDP 5080] ${rinfo.address}:${rinfo.port} -> ${text.substring(0, 200)}`);
      
      if (text.includes('REGISTER') && text.includes('SIP/2.0')) {
        // Parse SIP REGISTER request
        const lines = text.split('\r\n');
        const requestLine = lines[0];
        const headers = {};
        let callId = '';
        let fromTag = '';
        let toTag = '';
        let via = '';
        let contact = '';
        let cseq = '';
        
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('Via:')) via = line.substring(4).trim();
          else if (line.startsWith('From:')) {
            const match = line.match(/tag=([^;>]+)/);
            if (match) fromTag = match[1];
          } else if (line.startsWith('To:')) {
            // We'll add a tag in response
          } else if (line.startsWith('Call-ID:')) callId = line.substring(8).trim();
          else if (line.startsWith('CSeq:')) cseq = line.substring(5).trim();
          else if (line.startsWith('Contact:')) contact = line.substring(8).trim();
        }
        
        // Generate response tag
        const respTag = crypto.randomBytes(8).toString('hex');
        
        // Build SIP 200 OK response
        const response = [
          'SIP/2.0 200 OK',
          `Via: ${via};received=${rinfo.address};branch=z9hG4bK${crypto.randomBytes(8).toString('hex')}`,
          `From: <sip:8888881000@${PUBLIC_HOST}>;tag=${fromTag}`,
          `To: <sip:8888881000@${PUBLIC_HOST}>;tag=${respTag}`,
          `Call-ID: ${callId}`,
          `CSeq: ${cseq}`,
          `Contact: <sip:8888881000@${PUBLIC_HOST}:${SIP_PORT};transport=udp>`,
          'Expires: 3600',
          'Content-Length: 0',
          '', ''
        ].join('\r\n');
        
        sipUdp.send(response, rinfo.port, rinfo.address, (err) => {
          if (err) console.log('[SIP] Response error:', err.message);
          else console.log(`[SIP] 200 OK sent to ${rinfo.address}:${rinfo.port}`);
        });
      }
    });
    
    sipUdp.on('error', (err) => {
      console.error('[SIP UDP] Error:', err.message);
    });
    
    sipUdp.bind(SIP_PORT, '0.0.0.0', () => {
      console.log(`SIP UDP Server listening on 0.0.0.0:${SIP_PORT}`);
    });

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