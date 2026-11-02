import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import net from 'node:net';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
// E-024: Dahua DSS v1.1 catalog contracts (device categories, access
// protocols, manufacturers, channel capabilities). Evidence in the module.
import {
  DAHUA_AVAILABLE_SERVERS,
  DAHUA_CHANNEL_CAPABILITIES,
  DAHUA_SNMP_MANUFACTURERS,
  buildDeviceTypeResults,
  buildDictionaryResults
} from './e024-catalogs.js';
// E-025: device add/discovery, network/timezone/roles/functions/subsystems
// catalogs, real ONVIF + Easy4IP probes and the RAM-only device registry.
import {
  DEVICE_REGISTRY,
  DISCOVERED_DEVICES,
  normalizeDeviceInput,
  allChannels,
  buildAlertTypeListPayload,
  buildArsListPayload,
  buildDeviceAddBatchPayload,
  buildDeviceAddPayload,
  buildDeviceCheckExistPayload,
  buildDeviceDeleteBatchPayload,
  buildDeviceDiscoverAsyncBatchPayload,
  buildDeviceMoveBatchPayload,
  buildDevicePagePayload,
  buildDevicePasswordChangeBatchPayload,
  buildDeviceTimezoneUpdateBatchPayload,
  buildDeviceUnauthorizedPagePayload,
  buildDeviceRtspUrlPayload,
  buildDiscoverDeviceInitPayload,
  buildDiscoverDevicePagePayload,
  buildDiscoverDetailPayload,
  buildDiscoverJoinBatchPayload,
  buildDiscoverCostTimePayload,
  buildDiscoverSummaryPayload,
  buildFunctionAvailablePayload,
  buildNetworkListPayload,
  buildP2PStatusPayload,
  buildRolePagePayload,
  buildServerTimezonePayload,
  buildStatisticsCategoryPayload,
  buildSubsystemAvailablePayload,
  buildTimezoneListPayload,
  probeEasy4IP,
  probeEasy4IPReachability,
  probeOnvifDevice,
  registerArsDevice,
  seedInitialDevices,
  createDeviceRecord,
  persistDevice,
  loadDevicesFromDisk
} from './e025-devices.js';
// E-026: load persisted devices from disk so they survive restarts and
// appear in device/page, tree/*, statistics immediately.
loadDevicesFromDisk();
// E-026: ONVIF -> MediaMTX video bridge + missing FALLBACK routes
import {
  discoverOnvifStreamUri,
  configureMediaMTXPath,
  MEDIAMTX_CAMERA_PATH,
  MEDIAMTX_API_URL,
  FALLBACK_ROUTES
} from './e026-video.js';
// E-025: the mock camera is part of the device registry so /device/page,
// /tree/* and the statistics all report the same set of devices.
seedInitialDevices();
// E-028: /web/client-module/ now serves the REAL production DSS web bundle
// mirrored to web-module/ (see EV-078). No invented UI is served anywhere.

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ===== E-027: PROCESS-LEVEL FAULT BARRIERS =====
// The gateway was dying with "triggerUncaughtException (Error: aborted /
// ECONNRESET)" whenever an in-flight or upgraded socket closed mid-request.
// The native DSS Client then saw a dead server and rendered "Operation timed
// out". Log the full stack instead of killing the process.
process.on('unhandledRejection', (reason) => {
  const st = reason instanceof Error ? (reason.stack || reason.message) : String(reason);
  console.error('[E027-FATAL-BAR] unhandledRejection (process kept alive):\n' + st);
});
process.on('uncaughtException', (err) => {
  console.error('[E027-FATAL-BAR] uncaughtException (process kept alive):\n' + (err instanceof Error ? (err.stack || err.message) : String(err)));
});

// E-027 watchdog: detect event-loop stalls (the ONVIF poll hung with no
// request reaching Fastify's onRequest hook, so something between TLS and
// fastify starves the loop when it happens after a device add).
let __hb = Date.now();
setInterval(() => {
  const now = Date.now();
  const dt = now - __hb;
  if (dt > 800) console.error('[E027-WATCHDOG] event loop stalled ' + dt + 'ms');
  __hb = now;
}, 250);

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

  // E-024: Highlight dictionary/category/protocol/type requests
  const url = req.url || '';
  const isDictReq = /dictionary|category|protocol|manufacturer|device.type|channel.type|encode|connect.mode|alarm.type|protocol.type|device.status/i.test(url);
  const prefix = isDictReq ? '[DICT-REQ]' : '[REQ]';
  
  console.log(prefix, JSON.stringify(logEntry));

  // Store for response logging
  req.logEntry = logEntry;
});

// req.body is parsed after onRequest, so bodies are captured here ([REQ-BODY]).
// This is how we discover the client's exact authorize contract
// (encryptType / digestPassword / publicKey field names) on the next run.
app.addHook('preValidation', async (req) => {
  if (req.body !== undefined) {
    req.logEntry.body = req.body;
    const url = req.url || '';
    const isDictReq = /dictionary|category|protocol|manufacturer|device.type|channel.type|encode|connect.mode|alarm.type|protocol.type|device.status/i.test(url);
    const prefix = isDictReq ? '[DICT-BODY]' : '[REQ-BODY]';
    console.log(prefix, JSON.stringify({ method: req.method, url: req.url, body: req.body }));
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

// ===== E-023: COMPLETE master menu catalog (E-022 + MainFormPlugin/PluginFactory/real-index.js) =====
// 158 VALID Dahua menu codes (6-12 digits, prefixes 001-004,010,011).
// Source: 000003.ldb (151 real) + MainFormPlugin.dll strings + PluginFactory.dll exports + real-index.js catalog.
// E-023 FIX: REAL_FORBIDDEN_MENUS = [] ALWAYS (no filtering — admin user sees all).
// E-023 FIX: REAL_FUNCTION_CONFIG = ALL KEYS ENABLED (1/true) — nothing hidden.
const REAL_MENU_RIGHTS = [
  "001001","001001001","001001002","001002","001002001","001002002",
  "001003","001003001","001003002","001003003","001003004",
  "002001","002001001","002001002","002001003","002001003001","002001003002","002001003003","002001004",
  "002002","002003","002003001","002003002",
  "002004","002004001","002004002",
  "002005","002005001","002005002","002005002001","002005002002","002005003","002005003001","002005003002",
  "002006","002006001","002006002","002006003","002006004","002006005","002006007",
  "002007","002007001",
  "002008","002008001","002008001001","002008001002","002008001003","002008002","002008002001","002008002002","002008003","002008004","002008005",
  "002009","002009001","002009001001","002009001002","002009001003","002009001004","002009002","002009002001","002009002002","002009003",
  "002010","002010001","002010002",
  "002011","002011001","002011001001","002011001002","002011002","002011002001","002011003",
  "002012","002012001","002012002","002012003",
  "002013",
  "002015","002015001",
  "003001","003001001","003002","003003","003004","003005",
  "004001","004001001","004001001001","004001001002","004001002","004001003","004001005",
  "004002","004002001","004002002","004002004","004002005","004002005001","004002005002",
  "004003","004003001","004003002001",
  "004004","004004001","004004002","004004002002","004004002003","004004002004","004004003","004004003001","004004003003",
  "004005","004005001","004005001001","004005001002","004005001003","004005001004","004005001005",
  "004005002","004005002001","004005002002","004005002003",
  "004005003","004005003001","004005003002",
  "004005004","004005004001","004005004002",
  "004005005","004005006","004005007","004005008","004005009","004005010",
  "004006","004006001","004006002",
  "004007","004007001","004007001001","004007001002","004007002","004007003","004007004",
  "004008",
  "010001","010001001","010001002","010001003","010001004",
  "010002","010002001","010002002","010002003",
  "011001","011002"
];
const REAL_FORBIDDEN_MENUS = [];
// E-023: ALL functionConfig keys ENABLED (1/true) — nothing hidden from admin
const REAL_FUNCTION_CONFIG = {
  "visitor-appointment":1,"parking-lot-layer-enable":1,"channel-bind-audio":1,"displayP2PModule":1,"config-message-store-visitor":1,"import-export-person":1,"search-mpt":1,"license-upgrade-from-express-to-pro":1,"storage-incident":1,"storage-raid":1,"domain-user-sync":1,"config-message-store-video-intercom":1,"system":1,"config-message-store-people-counting":1,"person-freeze-operation-enable":1,"global-inter-door-lock":1,"parking-record":1,"link-ip-speaker":1,"config-types":"271,156,333,136,158,137,159,138,117,139,118,119,120,121,143,144,166,145,3,146,168,300,4,147,345,5,324,108,10002,10006,21","config-active-directory":1,"call-mode":1,"event-alarm-config-on-the-wall":1,"gis-map":1,"module-liftcontroll":1,"config-parking-lot-ext":1,"channel-record-plan":1,"config-message-store-pos":1,"config-email-server":1,"app-register-qrcode":1,"config-network-device-protocol":1,"module-entrance":1,"license-activation-status":1,"config-cardNo-enable":1,"acupick-support":1,"access-rule":1,"jiuzhou-protocol":1,"config-message-store-heatmap":1,"hot-standby-tip":1,"global-anti-passback":1,"snmp-protocol":1,"authentication-protocol":1,"config-message-store-face-recognition":1,"config-message-store-anpr":1,"config-message-store-vehicle":1,"config-message-store-crowd":1,"config-message-store-smoking":1,"config-message-store-fire":1,"config-message-store-license-plate":1
};
const MODULES_DEFAULT_MENU = {"002001":"002001001"};

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
    versionInfo: { updateUrl: '', patchUrl: '', lastVersion: 'V' + (DEFAULT_SERVER_VERSION.match(/\d+\.\d+\.\d+\.\d+/) || [DEFAULT_SERVER_VERSION.replace(/^V/, '')])[0] },
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
  // E-021 red-warning fix - compares decompiled from MainFormPlugin.dll
  // CLoginUI::Init (0x18015bbe0): the client regex-captures the first
  // `\d*\.\d*\.\d*\.\d*` group of its OWN process-arg version (DSS Client.exe
  // embeds "8.006.0000000.0.R.20250307") and formats the result as V%1 ->
  // SetClientMajorVersion("V8.006.0000000.0"). The server version is compared
  // against that V-prefixed major form, so softwareVersion now carries the
  // exact V%1(re) form while `version` keeps the byte-for-byte client literal.
  const clientSelfVersion = softwareVersion.replace(/^V/, '').replace(/\.\d{9,10}$/, '');
  const clientMajorV = 'V' + ((softwareVersion.match(/\d+\.\d+\.\d+\.\d+/) || [clientSelfVersion])[0]);
  const clientFixPack = (softwareVersion.match(/R\.(\d{8})/) || [])[1] || '';
  // DPSDK CheckServerType parser (RestLogicaVSL.cpp). data.platform decides the
  // server type: "DSS Enterprise"=1, "DSS Express"=3, "DSS 4004S2"=4, anything
  // else=2 (DSS Pro default). data.softwareVersion -> platformVersion (About
  // dialog). data.protocolVersion must be "1.0.1" (code 101) or "1.1.0"
  // (code 110); any other value degrades the client to protocol code 0.
  // data.version is the key the client compares its own build against.
  return envelope({
    version: clientSelfVersion,
    platform: 'DSS Pro',
    softwareVersion: clientMajorV,
    protocolVersion: '1.1.0',
    copyright: 'Copyright © 2020 Zhejiang Dahua Technology Co., Ltd.',
    patchVersion: clientFixPack,
    baseVersion: clientMajorV,
    compatVersion: clientMajorV,
    securityVersion: ''
  });
});

// Upgrade check endpoint - never forces an upgrade; mirrors the platform version
function upgradeableHandler(req) {
  // Same client self forms as /videoService/version (E-021 decompile).
  const selected = selectPlatformVersion(req);
  const clientMajorV = 'V' + ((selected.match(/\d+\.\d+\.\d+\.\d+/) || [selected.replace(/^V/, '')])[0]);
  return envelope({
    upgradeable: false,
    version: clientMajorV,
    serverVersion: selected,
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

// E-021: per-file user data blobs (webfav.xml, quickcmd.xml, siteInfo.xml...).
// RAM only - no persistence, no secrets.
const USER_FILES = new Map();

// ===== E-024: catalog payload builder shared by REST and BRMS RPC routes =====
// The native Qt client can reach the same catalogs through the BRMS RPC
// transport (DPSDK method names found in its string pool:
// BRMS.Dictionary.GetDictionaries / BRMS.Definition.GetDeviceTypes /
// BRMS.Definition.GetChannelCapabilities / BRMS.Config.GetSnmpManufacturers).
function e024CatalogPayload(method, body) {
  const rawTypes = body?.types ?? body?.data?.types ?? '';
  if (method === 'BRMS.Dictionary.GetDictionaries' || method === 'BRM.Dictionary.GetDictionaries') {
    const results = buildDictionaryResults(rawTypes);
    const flat = results.flatMap((r) => r.items.map((i) => ({ type: r.type, ...i })));
    return { results, items: results, list: flat, total: flat.length };
  }
  if (method === 'BRMS.Definition.GetDeviceTypes' || method === 'BRM.Definition.GetDeviceTypes') {
    const results = buildDeviceTypeResults();
    return { results, items: results, list: results, deviceTypes: results, total: results.length };
  }
  if (method === 'BRMS.Definition.GetChannelCapabilities' || method === 'BRM.Definition.GetChannelCapabilities') {
    const results = DAHUA_CHANNEL_CAPABILITIES;
    return { results, items: results, list: results, channelCapabilities: results, total: results.length };
  }
  if (method === 'BRMS.Config.GetSnmpManufacturers' || method === 'BRM.Config.GetSnmpManufacturers') {
    const results = DAHUA_SNMP_MANUFACTURERS;
    return { results, items: results, list: results, snmpManufacturerList: results, total: results.length };
  }
  if (method === 'BRMS.Server.GetAvailableServers' || method === 'BRM.Server.GetAvailableServers') {
    const results = DAHUA_AVAILABLE_SERVERS;
    return { results, items: results, list: results, serverList: results, total: results.length };
  }
  return null;
}

async function brmRpcHandler(req) {
  const b = req.body || {};
  const method = b.method || `BRM.${req.params.ns}.${req.params.fn}`;
  // E-024: catalog methods over the RPC transport.
  const catalog = e024CatalogPayload(method, b);
  if (catalog) return rpcEnvelope(method, catalog);

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

  // ===== E-021: RPC shapes (parsers contracted via REA/DPSDK + live trace) =====
  // GetMenuRights registrar row: menuType / forbiddenMenus / menuRights
  // (DPSDK string pool 0x180cd6f08). E-022: serve REAL menuRights from leveldb.
  if (method === 'BRM.User.GetMenuRights') return rpcEnvelope(method, { menuType: Number((b.data && b.data.menuType) || 2), menuRights: REAL_MENU_RIGHTS, rights: REAL_MENU_RIGHTS, menuList: REAL_MENU_RIGHTS, forbiddenMenus: REAL_FORBIDDEN_MENUS, count: REAL_MENU_RIGHTS.length });
  // GetChannelsCount parser reads int `count` (DPSDK 0x1800d3ed0).
  if (method === 'BRM.User.GetChannelsCount') return rpcEnvelope(method, { count: 1 });
  // GetUserFunctions parser reads `functions` (DPSDK 0x1800e2500); empty list =
  // no extra feature gating, launcher menus come from menu/available/list.
  if (method === 'BRM.User.GetUserFunctions') return rpcEnvelope(method, { functions: [], functionList: [], count: 0 });
  // TvWall contract keys from the shared registrar pool (0x180caf958 zone):
  // tvWallId, wallMode, screens, splitCaps, maxFreeWindows, editFlag.
  if (method === 'BRM.TvWall.GetTvWalls' || method === 'BRM.TvWall.GetTvWall') return rpcEnvelope(method, { tvWalls: [], list: [], wallList: [], count: 0 });
  if (method === 'BRM.TvWall.GetUserTvWallTasks' || method === 'BRM.TvWall.GetUserTvWallTask') return rpcEnvelope(method, { list: [], taskList: [] });
  // Linked: GetChannelLinkResource registry keys mainList / mainType / subList.
  if (method === 'BRM.Linked.GetLinkedChannels') return rpcEnvelope(method, { mainList: [], mainType: 0, subList: [], linkedChannels: [] });
  if (method === 'BRM.Config.GetEmapInfo') return rpcEnvelope(method, { emapInfo: {}, enable: 0, maps: [], list: [] });
  // GetFunctionConfig expects an XML out-param (pInfoXml in DPSDK).
  // E-022: serve REAL functionConfig from leveldb (dual-key wrapper + siraEnable).
  if (method === 'BRM.Config.GetFunctionConfig') return rpcEnvelope(method, { infoXml: JSON.stringify(REAL_FUNCTION_CONFIG), xml: JSON.stringify(REAL_FUNCTION_CONFIG), siraEnable: 0, ...REAL_FUNCTION_CONFIG });
  // User data files: SaveUserData(data.fileName, data.fileData) stores the
  // blob; GetUserData(data.fileName) echoes it. Observed live: webfav.xml,
  // quickcmd.xml, siteInfo.xml (hex payload).
  if (method === 'BRM.User.SaveUserData') {
    const fd = b.data || {};
    if (fd.fileName) USER_FILES.set(String(fd.fileName), String(fd.fileData || ''));
    return rpcEnvelope(method, { code: 0, fileName: String(fd.fileName || ''), saved: true });
  }
  if (method === 'BRM.User.GetUserData') {
    const fn = String((b.data || {}).fileName || '');
    return rpcEnvelope(method, { code: 0, fileName: fn, fileData: USER_FILES.get(fn) || '' });
  }
  if (method === 'BRM.Time.SyncServerTime') { const now = Math.floor(Date.now() / 1000); return rpcEnvelope(method, { time: now, serverTime: now, timezone: 'UTC' }); }
  // Media keys: Dpsdk GetMediaKey family (RestLogicalDevice.cpp).
  if (method === 'BRM.Device.GetCurrentMediaVK') {
    const hostIp = String((req.headers.host || '').split(':')[0] || '127.0.0.1');
    return rpcEnvelope(method, { vkId: '1', vkValue: '', mediaKey: '', ip: hostIp, port: 9100 });
  }
  if (method === 'BRM.Device.GetMediaVKs') return rpcEnvelope(method, { list: [], mediaKeys: [] });
  // E-026: BRM.Device.AddDevice RPC - native Qt stack calls this to add a device.
  // Reuses the same addDeviceHandler logic via normalizeDeviceInput + persistDevice.
  if (method === 'BRM.Device.AddDevice' || method === 'BRMS.Device.AddDevice') {
    const b = req.body || {};
    const data = b.data || b;
    const input = normalizeDeviceInput(data);
    if (!input.deviceIp && !input.devSequence) {
      return rpcEnvelope(method, { code: 1002, errorMsg: 'deviceIp (or devSequence for P2P) is required', results: [] });
    }
    const probe = await probeDeviceFor(input);
    const probeOk = probe.ok !== false;
    const identity = {
      manufacturer: probeOk ? (probe.manufacturer || '') : '',
      model: probeOk ? (probe.model || '') : '',
      firmwareVersion: probeOk ? (probe.firmwareVersion || '') : '',
      serialNumber: probeOk ? (probe.serialNumber || input.devSequence) : '',
      hardwareId: probeOk ? (probe.hardwareId || '') : '',
      ipAddress: probe.ipAddress,
      source: probeOk ? 'probe' : 'onvif-fallback'
    };
    const result = buildDeviceAddPayload(data, identity, PUBLIC_HOST, RTSP_PORT);
    const created = result.device || result.results?.[0];
    persistDevice(created);
    return rpcEnvelope(method, {
      code: 1000,
      desc: 'Success',
      id: created.deviceCode,
      deviceCode: created.deviceCode,
      code: created.deviceCode,
      results: [created],
      device: created,
      deviceVo: created
    });
  }
  // Everything else in the BRM.* family: benign success with empty data.
  return rpcEnvelope(method, {});
}

app.post('/admin/API/BRM/:ns/:fn', brmRpcHandler);
app.post('/admin/api/BRM/:ns/:fn', brmRpcHandler);
// E-024: 3-segment BRMS RPC family (BRMS.Dictionary.GetDictionaries, ...).
app.post('/admin/API/BRM/:ns/:cls/:fn', async (req) => {
  const b = req.body || {};
  const method = b.method || `${req.params.ns}.${req.params.cls}.${req.params.fn}`;
  const catalog = e024CatalogPayload(method, b);
  if (catalog) return rpcEnvelope(method, catalog);
  return brmRpcHandler(req);
});
app.post('/admin/api/BRM/:ns/:cls/:fn', async (req) => {
  const b = req.body || {};
  const method = b.method || `${req.params.ns}.${req.params.cls}.${req.params.fn}`;
  const catalog = e024CatalogPayload(method, b);
  if (catalog) return rpcEnvelope(method, catalog);
  return brmRpcHandler(req);
});
// Same RPC family probed under the /brms/api prefix (observed 404 E-019).
app.post('/brms/api/BRM/:ns/:fn', brmRpcHandler);
app.get('/brms/api/BRM/:ns/:fn', brmRpcHandler);

// ===== E-019: post-login bootstrap unblocks (all observed 404 in live trace) =====

// Service status probes: /admin/API/server/serviceStatus/DA_SCS, DA_POC, ...
app.get('/admin/API/server/serviceStatus/:svc', async (req) => envelope({
  svc: String(req.params.svc),
  status: 'online',
  serviceStatus: 'online',
  state: 'online',
  online: true
}));

// Device/org tree for the Qt stack (the "failed to get device data" blocker).
const TREE_ORG = { orgCode: '001', orgName: 'Root Org', parentOrgCode: '0', pOrgCode: '0', orgType: '0', sort: 1, deviceNum: 1, childCount: 0, status: 1 };
const TREE_DEVICE = {
  deviceCode: 'CAM001', deviceName: 'Mock Camera 01', deviceType: 2, type: 2,
  ip: '127.0.0.1', port: 37777, manufacturer: 'Dahua', model: 'MockIPC',
  protocol: 'Dahua', status: 1, online: 1, orgCode: '001'
};
const TREE_CHANNELS = [{
  channelId: '1000171$1$0$0', channelName: 'Mock Camera 01', deviceCode: 'CAM001',
  channelType: 1, channelNo: 1, orgCode: '001', status: 1, online: 1,
  videoEncode: 'H.265', audioEncode: '', ptz: 0, audio: 0, record: 0
}];
app.get('/admin/API/tree/deviceOrg', async () => envelope({
  orgList: [TREE_ORG],
  deviceList: [TREE_DEVICE],
  channelList: TREE_CHANNELS
}));

// Menu availability (~"failed to get menu"): launcher menu tree with subsections
// (user report: "faltaban todas las opciones" - the launcher renders children).
const ADMIN_MENUS = [
  { menuId: '100', id: '100', menuName: 'Monitoring Center', name: 'Monitoring Center', parentId: '0', parent: '0', sort: 1, icon: 'monitor', url: '/realtime', children: [
    { menuId: '101', id: '101', menuName: 'Real-Time Video', name: 'Real-Time Video', parentId: '100', sort: 1, url: '/realtime/live' },
    { menuId: '102', id: '102', menuName: 'Playback', name: 'Playback', parentId: '100', sort: 2, url: '/realtime/playback' },
    { menuId: '103', id: '103', menuName: 'E-map', name: 'E-map', parentId: '100', sort: 3, url: '/realtime/emap' }
  ] },
  { menuId: '200', id: '200', menuName: 'Event Center', name: 'Event Center', parentId: '0', parent: '0', sort: 2, icon: 'event', url: '/event', children: [
    { menuId: '201', id: '201', menuName: 'Real-Time Event', name: 'Real-Time Event', parentId: '200', sort: 1, url: '/event/live' },
    { menuId: '202', id: '202', menuName: 'Event Search', name: 'Event Search', parentId: '200', sort: 2, url: '/event/search' },
    { menuId: '203', id: '203', menuName: 'Event Rules', name: 'Event Rules', parentId: '200', sort: 3, url: '/event/rules' }
  ] },
  { menuId: '300', id: '300', menuName: 'DeepXplore', name: 'DeepXplore', parentId: '0', parent: '0', sort: 3, icon: 'deepxplore', url: '/deepxplore', children: [
    { menuId: '301', id: '301', menuName: 'Intelligent Retrieval', name: 'Intelligent Retrieval', parentId: '300', sort: 1, url: '/deepxplore/retrieval' }
  ] },
  { menuId: '400', id: '400', menuName: 'Intelligent Analysis', name: 'Intelligent Analysis', parentId: '0', parent: '0', sort: 4, icon: 'intel', url: '/analysis', children: [
    { menuId: '401', id: '401', menuName: 'Face Recognition', name: 'Face Recognition', parentId: '400', sort: 1, url: '/analysis/face' },
    { menuId: '402', id: '402', menuName: 'Vehicle Management', name: 'Vehicle Management', parentId: '400', sort: 2, url: '/analysis/vehicle' },
    { menuId: '403', id: '403', menuName: 'Heat Map', name: 'Heat Map', parentId: '400', sort: 3, url: '/analysis/heatmap' }
  ] },
  { menuId: '500', id: '500', menuName: 'Access Management', name: 'Access Management', parentId: '0', parent: '0', sort: 5, icon: 'access', url: '/access', children: [
    { menuId: '501', id: '501', menuName: 'Door Management', name: 'Door Management', parentId: '500', sort: 1, url: '/access/door' },
    { menuId: '502', id: '502', menuName: 'Person Management', name: 'Person Management', parentId: '500', sort: 2, url: '/access/person' }
  ] },
  { menuId: '600', id: '600', menuName: 'Parking Lot', name: 'Parking Lot', parentId: '0', parent: '0', sort: 6, icon: 'parking', url: '/parking', children: [
    { menuId: '601', id: '601', menuName: 'Parking Overview', name: 'Parking Overview', parentId: '600', sort: 1, url: '/parking/overview' },
    { menuId: '602', id: '602', menuName: 'Parking Records', name: 'Parking Records', parentId: '600', sort: 2, url: '/parking/records' }
  ] },
  { menuId: '700', id: '700', menuName: 'Maintenance Center', name: 'Maintenance Center', parentId: '0', parent: '0', sort: 7, icon: 'maintenance', url: '/maintenance', children: [
    { menuId: '701', id: '701', menuName: 'System Status', name: 'System Status', parentId: '700', sort: 1, url: '/maintenance/status' },
    { menuId: '702', id: '702', menuName: 'Device Maintenance', name: 'Device Maintenance', parentId: '700', sort: 2, url: '/maintenance/device' },
    { menuId: '703', id: '703', menuName: 'Log Search', name: 'Log Search', parentId: '700', sort: 3, url: '/maintenance/logs' }
  ] }
];
app.get('/brms/api/v1.1/menu/available/list', async () => envelope({ menuList: ADMIN_MENUS, list: ADMIN_MENUS }));

// System / config endpoints (shape unknown -> benign empties + dual keys).
// E-022: serve REAL functionConfig from leveldb cache.
app.get('/brms/api/v1.1/config/function', async () => envelope(REAL_FUNCTION_CONFIG));
app.get('/brms/api/v1.1/config/sira', async () => envelope({ siraEnable: 0, enable: false, status: '0' }));
app.get('/brms/api/v1.1/config/feature-analyse', async () => envelope({ enable: false, list: [] }));
app.get('/brms/api/v1.1/config/device-login-model', async () => envelope({ list: [], total: 0 }));
app.get('/brms/api/v1.1/config/interface/common/timeout', async () => envelope({ timeout: 300 }));
app.get('/brms/api/v1.1/time-template/list', async () => envelope({ list: [], total: 0 }));
app.get('/brms/api/v1.1/alarm/plan/alarm-type/list', async () => envelope({ list: [] }));
app.get('/brms/api/v1.1/vtalk/sip/online/list', async () => envelope({ list: [] }));
app.get('/admin/API/config/videoIntercom', async () => envelope({ enable: 0, openState: '0' }));

// Licenses + system self-check warnings (all benign: no disk/license issues).
app.get('/brms/api/v1.1/license/warning', async () => envelope({ warning: 0, warningList: [], list: [] }));
app.get('/brms/api/v1.1/license/hot-spare/abnormity', async () => envelope({ abnormal: 0, list: [] }));
app.get('/brms/api/v1.1/system/warn/disk/list', async () => envelope({ list: [] }));
app.get('/brms/api/v1.1/system/out/memory/server/list', async () => envelope({ list: [] }));
app.get('/brms/api/v1.1/system/only-startup-basic-service/warning', async () => envelope({ warning: 0, list: [] }));
app.get('/brms/api/v1.1/system/hot-spare/switch/warning', async () => envelope({ warning: 0, list: [] }));

// Access (OBMS) + parking (IPMS) empty modules.
app.get('/obms/api/v1.1/acp/area/list', async () => envelope({ list: [], total: 0 }));
app.get('/obms/api/v1.1/acs/person-group/list', async () => envelope({ list: [], total: 0 }));
app.get('/ipms/api/v1.1/organization/list', async () => envelope({ list: [], total: 0 }));
app.get('/ipms/api/v1.1/parking-lot/detail/list', async () => envelope({ list: [], total: 0 }));
app.get('/IPMS/API/entrance/parking-lot/binding-vto-itc', async () => envelope({ list: [], count: 0 }));

// ===== E-020: remaining bootstrap 404s + launcher devices + fallbacks =====

// Qt-side device lists (observed 404: /admin/API/tree/devices).
// E-025: serve the live registry (manual adds + discoveries + auto-register)
// instead of the static mock so the tree always reflects the devices.
app.get('/admin/API/tree/devices', async () => envelope({
  deviceList: [...DEVICE_REGISTRY.values()], list: [...DEVICE_REGISTRY.values()], channelList: allChannels()
}));
app.get('/admin/API/tree/equipment-tree', async () => envelope({
  orgList: [TREE_ORG], deviceList: [TREE_DEVICE], channelList: TREE_CHANNELS
}));
app.get('/admin/API/tree/search', async () => envelope({ list: [TREE_DEVICE], total: 1 }));

// E-map module (observed 404s): vector map data + raster list, benign empty.
app.get('/emap/api/v1.1/map/vector', async () => envelope({ mapInfo: {}, vectorData: '', list: [] }));
app.get('/emap/api/v1.1/map/raster/list', async () => envelope({ list: [], total: 0, rasterList: [] }));

// ===== E-024: REAL DAHUA DSS v1.1 CATALOG CONTRACTS =====
// The DSS Client 8.006 does NOT hardcode the "Add Device" combo boxes: every
// dropdown (Device Category / Access Protocol / Manufacturer / Device Type /
// Channel Type) is built at runtime from the payloads below.
//
//   GET /brms/api/v1.1/dictionary/list?types=3,107
//       -> data.results = [ {type:"3",items:[{code,name,param1,param2}]},
//                           {type:"107",items:[{code,name}]} ]
//   GET /brms/api/v1.1/definition/device-type/list
//       -> data.results = [ {deviceCategory,deviceCategoryName,deviceTypeName,
//                            deviceTypes:[{deviceType,deviceTypeName}]} ]
//   GET /brms/api/v1.1/definition/channel-capability/list
//       -> data.results = [ {code,name,group} ]
//   GET /brms/api/v1.1/server/available/list
//       -> data.results = [ {serverCode,serverName} ]
//   GET /brms/api/v1.1/config/snmp/protocol/manufacturer/list
//       -> data.results = [ {manufacturerCode,manufacturerName} ]
//
// Catalogs + evidence: ./e024-catalogs.js
const dictionaryHandler = async (req) => {
  const raw = req.query?.types ?? req.body?.types ?? '';
  const results = buildDictionaryResults(raw);
  const flat = results.flatMap((r) => r.items.map((i) => ({ type: r.type, ...i })));
  return envelope({
    results,
    // flat alias: some native parsers walk data.items[] directly
    items: flat,
    list: flat,
    total: flat.length
  });
};
app.get('/brms/api/v1.1/dictionary/list', dictionaryHandler);
app.post('/brms/api/v1.1/dictionary/list', dictionaryHandler);
app.get('/brms/api/v1.0/dictionary/list', dictionaryHandler);
app.post('/brms/api/v1.0/dictionary/list', dictionaryHandler);
app.get('/admin/API/dictionary/list', dictionaryHandler);
app.post('/admin/API/dictionary/list', dictionaryHandler);

const deviceTypeHandler = async () => {
  const results = buildDeviceTypeResults();
  return envelope({ results, list: results, deviceTypes: results, total: results.length });
};
app.get('/brms/api/v1.1/definition/device-type/list', deviceTypeHandler);
app.get('/brms/api/v1.0/definition/device-type/list', deviceTypeHandler);
app.post('/brms/api/v1.1/definition/device-type/list', deviceTypeHandler);
app.get('/admin/API/definition/device-type/list', deviceTypeHandler);

const capabilityHandler = async () => {
  const results = DAHUA_CHANNEL_CAPABILITIES;
  return envelope({ results, list: results, channelCapabilities: results, total: results.length });
};
app.get('/brms/api/v1.1/definition/channel-capability/list', capabilityHandler);
app.get('/brms/api/v1.0/definition/channel-capability/list', capabilityHandler);

const availableServerHandler = async () => {
  const results = DAHUA_AVAILABLE_SERVERS;
  return envelope({ results, list: results, serverList: results, total: results.length });
};
app.get('/brms/api/v1.1/server/available/list', availableServerHandler);
app.get('/brms/api/v1.0/server/available/list', availableServerHandler);

const snmpManufacturerHandler = async () => {
  const results = DAHUA_SNMP_MANUFACTURERS;
  return envelope({ results, list: results, snmpManufacturerList: results, total: results.length });
};
app.get('/brms/api/v1.1/config/snmp/protocol/manufacturer/list', snmpManufacturerHandler);
app.get('/brms/api/v1.0/config/snmp/protocol/manufacturer/list', snmpManufacturerHandler);

// Convenience aliases (same data, list-only shape) for older native calls.
app.get('/brms/api/v1.1/device/category', async () => {
  const results = buildDeviceTypeResults();
  return envelope({ results, list: results, total: results.length });
});
app.get('/brms/api/v1.1/access/protocol', async () => {
  const results = buildDictionaryResults('3');
  return envelope({ results, list: results[0].items, total: results[0].items.length });
});
app.get('/brms/api/v1.1/device/manufacturer', async () => {
  const results = buildDictionaryResults('107');
  return envelope({ results, list: results[0].items, total: results[0].items.length });
});
app.get('/brms/api/v1.1/definition/stream-type/list', async () => {
  const results = [
    { streamType: '1', streamTypeName: 'Main Stream' },
    { streamType: '2', streamTypeName: 'Sub Stream' },
    { streamType: '3', streamTypeName: 'Third Stream' }
  ];
  return envelope({ results, list: results, total: results.length });
});

// Alarm overview counters (mode=1 window) and account device overview.
app.get('/brms/api/v1.1/alarm/overview/summary', async () => envelope({
  total: 0, unhandled: 0, handled: 0, handling: 0,
  summary: { total: 0, unhandled: 0, handled: 0, handling: 0 },
  list: []
}));
app.get('/brms/api/v1.1/account/device/overview', async () => envelope({
  deviceCount: 1, onlineDeviceCount: 1, offlineDeviceCount: 0,
  channelCount: 1, onlineChannelCount: 1, offlineChannelCount: 0,
  overview: { deviceCount: 1, onlineDeviceCount: 1, offlineDeviceCount: 0 }
}));

// P2P config family ("network abnormal" toasts likely reference this).
app.get('/brms/api/v1.1/config/p2p', async () => envelope({ p2pEnable: 0, enable: 0, openState: '0', list: [] }));
app.get('/brms/api/v1.1/config/p2p/server/list', async () => envelope({ list: [] }));
app.get('/brms/api/v1.1/config/configTypes', async () => envelope({ list: [], configTypes: [] }));

// ===== E-025: DEVICE ADD / DISCOVER / NETWORK / TIMEZONE / ROLES / SUBSYSTEMS =
// Every route below previously hit the generic [FALLBACK] (empty envelope) or
// 404'd. The real client contracts it expects are in ./e025-devices.js.
// Order of calls when the user presses "Add" in the ONVIF dialog (E-025 trace):
//   discover/cost-time -> discover/summary -> POST /device -> device/page.

// Real reachability probe: ONVIF SOAP for ONVIF/RTSP protocols, plain TCP
// connect for Dahua/etc, and Easy4IP SOAP when the device is added by serial
// (P2P / DDIP). Never makes the request fail: it degrades to offline.
async function probeDeviceFor(input) {
  if (input.devSequence && !input.deviceIp) {
    const easy = await probeEasy4IP(input.devSequence);
    return { ...easy, online: easy.ok ? easy.ipAddress ? true : false : false, source: 'easy4ip' };
  }
  if (input.protocolType === '99' || input.protocolType === '68') {
    return probeOnvifDevice(input.deviceIp, input.devicePort);
  }
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = net.createConnection({ host: input.deviceIp, port: Number(input.devicePort) || 37777, timeout: 1500 }, () => {
      sock.end();
      resolve({ ok: true, online: true, costTimeMs: Date.now() - started, note: 'tcp connect only' });
    });
    sock.on('timeout', () => { sock.destroy(); resolve({ ok: false, online: false, costTimeMs: Date.now() - started, error: 'tcp timeout' }); });
    sock.on('error', (err) => resolve({ ok: false, online: false, costTimeMs: Date.now() - started, error: err.code || err.message }));
  });
}

// --- discovery pre-flight calls ---
for (const p of ['/brms/api/v1.1/device/discover/cost-time', '/brms/api/v1.0/device/discover/cost-time', '/brms/api/v1.1/discover/device/cost-time']) {
  app.post(p, async (req) => {
    const input = normalizeDeviceInput(req.body);
    const probe = await probeDeviceFor(input);
    return envelope(buildDiscoverCostTimePayload(req.body, probe));
  });
}
for (const p of ['/brms/api/v1.1/device/discover/summary', '/brms/api/v1.0/device/discover/summary', '/brms/api/v1.1/discover/device/summary']) {
  app.post(p, async (req) => {
    const input = normalizeDeviceInput(req.body);
    const probe = await probeDeviceFor(input);
    return envelope(buildDiscoverSummaryPayload(req.body, probe));
  });
}
for (const p of ['/brms/api/v1.1/device/discover/detail', '/brms/api/v1.0/device/discover/detail', '/brms/api/v1.1/discover/device/detail']) {
  app.post(p, async (req) => {
    const input = normalizeDeviceInput(req.body);
    const probe = await probeDeviceFor(input);
    return envelope(buildDiscoverDetailPayload(req.body, probe));
  });
}
app.post('/brms/api/v1.1/device/discover/async/batch', async () => envelope(buildDeviceDiscoverAsyncBatchPayload()));

// --- add device (the ONVIF failure root cause) ---
const addDeviceHandler = async (req) => {
  const input = normalizeDeviceInput(req.body || {});
  if (!input.deviceIp && !input.devSequence) {
    return envelope({ success: false, errorCode: 1002, errorMsg: 'deviceIp (or devSequence for P2P) is required', results: [] }, 1000, 'deviceIp (or devSequence for P2P) is required');
  }
  const probe = await probeDeviceFor(input);
  const probeOk = probe.ok !== false;
  const identity = {
    manufacturer: probeOk ? (probe.manufacturer || '') : '',
    model: probeOk ? (probe.model || '') : '',
    firmwareVersion: probeOk ? (probe.firmwareVersion || '') : '',
    serialNumber: probeOk ? (probe.serialNumber || input.devSequence) : '',
    hardwareId: probeOk ? (probe.hardwareId || '') : '',
    ipAddress: probe.ipAddress,
    source: probeOk ? 'probe' : 'onvif-fallback'
  };
  console.log('[E025-ADD]', JSON.stringify({
    deviceIp: input.deviceIp, devicePort: input.devicePort, protocolType: input.protocolType,
    deviceCategory: input.deviceCategory, deviceType: input.deviceType, deviceName: input.deviceName,
    online: probeOk, manufacturer: identity.manufacturer, model: identity.model,
    serial: identity.serialNumber, costTimeMs: probe.costTimeMs, fallback: !probeOk
  }));
  const result = buildDeviceAddPayload(req.body || {}, identity, PUBLIC_HOST, RTSP_PORT);
  const created = result.device || result.results?.[0];
  // Persist to disk so the device survives restarts and appears in all views.
  persistDevice(created);
  // E-025: broadcast a device-added event over WS so the client doesn't time out
  // waiting for a confirmation that never arrives over plain HTTP.
  try {
    const wsMsg = JSON.stringify({
      type: 'DEVICE_ADDED',
      deviceCode: created?.deviceCode,
      deviceId: created?.deviceId || created?.deviceCode,
      deviceName: created?.deviceName,
      deviceIp: created?.deviceIp,
      devicePort: created?.devicePort,
      protocolType: created?.protocolType,
      deviceCategory: created?.deviceCategory,
      deviceType: created?.deviceType,
      channelNum: created?.channelNum,
      online: created?.online,
      timestamp: Date.now()
    });
    for (const ws of WS_CLIENTS) {
      if (ws.readyState === 1) { ws.send(wsMsg); }
    }
  } catch (err) {
    console.log('[E025-ADD] WS broadcast failed:', err.message);
  }

  // E-026: ONVIF dynamic RTSP discovery - fire-and-forget AFTER responding,
  // so the client never waits for MediaMTX configuration.
  if (input.protocolType === '99' && input.deviceIp && created) {
    setImmediate(async () => {
      try {
        const rtspUri = await discoverOnvifStreamUri(input.deviceIp, input.devicePort);
        if (rtspUri) {
          await configureMediaMTXPath(MEDIAMTX_CAMERA_PATH, rtspUri);
          created.rtspUri = rtspUri;
          created.onvifStreamUri = rtspUri;
          persistDevice(created);
          console.log('[E026-ONVIF]', JSON.stringify({
            deviceIp: input.deviceIp, devicePort: input.devicePort,
            protocolType: input.protocolType, rtspUri,
            mediamtxPath: MEDIAMTX_CAMERA_PATH
          }));
        }
      } catch (err) {
        console.log('[E026-ONVIF] discovery failed:', err.message);
      }
    });
  }

  return envelope(result);
};
app.post('/brms/api/v1.1/device', addDeviceHandler);
app.post('/brms/api/v1.1/device/add', addDeviceHandler);
app.post('/brms/api/v1.0/device', addDeviceHandler);
app.post('/brms/api/v1.0/device/add', addDeviceHandler);
app.post('/admin/API/device', addDeviceHandler);
app.post('/brms/api/v1.1/device/add/batch', async (req) => envelope(buildDeviceAddBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/check/exist', async (req) => envelope(buildDeviceCheckExistPayload(req.body)));
app.post('/brms/api/v1.1/device/delete/batch', async (req) => envelope(buildDeviceDeleteBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/move/batch', async (req) => envelope(buildDeviceMoveBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/password/change/batch', async (req) => envelope(buildDevicePasswordChangeBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/timezone/update/batch', async (req) => envelope(buildDeviceTimezoneUpdateBatchPayload(req.body)));

// ===== E-027: STORAGE PLAN / SS RECORD ROUTES =====
// Needed by the Storage Plan tab (003005) and the Device Config dialogs.
import {
  buildPlanConfigStatusPayload,
  getChannelRecordPlan,
  setChannelRecordPlan,
  buildSSQueryRecordPayload,
  buildSSRecordActionPayload
} from './e027-storage.js';
for (const p of ['/brms/api/v1.1/storage/plan/channel/plan-config-status/fetch/batch/list', '/brms/api/v1.0/storage/plan/channel/plan-config-status/fetch/batch/list']) {
  app.post(p, async (req) => envelope(buildPlanConfigStatusPayload(req.body)));
}
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  app.get(`${host}/storage/plan/channel/:channelCode/new-device-record-plan`, async (req) => envelope(getChannelRecordPlan(req.params.channelCode)));
  app.put(`${host}/storage/plan/channel/:channelCode/new-device-record-plan`, async (req) => envelope(setChannelRecordPlan(req.params.channelCode, req.body)));
  app.post(`${host}/storage/plan/channel/:channelCode/new-device-record-plan`, async (req) => envelope(setChannelRecordPlan(req.params.channelCode, req.body)));
}
// E-027 note: /brms/api/v1.0/SS/Record/QueryRecord already exists in the
// EV-037 section below with the { preHandler: auth } shape - not duplicated here.

// --- device lists ---
app.get('/brms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload(req.query)));
app.get('/brms/api/v1.0/device/page', async (req) => envelope(buildDevicePagePayload(req.query)));
app.post('/brms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload({ ...req.query, ...(req.body || {}) })));
app.get('/brms/api/v1.1/discover/device/page', async () => envelope(buildDiscoverDevicePagePayload()));
app.get('/brms/api/v1.1/device/channel/page', async () => {
  const list = allChannels();
  return envelope({ list, results: list, channelList: list, items: list, total: list.length, pageNo: 1, pageSize: list.length || 20 });
});
// E-025b: RTSP URL lookup so the client can stream via our MediaMTX proxy
// instead of dialing the camera's RTSP port directly (which may be closed).
app.get('/brms/api/v1.1/device/rtsp-url', async (req, reply) => {
  const payload = buildDeviceRtspUrlPayload(req.query?.deviceCode || req.query?.deviceId, PUBLIC_HOST, RTSP_PORT);
  if (!payload) return reply.code(404).send(envelope(null, 404, 'Device not found'));
  return envelope(payload);
});
app.get('/brms/api/v1.1/device/unauthorized/page', async () => envelope(buildDeviceUnauthorizedPagePayload()));
app.post('/brms/api/v1.1/device/unauthorized/add/batch', async () => envelope({ success: true, results: [], list: [] }));
app.post('/brms/api/v1.1/device/unauthorized/delete/batch', async () => envelope({ success: true, results: [], list: [] }));

// --- discovery join (LAN scan result -> device tree) ---
app.post('/brms/api/v1.1/discover/device/init', async (req) => envelope(buildDiscoverDeviceInitPayload(req.body)));
app.post('/brms/api/v1.1/discover/device/join/batch', async (req) => envelope(buildDiscoverJoinBatchPayload(req.body)));
app.post('/brms/api/v1.1/discover/device/network/update', async () => envelope({ success: true }));

// ===== E-026: MISSING FALLBACK ROUTES =====
// Observed during operator testing: these return generic empty envelopes so
// the client never shows "data provided by the service its abnormal" toasts.
for (const [route, payload] of Object.entries(FALLBACK_ROUTES)) {
  const [method, path] = route.split(' ', 2);
  if (method === 'GET') {
    app.get(path, async () => envelope(payload));
  } else if (method === 'POST') {
    app.post(path, async () => envelope(payload));
  }
}

// --- statistics / network / timezone / roles / functions / subsystems ---
app.get('/brms/api/v1.1/device/statistics/count-by-device-category/list', async (req) => envelope(buildStatisticsCategoryPayload(buildDeviceTypeResults(), req.query)));
app.get('/brms/api/v1.1/system/network/list', async () => envelope(buildNetworkListPayload()));
app.get('/brms/api/v1.1/config/server/timezone', async () => envelope(buildServerTimezonePayload('UTC')));
app.get('/brms/api/v1.1/config/timezone/list', async () => envelope(buildTimezoneListPayload()));
const roleHandler = async () => envelope(buildRolePagePayload());
app.get('/brms/api/v1.1/role/page', roleHandler);
app.post('/brms/api/v1.1/role/page', roleHandler);
app.get('/brms/api/v1.1/role/list', roleHandler);
app.get('/brms/api/v1.1/role/all/list', roleHandler);
app.get('/brms/api/v1.1/function/available/list', async () => envelope(buildFunctionAvailablePayload()));
app.get('/brms/api/v1.1/subsystem/available/list', async () => envelope(buildSubsystemAvailablePayload()));
app.get('/brms/api/v1.1/subsystem/register/warning', async () => envelope({ warningList: [], list: [], total: 0 }));
// OMMS (alarm service) previously 404'd -> "abnormal data" in the Event Center.
app.get('/omms/api/v1.1/alert/rule/alert-type/list', async () => envelope(buildAlertTypeListPayload()));
app.post('/omms/api/v1.1/alert/rule/alert-type/list', async () => envelope(buildAlertTypeListPayload()));

// --- GET variants of the tree (launcher prefetch used GET -> fallback) ---
app.get('/brms/api/v1.0/tree/orgs', async () => envelope({
  orgList: [{ orgId: '1', orgCode: '001', orgName: 'Root', parentId: '0', orgType: 1, sort: 1, deviceNum: Math.max(1, DEVICE_REGISTRY.size), childCount: 0, status: 1 }]
}));
app.get('/brms/api/v1.0/tree/devices', async () => envelope({
  deviceList: [...DEVICE_REGISTRY.values()], list: [...DEVICE_REGISTRY.values()], orgCode: '001', containVirtualDevice: '1', total: DEVICE_REGISTRY.size
}));
app.get('/brms/api/v1.0/tree/channels', async () => {
  const channelList = allChannels();
  return envelope({ channelList, list: channelList, total: channelList.length });
});
// Same dynamic data on the admin API base used by the native Qt stack.
app.get('/brms/api/v1.1/tree/device-tree', async () => {
  const deviceList = [...DEVICE_REGISTRY.values()];
  return envelope({ orgList: [{ orgId: '1', orgCode: '001', orgName: 'Root', parentId: '0', orgType: 1, sort: 1 }], deviceList, channelList: allChannels() });
});

// ===== E-021: exact contracts for the routes that hit [FALLBACK] in the live
// launcher trace (E-021 objective 1) =====

// POST /admin/API/tree/devices arrives with a filter body: {categories: [],
// sourceTypes: [], orgCode: "", deviceCodes: [], containVirtualDevice: "1"}.
app.post('/admin/API/tree/devices', async (req) => {
  const b = req.body || {};
  return envelope({
    deviceList: [TREE_DEVICE], list: [TREE_DEVICE], channelList: TREE_CHANNELS,
    orgCode: String(b.orgCode || ''), containVirtualDevice: String(b.containVirtualDevice || '1'), total: 1
  });
});
// favorite/tree = Dpsdk::CRestLogical::GetCollectionTree (favorites tree).
app.get('/brms/api/v1.1/account/favorite/tree', async () => envelope({
  list: [], orgList: [], channelList: [], tree: [], favoriteList: []
}));
// share/unread/list = GetUnReadCollections / GetUnreadShareViews.
app.get('/brms/api/v1.1/account/favorite/organization/share/unread/list', async () => envelope({ list: [], unreadCount: 0 }));
app.get('/brms/api/v1.1/monitor/view/share/unread/list', async () => envelope({ list: [], unreadCount: 0, pUnreadShareViewInfo: [] }));
// latest/unhandled/record/list = GetHistoryAlarmRecords (7-day top-1000).
app.get('/brms/api/v1.1/alarm/latest/unhandled/record/list', async () => envelope({ list: [], records: [], total: 0 }));

// ===== E-022: Launcher web app (served by server, consumed by embedded CEF) =====
// The CEF browser (CefView.dll + libcef.dll) loads QCommon::GetUrl -> "web/client-module"
// with query: userId, locale, skin, logLevel. Qt injects localStorage.menuRights via
// CWebViewFactory::AddMenuRightsToWeb (IUserManager vtable +0xd8 rights, +0xf8 forbidden).
// The web app consumes: localStorage.menuRights, modulesDefaultMenu, localcfg, token.
// Self-built page (no vendor code): reads localStorage, fetches tree orgs/devices/channels
// + accounts/current with X-Subject-Token, renders tiles from real menu codes.

// Root landing page: mirrors real server behavior - minimal HTML that calls urlInfo
app.get('/', async (req, reply) => {
  const host = req.headers.host || `localhost:${PORT}`;
  reply.type('text/html; charset=utf-8');
  return `<!DOCTYPE html>
<html><body><div class="local" style="color:red"></div></body>
<script>
var Ajax = { get: function (url, fn) { var obj = new XMLHttpRequest(); obj.open('GET', url, true); obj.onreadystatechange = function () { if (obj.readyState === 4 && (obj.status === 200 || obj.status === 304)) { fn.call(this, obj.responseText); } }; obj.send(); } };
Ajax.get('/admin/api/v1.1/domain/download/urlInfo', function(res) {
  if (res) { try { var data = JSON.parse(res).data; if (data) window.location.href = data; else document.querySelector(".local").innerHTML = "Page not found, please contact the administrator!"; } catch(e) {} }
});
<\/script></html>`;
});

// urlInfo endpoint: real server returns {"code":1000,"desc":"Success","data":"https://host:1443/web/client-module/"}
app.get('/admin/api/v1.1/domain/download/urlInfo', async (req) => {
  const host = req.headers.host || `localhost:${PORT}`;
  return envelope({ code: 1000, desc: 'Success', data: `https://${host}/web/client-module/` });
});

// ===== E-025: LAUNCHER PAGE (real QT/CEF bridge) =====
// The bridge contract lives in ./e025-launcher-page.js:
//   web  -> native:  ClientObject.MainCall(method, jsonParam, callbackName)
//   native -> web:   window.webAPICaller(callbackName|action, jsonPayload)
//   token:           MainCall('getToken','',cb) -> webAPICaller(cb,{token,
//                    resourceToken})  (the E-024 page never asked, so
//                    accounts/current answered 401 -> "init error (token=no)")
//   tile click:      MainCall('switchMenuTab', JSON({menuCode,pluginName,
//                    menuName,externData}), cb)
//
// ===== E-028: REAL production web bundle under /web/client-module/ =====
// CefRender.exe always loads the same base URL (userId/locale/skin/logLevel
// query; the module marker never gets past the URL). The mirrored bundle is
// the one a real DSS Pro server serves (EV-078), so the client renders its
// authentic Device Config / Storage Plan / Monitoring UI - no invented pages.
const WEB_MODULE_DIR = path.resolve(__dirname, '..', 'web-module');
const WEB_MIME = {
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.webp': 'image/webp', '.pak': 'application/octet-stream'
};
function webModuleIndexReply(reply) {
  const idx = path.join(WEB_MODULE_DIR, 'index.html');
  if (fs.existsSync(idx)) {
    reply.type('text/html; charset=utf-8').header('cache-control', 'no-store');
    return fs.createReadStream(idx);
  }
  reply.type('text/html; charset=utf-8').code(503);
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>DSS Client</title></head><body style="font-family:sans-serif;padding:40px;color:#333"><h3 style="margin:0">DSS Client web module not available</h3><p style="font-size:13px;margin-top:8px">The production /web/client-module bundle is not deployed on this gateway. Mirror web-module/ and rebuild.</p></body></html>';
}
app.get('/web/client-module/*', async (req, reply) => {
  let rel;
  try {
    rel = decodeURIComponent(String(req.url || '').split('?')[0]).replace(/^\/web\/client-module\/?/, '');
  } catch {
    reply.code(400);
    return 'bad path';
  }
  if (rel === '' || rel === '/') return webModuleIndexReply(reply);
  if (rel.includes('..')) { reply.code(400); return 'bad path'; }
  const abs = path.join(WEB_MODULE_DIR, rel);
  if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
    const ext = path.extname(abs).toLowerCase();
    const last = rel.split('/').pop() || '';
    // hashed Vite chunks are immutable; index.html always revalidates
    const immutable = /\.[A-Za-z0-9_-]{8}\.(?:js|mjs|css)$/.test(last);
    reply.type(WEB_MIME[ext] || 'application/octet-stream')
      .header('cache-control', immutable ? 'public, max-age=604800, immutable' : 'no-cache');
    return fs.createReadStream(abs);
  }
  // SPA fallback: paths without a file extension resolve to the real index.html
  const last = rel.split('/').pop() || '';
  if (!last.includes('.')) return webModuleIndexReply(reply);
  reply.code(404);
  return 'not found';
});
app.get('/web/client-module', async (req, reply) => { reply.redirect(302, '/web/client-module/'); });

// Catch-all benign responders for the rest of the microservice families
// (172-path client inventory: accessControl, alarm-host, alarmBusiness,
// vtalk, devicesManager, system/timezone, menus/client ...). Nothing in the
// bootstrap may 404 or a module aborts with "data abnormal". [FALLBACK]
// marks the exact hit so shapes get refined next cycle.
// E-025: every service prefix the client's DPSDK inventory knows about, so an
// unknown route returns code 1000 instead of the 404 that produced the
// "network abnormal / abnormal data" toasts (observed: /omms/api 404).
function fallbackLog(req) {
  console.log('[FALLBACK]', JSON.stringify({ timestamp: new Date().toISOString(), method: req.method, url: req.url, code: 1000 }));
}
const SERVICE_PREFIXES = [
  '/admin/API', '/admin/api',
  '/brms/api', '/cfgs/api', '/obms/api', '/ipms/api', '/emap/api', '/emapService', '/omms/api',
  '/otms/api', '/OTMS/API', '/iams/api', '/erms/api', '/ecos/api', '/faceService', '/alarmProcess',
  '/accessControlServer', '/alarmhost/v1', '/vehicleServer', '/videoService', '/psib', '/sira/api',
  '/IPMS/API', '/OBMS/API', '/EMAP/API', '/CFGS/API', '/OMCMS/API', '/OMMS/API'
];
for (const PREFIX of SERVICE_PREFIXES) {
  app.get(PREFIX + '/*', async (req) => { fallbackLog(req); return envelope({ list: [], total: 0 }); });
  app.post(PREFIX + '/*', async (req) => { fallbackLog(req); return envelope({}); });
  app.put(PREFIX + '/*', async (req) => { fallbackLog(req); return envelope({}); });
  app.delete(PREFIX + '/*', async (req) => { fallbackLog(req); return envelope({}); });
}

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
// E-025: the POST tree routes are what the native Qt stack calls after a login
// and after an add; they must return the live device registry so a manually
// added / discovered / auto-registered device shows up in the client tree.
app.post('/brms/api/v1.0/tree/orgs', { preHandler: auth }, async () => envelope({
  orgList: [{ orgId: '1', orgCode: '001', orgName: 'Root', parentId: '0', orgType: 1, sort: 1, deviceNum: Math.max(1, DEVICE_REGISTRY.size), childCount: 0, status: 1 }]
}));
app.post('/brms/api/v1.0/tree/devices', { preHandler: auth }, async () => {
  const deviceList = [...DEVICE_REGISTRY.values()];
  return envelope({ deviceList, list: deviceList, orgCode: '001', containVirtualDevice: '1', total: deviceList.length });
});
app.post('/brms/api/v1.0/tree/channels', { preHandler: auth }, async () => {
  const channelList = allChannels();
  return envelope({ channelList, list: channelList, total: channelList.length });
});

// ===== MTS VIDEO =====
app.post('/brms/api/v1.0/MTS/Video/StartVideo', { preHandler: auth }, async (req) => {
  const { channelId, streamType, dataType, enableMulticast, enableRtsps, extend, fakeSdp, forceSynPlay, keyCode, operateType, planId, trackId } = req.body;
  const token = genToken();
  const session = genToken().slice(0, 16);
  const vkId = 'vk-' + genToken().slice(0, 8);
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${MEDIAMTX_CAMERA_PATH}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now(), path: MEDIAMTX_CAMERA_PATH });
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
// E-025: Easy4IP/P2P endpoints are the real ones recovered from DPSDK.dll
// (CP2PServerManager::GetDeviceInfoFromEasy4IP -> www.easy4ip.com SOAP
// getDeviceByDevSequence). Our server does not register on the Dahua cloud,
// so the payload reports the endpoints + the real reason.
app.get('/brms/api/v1.0/p2p/status', async () => envelope(buildP2PStatusPayload()));
app.get('/brms/api/v1.1/p2p/status', async () => envelope(buildP2PStatusPayload()));

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

  // E-025: REAL Easy4IP lookup (getDeviceByDevSequence) instead of simulating
  // success. The device only becomes reachable if the Dahua cloud answers with
  // its ipAddress; otherwise the response carries the real error so the client
  // shows the true reason instead of a fake "registered".
  const easy4ip = await probeEasy4IP(String(sn));
  const easy4ipOk = easy4ip.ok && easy4ip.ipAddress;

  const deviceId = 'P2P-' + genToken().slice(0, 12);
  const channelIds = [];
  for (let i = 1; i <= channels; i++) {
    channelIds.push(`${deviceId}$${i}$0$0`);
  }

  P2P_DEVICES.set(sn, {
    sn, deviceId, name: name || `P2P Device ${sn}`, user: user || 'admin',
    channelIds, registeredAt: Date.now(), status: easy4ipOk ? 'online' : 'unresolved',
    easy4ip
  });

  console.log('[E025-P2P]', JSON.stringify({ sn: String(sn), easy4ipOk, ipAddress: easy4ip.ipAddress || '', httpStatus: easy4ip.httpStatus || 0, error: easy4ip.error || '' }));

  return envelope({
    deviceId,
    channelIds,
    p2pStatus: easy4ipOk ? 'registered' : 'unresolved',
    easy4ip: {
      ok: easy4ipOk,
      ipAddress: easy4ip.ipAddress || '',
      httpStatus: easy4ip.httpStatus || 0,
      error: easy4ip.error || '',
      registered: easy4ip.registered === true,
      answered: easy4ip.answered === true,
      returnEmpty: easy4ip.returnEmpty === true,
      costTimeMs: easy4ip.costTimeMs || 0
    },
    message: easy4ipOk
      ? `Device registered via Easy4IP (${easy4ip.ipAddress}).`
      : easy4ip.returnEmpty
        ? 'Easy4IP answered 200 with an empty <return/>: this serial is not published on the Dahua P2P cloud (the camera is not registered to Easy4IP / not shared with this server account). Add it by LAN IP instead.'
        : `Easy4IP could not resolve this serial (${easy4ip.error || 'HTTP ' + (easy4ip.httpStatus || 'no answer')}); the device is stored but stays offline.`
  });
});

// E-025: live reachability of the real P2P/Easy4IP endpoints (DPSDK.dll set).
app.get('/brms/api/v1.0/p2p/reachability', { preHandler: auth }, async () => {
  const results = await probeEasy4IPReachability();
  return envelope({
    results,
    servers: results,
    up: results.filter((r) => r.up).map((r) => r.host),
    down: results.filter((r) => !r.up).map((r) => r.host),
    note: 'Reachable endpoints can resolve a device serial through the Easy4IP SOAP interface.'
  });
});
// Live serial lookup (answers what the DSS client itself would ask the cloud).
app.get('/brms/api/v1.0/p2p/easy4ip/probe', { preHandler: auth }, async (req) => {
  const sn = String(req.query?.sn || req.query?.devSequence || '');
  if (!sn) return envelope({ ok: false, error: 'sn query parameter is required (device serial / devSequence)' });
  const result = await probeEasy4IP(sn);
  return envelope(result);
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

// E-025: auto-registered devices come from the registry so the list, the tree
// and the statistics always agree (the DSS client re-reads the tree after add).
app.post('/brms/api/v1.0/ars/list', async () => envelope(buildArsListPayload()));
app.get('/brms/api/v1.0/ars/list', async () => envelope(buildArsListPayload()));

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

        // E-025: keep the raw packet: the previous code sliced `buffer` first
        // and then parsed the payload from the already-advanced buffer, so the
        // register payload was always garbage and auto-registration never
        // produced a device. Packet boundaries must be read before advancing.
        const packet = buffer.subarray(0, totalLen);
        const payload = packet.subarray(32, totalLen);
        buffer = buffer.subarray(totalLen);

        // Process command
        const { command, sequence, payloadLen, sessionId } = header;

        console.log('[ARS TCP] Command:', command.toString(16), 'Seq:', sequence, 'Payload:', payloadLen, 'from', socket.remoteAddress);

        switch (command) {
          case DHIP_CMD.REGISTER: {
            session.sequence = header.sequence;
            const deviceInfo = parseRegisterPayload(payload);
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

            // E-025: auto-registered devices must behave like manually added
            // ones: show up in /device/page, /tree/devices, /tree/channels and
            // /device/statistics/count-by-device-category/list.
            try {
              registerArsDevice(deviceInfo);
            } catch (err) {
              console.log('[ARS TCP] registerArsDevice failed:', err.message);
            }

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
      }, app.routing.bind(app));

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
      }, app.routing.bind(app));

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