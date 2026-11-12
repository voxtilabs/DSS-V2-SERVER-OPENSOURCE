import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { WebSocketServer } from 'ws';
// E-039: MQTT notify broker + device-change hub (real topics from the
// DPSDK.dll / PROLogic.dll string pools - see the module header).
import {
  createMqttBroker,
  createNotifyHub,
  buildMqConfigPayload,
  setNativeAlarmMapper,
  MQ_USER_ID
} from './e039-mq-notify.js';
// E-040: STOMP publisher to the REAL ActiveMQ Classic broker (OpenWire
// 61616 is what the native client's MSG.exe actually connects to - see the
// module header for the pcap + MSG.exe MQInit evidence).
import { createStompPublisher } from './e040-amq-notify.js';
// E-041: persistent org store (root '001' + 'VIGILAB' in data/orgs.json).
import { loadOrgsFromDisk, buildGetOrganizationsPayload, buildOrganizationListPayload, deviceOrgCode, orgName, listOrgs } from './e041-orgs.js';
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
  buildChannelListPayload,
  buildDeviceOrganizationBatchPayload,
  findDevicePayloadByCode,
  buildDiscoverCostTimePayload,
  buildDiscoverSummaryPayload,
  buildFunctionAvailablePayload,
  buildNetworkListPayload,
  buildP2PStatusPayload,
  buildRolePagePayload,
  buildUserPagePayload,
  buildUserDetailPayload,
  buildUserGroupListPayload,
  buildLdapConfigPayload,
  buildUserEmailListPayload,
  buildAuthorityResourceRolesPayload,
  buildResourceAllocateOrgDevicesPayload,
  buildChannelFunctionCheckPayload,
  buildDeviceFunctionCheckPayload,
  buildServerTimezonePayload,
  buildStatisticsCategoryPayload,
  buildSubsystemAvailablePayload,
  buildTimezoneListPayload,
  probeEasy4IP,
  probeEasy4IPReachability,
  probeOnvifDevice,
  registerArsDevice,
  createDeviceRecord,
  persistDevice,
  loadDevicesFromDisk,
  deviceOnlineOf,
  buildDeviceTableRow
} from './e025-devices.js';
// E-026: load persisted devices from disk so they survive restarts and
// appear in device/page, tree/*, statistics immediately.
loadDevicesFromDisk();
// E-041: load (or seed) the persistent org store so VIGILAB is always served.
loadOrgsFromDisk();
// E-026: ONVIF -> MediaMTX video bridge + missing FALLBACK routes
import {
  discoverOnvifStreamUri,
  configureMediaMTXPath,
  mediaMtxPathForDevice,
  MEDIAMTX_CAMERA_PATH,
  MEDIAMTX_API_URL,
  FALLBACK_ROUTES
} from './e026-video.js';
// E-034: every registered device owns its own MediaMTX RTSP path.
import { ensureDeviceStream, findDeviceByChannelId, buildDeviceModifyBatchPayload, setDeviceNotifier } from './e025-devices.js';
// E-033: real monitor/view contract (saved layouts) extracted from the
// original DSS Server V8.008 package (ViewController / ViewTreeVo / ...).
import {
  loadViewsFromDisk,
  seedMonitoringCenter,
  buildViewTreePayload,
  buildViewDirPayload,
  addViewDir,
  updateViewDir,
  batchDeleteViewDir,
  addView,
  updateView,
  renameView,
  batchDeleteView,
  shareView,
  ackShareView,
  buildShareViewPayload,
  buildUnreadShareViewsPayload
} from './e033-monitor-views.js';
// E-037: real native contracts (menu catalog, function rights, device/org
// tree) extracted from the original DSS Server V8.008 package.
import {
  DSS_MENU_CATALOG,
  DSS_FUNCTION_CATALOG,
  DSS_ADMIN_FUNCTION_CODES,
  DSS_ADMIN_DEVICE_PRIVILEGES,
  DSS_ROLE_MENU_CODES,
  buildMenuAvailablePayload,
  buildMenuAvailableFlag,
  buildFunctionListPayload,
  buildNativeDeviceTreePayload,
  buildNativeOrgTreePayload,
  buildNativeAllOrgPayload
} from './e037-native-tree.js';
// E-139: paged tree contract FUN_18071dac0 ({totalCount, results[]}, online string,
// parentId, nodeType, hasChild) for v1.0/tree/orgs|devices|channels
import {
  buildPagedOrgsPayload,
  buildPagedDevicesPayload,
  buildPagedChannelsPayload
} from './e139-paged-tree.js';
// E-143a: tree payloads never leak the camera's internal IP
import { maskDeviceIp } from './e143-ip-mask.js';
loadViewsFromDisk();
// E-120: Monitoring Center opens populated (VIGILAB dir + operator camera view)
try {
  const seeded = seedMonitoringCenter({});
  if (seeded.seeded) console.log('[E120-VIEWS] seeded Monitoring Center:', JSON.stringify(seeded));
} catch (err) { console.log('[E120-VIEWS] seed skipped:', err.message); }
// E-025: the mock camera is part of the device registry so /device/page,
// /tree/* and the statistics all report the same set of devices.
// E-028: the seeded mock ("Test Camera" @127.0.0.1:37777, manufacturer
// "Dahua", model "MockIPC") was an INVENTED device identity - E-026 removed
// the invented ONVIF fallback for the same reason. The registry now only
// holds devices the operator really added (identity taken from the camera).
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

// E-109b: persistent request journal. `docker logs` die with the container -
// the 2026-11-07 forensics of client FALLBACK hits had to be recovered from
// /tmp files. The /app/data volume is rw, so every [REQ]/[RES]/[FALLBACK] line
// is appended there (best-effort; never breaks a request).
const JOURNAL_DIR = '/app/data/logs';
function journal(line) {
  try {
    fs.mkdirSync(JOURNAL_DIR, { recursive: true });
    fs.appendFileSync(`${JOURNAL_DIR}/requests-${new Date().toISOString().slice(0, 10)}.log`, line + '\n');
  } catch { /* journal is best-effort */ }
}

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
  journal(prefix + ' ' + JSON.stringify(logEntry));

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
  journal('[RES] ' + JSON.stringify(logEntry)); // E-109b
});

const REALM = process.env.REALM || 'DSS-V2-LAB';
const PORT = parseInt(process.env.PORT || '11443', 10);
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '1443', 10);
const HTTPS_PORT_2 = parseInt(process.env.HTTPS_PORT_2 || '9443', 10);
const RTSP_PORT = parseInt(process.env.RTSP_PORT || '9100', 10);
const ARS_PORT = parseInt(process.env.ARS_PORT || '9500', 10);
const SIP_PORT = parseInt(process.env.SIP_PORT || '5080', 10);

// E-039: MQTT notify broker (real brms.notify* topics, MQType "mqtt").
// MQ_ENABLE=0 reverts GetMqConfig to UseMqFlag:0 (HTTP-only event path).
const MQTT_PORT = parseInt(process.env.MQTT_PORT || '1883', 10);
const MQ_ENABLE = (process.env.MQ_ENABLE || '1') !== '0';
// E-040: ActiveMQ Classic service (OpenWire 61616 = the port the native
// client really dials per the production pcap; STOMP 61613 = the port this
// gateway publishes the brms.notify* topics through).
const AMQ_HOST = process.env.AMQ_HOST || '127.0.0.1';
const AMQ_PORT = parseInt(process.env.AMQ_PORT || '61616', 10);
const AMQ_STOMP_PORT = parseInt(process.env.AMQ_STOMP_PORT || '61613', 10);
const AMQ_ENABLE = (process.env.AMQ_ENABLE || '1') !== '0';
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
// E-039: device-change push hub - fans every registry mutation out to the
// WS event stream AND the real MQ notify topics (brms.notifyBatchAddDevices,
// brms.notifyChannelStatuses) so the native client refreshes its tree without
// a relogin instead of hitting the CDevAdd 30 s "Operation timed out" timer.
const MQTT = createMqttBroker();
// E-040: STOMP publisher to ActiveMQ. AMQ_ENABLE=0 disables only the AMQ
// push (MQTT 1883 dual push + WS stay up).
const AMQ = AMQ_ENABLE
  ? createStompPublisher({
      host: AMQ_HOST,
      port: AMQ_STOMP_PORT,
      login: process.env.AMQ_LOGIN || 'admin',
      passcode: process.env.AMQ_PASSWORD || 'admin'
    })
  : null;
const NOTIFY = createNotifyHub({
  wsClients: WS_CLIENTS,
  mqttPublish: (topic, body) => MQTT.publish(topic, body),
  amqPublish: AMQ ? (topic, body) => AMQ.publish(`/topic/${topic}`, body) : null,
  // E-088: same UserId served by GetMqConfig so the mq.* notify topics match
  // the ones MSG.exe subscribed to (mq.<x>.msg.topic.<UserId>).
  mqUserId: MQ_USER_ID
});
// E-144: wire the device-notify hook so device modify pushes DEVICE_STATUS
// from e025-devices.js without importing the hub there.
setDeviceNotifier(NOTIFY);

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
// E-147: the DSS client digest chain, derived from three live captures (all
// matched): temp = md5(user + md5(pass)); inner = md5(`${user}:${realm}:${temp}`);
// sig = md5(md5(inner + ':' + randomKey)) — the client hashes the digest twice.
function clientDigest(user, pass) { return md5(user + md5(pass)); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey)); }
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
  // E-134 D1/D4 (REA auditor ses_e41b71d20, FUN_18072a2b0 descriptor de 26
  // claves + FUN_1806771a0 keepalive): faltaban secretKey/secretVector/
  // credential/reused/verification/userLevel/pocId/userGroupId/
  // unlockRemainTimes/unlockRemainTime y versionInfo.patchVersion ->
  // "LoginSecTime is failed, PrivateDecrypt Failed" en cada sesion.
  const secretKey = crypto.createHash('sha256').update(token).digest('hex');
  return {
    token,
    duration: 86400,
    userId: '1',
    userLevel: '1',
    secretKey,
    secretVector: crypto.randomBytes(16).toString('hex'),
    credential: crypto.createHash('sha256').update(token + '::' + secretKey).digest('hex'),
    reused: '0',
    verification: '0',
    pocId: '1',
    userGroupId: '1',
    pocPassword: '',
    unlockRemainTimes: '0',
    unlockRemainTime: '0',
    versionInfo: { updateUrl: '', patchUrl: '', patchVersion: '20250307', lastVersion: 'V' + (DEFAULT_SERVER_VERSION.match(/\d+\.\d+\.\d+\.\d+/) || [DEFAULT_SERVER_VERSION.replace(/^V/, '')])[0] },
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
      const temp = clientDigest(String(b.userName), 'admin123');
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
  // E-106: a body carrying password/encryptPassword is the RSA second-time
  // login (post password/check) - do NOT challenge again or the client loops.
  const hasRsaCred = b.password || b.encryptPassword || b.encryptPwd;
  if (b.userName && !b.signature && !b.digestPassword && !hasRsaCred) {
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

// ===== E-106: second-time login (RSA password check) =======================
// Live evidence 2026-11-07 09:39:55Z: the real client opens with
//   GET  /brms/api/v1.1/account/security/public-key/generate  (VerifyFirstTime)
//   POST /brms/api/v1.1/account/security/password/check       (VerifySecondTime)
// Both hit the generic [FALLBACK] (59B / 40B stubs) -> the RSA step never
// completed -> NO accounts/authorize ever ran -> x-subject-token ABSENT on
// every later call -> "Failed to get the LDAP configuration: Abnormal
// network" / "Failed to get the role list: Abnormal network" toasts and an
// empty Users window. DPSDK strings: "VerifyFirstTime ... public-key/generate"
// (@0xca13d9), "VerifySecondTime ... password/check" (@0xca1559),
// "Get RsaCryption failed" + "-----BEGIN PUBLIC KEY-----" (@0xc7cbf4),
// response keys `publicKey` + `randomKey` (@0xcc70a8).
const PUBKEY_PENDINGS = new Map(); // randomKey -> { privateKey, expires }
function purgePubKeys() {
  for (const [k, v] of PUBKEY_PENDINGS) if (Date.now() > v.expires) PUBKEY_PENDINGS.delete(k);
}
function genRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}
const pubKeyGenerateHandler = async () => {
  purgePubKeys();
  const kp = genRsaKeyPair();
  const rk = crypto.randomBytes(16).toString('hex');
  PUBKEY_PENDINGS.set(rk, { privateKey: kp.privateKey, expires: Date.now() + 300000 });
  return envelope({
    publicKey: kp.publicKey, randomKey: rk, keyId: rk, publicKeyId: rk,
    encryptType: 'RSA', expireTime: '300', needUpdate: '0'
  });
};
const passwordCheckHandler = async (req) => {
  const b = req.body || {};
  const rk = String(b.randomKey || '');
  const enc = String(b.password || b.encryptPassword || '');
  const entry = PUBKEY_PENDINGS.get(rk);
  let decryptedLen = -1;
  if (entry && enc) {
    let buf = null;
    try { buf = Buffer.from(enc, 'base64'); } catch { buf = null; }
    if (buf && buf.length > 0) {
      for (const padding of [crypto.constants.RSA_PKCS1_PADDING, crypto.constants.RSA_PKCS1_OAEP_PADDING]) {
        try {
          const plain = crypto.privateDecrypt({ key: entry.privateKey, padding }, buf);
          decryptedLen = plain.length;
          console.log('[E106-PWD-CHECK]', JSON.stringify({ randomKey: rk, encLen: enc.length, plainLen: plain.length }));
          break;
        } catch { /* try next padding */ }
      }
    }
  }
  console.log('[E106-PWD-CHECK]', JSON.stringify({ randomKey: rk, encLen: enc.length, decryptedLen }));
  // Success either way: this server's authorize accepts the credentials and
  // the client only needs code 1000 to continue to LoginSecondTime.
  return envelope({
    success: true, result: '1', status: '1', checkResult: '1', passed: '1',
    needChange: '0', passwordExpired: '0', firstLogin: '0'
  });
};
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  app.get(`${host}/account/security/public-key/generate`, pubKeyGenerateHandler);
  app.post(`${host}/account/security/public-key/generate`, pubKeyGenerateHandler);
  app.post(`${host}/account/security/password/check`, passwordCheckHandler);
}
app.post('/admin/API/account/security/public-key/generate', pubKeyGenerateHandler);
app.post('/admin/API/account/security/password/check', passwordCheckHandler);

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
  // E-132 (REA ses_e4217e90affe5dwaqu3eemapWC + client log proof): the login
  // compare is data.baseVersion (sscanf "V%u.%u.%u.%u") vs the client's own
  // V8.006.0000000.0 - UserLogical emits code 10 (toast "Client & server
  // versions don't match...", MainFormPlugin 0x180664810) when the served
  // baseVersion parses LOWER. selectPlatformVersion() can pick an older
  // CLIENT_VERSIONS entry from a stray UA/query token, so this pre-login
  // endpoint is PINNED to the deployed fleet build (8.006): never older.
  const softwareVersion = CLIENT_VERSIONS['8.006'];
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
  // E-132: serverName is the field that actually selects server type 1/3/4/2
  // (CRestLogical+0xc8, 0x2ef872); absent => type 2. Send it explicitly.
  return envelope({
    version: clientSelfVersion,
    platform: 'DSS Pro',
    serverName: 'DSS Pro',
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
  // E-132: pinned to the fleet build like /videoService/version (never older,
  // never newer - equality is what the client's switch expects).
  const selected = CLIENT_VERSIONS['8.006'];
  const clientMajorV = 'V' + ((selected.match(/\d+\.\d+\.\d+\.\d+/) || [selected.replace(/^V/, '')])[0]);
  // E-126: serverVersion must match the client's OWN literal form
  // (8.006.0000000.0.R.20250307) - an epoch-suffixed value made the client
  // log "Local major V8.006... vs Remote ..." mismatches (MainFormPlugin
  // 0x6630b8). No epoch suffix here.
  const self = selected.replace(/^V/, '').replace(/\.\d{9,10}$/, '');
  return envelope({
    upgradeable: false,
    version: clientMajorV,
    serverVersion: self,
    clientVersion: self,
    downloadUrl: '',
    releaseNote: '',
    list: [], results: []
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
// The DPSDK pipe writer of the response (0x180a488e0) exposes the legacy keys:
//   method, SessionId, UseMqFlag, MQConfig, MQUser, MQPwd, UserId, GroupId,
//   SSLEnable, UnSSLPort, CertificatePath, ProtocolVersion, TopicInfos.
// E-087 (Ghidra RE): the ACTUAL GetMqConfig response parser (FUN_180214d60,
// descriptor FUN_1806755a0/DAT_180f76610) reads STRING keys password/addr/
// mqtt/enableTls/userName - `addr` IS the "MQ Config" handed to MSG.exe.
// E-040: the gateway now RUNS the notify bus the client expects
// (ActiveMQ OpenWire 61616 via MSG.exe), so UseMqFlag=1 + addr
// "<host>:61616" + mqtt "" (empty mqtt => pipe path) are served (see
// buildMqConfigPayload). MQ_ENABLE=0 restores the old UseMqFlag=0 HTTP-only
// behavior. `info` and `data` are the observed wrapper keys; the GetMqConfig
// route additionally spreads the payload at root level (dual-key strategy).
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
  // E-087: BRMS.Organization.GetOrganizations - real GetOrganizationsVo list
  // (server package javap) served in every list-shaped alias.
  if (method === 'BRMS.Organization.GetOrganizations' || method === 'BRM.Organization.GetOrganizations' || method === 'BRMSOrganizationGetOrganizations') {
    return buildGetOrganizationsPayload();
  }
  return null;
}

async function brmRpcHandler(req) {
  const b = req.body || {};
  // E-133 (REA ses_e4217e907): 3-segment RPC keeps :cls in the method name -
  // BRM.Resource.Tree.GetDeviceOrg must NOT collapse to BRM.Resource.GetDeviceOrg.
  const method = b.method || (req.params.cls
    ? `BRM.${req.params.ns}.${req.params.cls}.${req.params.fn}`
    : `BRM.${req.params.ns}.${req.params.fn}`);
  // E-024: catalog methods over the RPC transport.
  const catalog = e024CatalogPayload(method, b);
  if (catalog) return rpcEnvelope(method, catalog);

  // E-133: tree RPCs used by the Monitoring Center Resources/Browser panel
  // (Resource.Tree.GetDeviceOrg -> departments[], BRMS.Tree.GetDeviceTree ->
  // devices[]). Same payloads as /admin/API/tree/deviceOrg|devices.
  if (/Resource\.Tree\.GetDeviceOrg$|Tree\.GetDeviceOrg$/.test(method) || method.endsWith('Tree.GetDeviceOrg')) {
    return rpcEnvelope(method, buildNativeOrgTreePayload());
  }
  if (/Tree\.GetDeviceTree$|Tree\.GetDevices$/.test(method) || method.endsWith('Tree.GetDeviceTree')) {
    return rpcEnvelope(method, buildNativeDeviceTreePayload((b.data || b)));
  }

  if (method === 'BRM.Config.GetMqConfig') {
    // E-040/E-087: real contract - UseMqFlag=1 + MQConfig/addr "<host>:61616"
    // (MSG.exe builds failover:(ssl://<addr>...startupMaxReconnectAttempts=1)
    // verbatim; the broker serves OpenWire over TLS with the lab System CA
    // keystore, MSG.exe sets decaf.net.ssl.disablePeerVerification) + mqtt
    // "<host>:1883" (non-empty => DPSDK libcurl-MQTT branch subscribes
    // directly on our dual-push broker; lab: MSG.exe never dialed 61616
    // with mqtt "") + the real brms.notify*
    // topic list (DPSDK.dll 0xc40450 / PROLogic.dll 0x62f7b0) + the DPSDK
    // descriptor keys password/addr/mqtt/enableTls/userName (FUN_1806755a0).
    const cfg = buildMqConfigPayload({ publicHost: PUBLIC_HOST, amqPort: AMQ_PORT, mqttPort: MQTT_PORT, enabled: MQ_ENABLE, httpsPort: HTTPS_PORT });
    // E-131: SessionId stays an INT (MSG.exe get<int>) - never String()
    cfg.SessionId = parseInt(b.clientPushId, 10) || cfg.SessionId;
    // dual-key: legacy envelope (info/data) AND root-level spread (the DPSDK
    // response parser may bind either layer).
    return { ...rpcEnvelope(method, cfg), ...cfg };
  }

  // ===== E-021: RPC shapes (parsers contracted via REA/DPSDK + live trace) =====
  // GetMenuRights registrar row: menuType / forbiddenMenus / menuRights
  // (DPSDK string pool 0x180cd6f08). E-022: serve REAL menuRights from leveldb.
  // E-035: the rights are the union of the REAL seed grants of the Super
  // Administrator role (sys_role_menu_default_relation, 86 codes) and the
  // REAL codes harvested from the server leveldb (158) - the leveldb harvest
  // was missing 14 real menus (001,002,003,004,010,002005004,002007002-4,
  // 003001002,004002003,004003002,004004004-5), so a menu could be hidden.
  if (method === 'BRM.User.GetMenuRights') {
    const rights = [...new Set([...(DSS_ROLE_MENU_CODES['1'] || []), ...REAL_MENU_RIGHTS])];
    return rpcEnvelope(method, {
      menuType: Number((b.data && b.data.menuType) || 2),
      menuRights: rights,
      rights,
      menuList: rights,
      forbiddenMenus: REAL_FORBIDDEN_MENUS,
      count: rights.length
    });
  }
  // GetChannelsCount parser reads int `count` (DPSDK 0x1800d3ed0).
  if (method === 'BRM.User.GetChannelsCount') return rpcEnvelope(method, { count: DEVICE_REGISTRY.size });
  // E-035: GetUserFunctions -> UserFunctionVo{List<String> functions}.
  // The codes are the REAL ones of the Super Administrator role
  // (adm_role_function ROLE_ID=1 in the server seed + FunctionType enum):
  // 1 record, 2 ptzOperateAndConfig, 3 talk, 5 recordLock, 6 recordTips,
  // 8 liveView, 9 playback, 10 download, 11 privacyMasking.
  // An EMPTY list told the client that the account owns no live-view /
  // playback function at all.
  if (method === 'BRM.User.GetUserFunctions') {
    const functions = DSS_ADMIN_FUNCTION_CODES.slice();
    return rpcEnvelope(method, {
      functions,
      functionList: functions,
      authorizedFunctionCodes: functions,
      devicePrivileges: DSS_ADMIN_DEVICE_PRIVILEGES.slice(),
      count: functions.length
    });
  }
  // E-037: the Monitor Center (Live View / Monitoring tabs) builds its
  // resource tree through these BRM RPC methods. They used to fall through to
  // the generic empty envelope, so the native tree stayed EMPTY.
  //   Resource.Tree.GetDeviceOrg  -> {departments:[OrgNodeVo]}
  //   Resource.Tree.GetDeviceTree -> {devices:[DeviceInfoVo]}
  //   Resource.Tree.GetDevices    -> {devices:[DeviceInfoVo]}
  //   Resource.Device.GetDeviceAllOrg / GetDeviceByOrgCode -> departments
  // Both spellings are dispatched: the transport URL /brms/api/BRM/:ns/:fn
  // prefixes "BRM." (observed in the mirrored client), and the DPSDK string
  // pool lists the plain "Resource.Tree.*" names.
  if (method === 'Resource.Tree.GetDeviceOrg' || method === 'BRM.Resource.Tree.GetDeviceOrg') {
    const p = buildNativeOrgTreePayload();
    return rpcEnvelope(method, { ...p, orgType: '1', subOrgCount: '0', hasData: p.departments.length ? '1' : '0' });
  }
  if (method === 'Resource.Tree.GetDeviceTree' || method === 'Resource.Tree.GetDevices' ||
      method === 'BRM.Resource.Tree.GetDeviceTree' || method === 'BRM.Resource.Tree.GetDevices') {
    const data = b.data || b;
    return rpcEnvelope(method, buildNativeDeviceTreePayload(data));
  }
  if (method === 'Resource.Device.GetDeviceAllOrg' || method === 'Resource.Device.GetDeviceByOrgCode' ||
      method === 'BRM.Resource.Device.GetDeviceAllOrg' || method === 'BRM.Resource.Device.GetDeviceByOrgCode') {
    return rpcEnvelope(method, buildNativeAllOrgPayload());
  }
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
  if (method === 'BRM.Device.GetCurrentMediaVK' || method === 'BRM.Config.GetCurrentMediaVK') {
    const hostIp = String((req.headers.host || '').split(':')[0] || '127.0.0.1');
    // E-134 D5 (FUN_1807512d0): el parser exige createDate/vkValue/algorithm/vkId
    const vk = crypto.createHash('md5').update('vk:' + hostIp).digest('hex');
    return rpcEnvelope(method, { vkId: '1', vkValue: vk, mediaKey: vk, algorithm: 'MD5', createDate: String(Math.floor(Date.now() / 1000)), ip: hostIp, port: 9100 });
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
    // E-039: RPC add also pushes the notify event (WS + MQ topics).
    try { NOTIFY.deviceEvent('DEVICE_ADDED', created); } catch { /* best effort */ }
    // E-034: the RPC path provisions the same per-device RTSP path.
    scheduleStreamProvisioning(created);
    // E-142 (rea-flows-v3 §5, FUN_1806e8170): the native AddDevice parser reads
    // exactly {deviceCode STRING, failedDevices:[{errorMsg,deviceIp}]}.
    return rpcEnvelope(method, {
      id: created.deviceCode,
      deviceCode: String(created.deviceCode),
      failedDevices: [],
      results: [created],
      list: [created],
      device: created,
      deviceVo: created
    });
  }
  // E-135: motor del catalogo RPC - payload por familia/P0 para los ~2.024
  // metodos del pool del cliente (ya no cae al stub vacio; code 1000).
  return rpcEnvelope(method, e135BuildRpcPayload(method, { ...(req.query || {}), ...b }));
}

app.post('/admin/API/BRM/:ns/:fn', brmRpcHandler);
app.post('/admin/api/BRM/:ns/:fn', brmRpcHandler);
// E-087: the DPSDK descriptor for BRMS.Organization.GetOrganizations
// (FUN_1806c97f0) registers it as a GET - serve both verbs.
app.get('/admin/API/BRM/:ns/:fn', brmRpcHandler);
app.get('/admin/api/BRM/:ns/:fn', brmRpcHandler);
// E-024: 3-segment BRMS RPC family (BRMS.Dictionary.GetDictionaries, ...).
// E-133: GET also served on the 3-segment family (some descriptors register
// GET, e.g. BRMS.Organization.GetOrganizations via FUN_1806c97f0).
const rpc3seg = async (req) => {
  const b = req.body || {};
  const method = b.method || `${req.params.ns}.${req.params.cls}.${req.params.fn}`;
  const catalog = e024CatalogPayload(method, b);
  if (catalog) return rpcEnvelope(method, catalog);
  return brmRpcHandler(req);
};
app.post('/admin/API/BRM/:ns/:cls/:fn', rpc3seg);
app.post('/admin/api/BRM/:ns/:cls/:fn', rpc3seg);
app.get('/admin/API/BRM/:ns/:cls/:fn', rpc3seg);
app.get('/admin/api/BRM/:ns/:cls/:fn', rpc3seg);
// Same RPC family probed under the /brms/api prefix (observed 404 E-019).
app.post('/brms/api/BRM/:ns/:fn', brmRpcHandler);
app.get('/brms/api/BRM/:ns/:fn', brmRpcHandler);
app.post('/brms/api/BRM/:ns/:cls/:fn', rpc3seg);
app.get('/brms/api/BRM/:ns/:cls/:fn', rpc3seg);
// E-134b: versioned BRM RPC family under /brms/api/v1.x (live journal 09-11
// FALLBACK: GET /brms/api/v1.1/BRM/Config/GetCurrentMediaVK?channelId=...).
for (const v of ['v1.0', 'v1.1']) {
  app.post(`/brms/api/${v}/BRM/:ns/:fn`, brmRpcHandler);
  app.get(`/brms/api/${v}/BRM/:ns/:fn`, brmRpcHandler);
  app.post(`/brms/api/${v}/BRM/:ns/:cls/:fn`, rpc3seg);
  app.get(`/brms/api/${v}/BRM/:ns/:cls/:fn`, rpc3seg);
}

// ===== E-019: post-login bootstrap unblocks (all observed 404 in live trace) =====

// Service status probes: /admin/API/server/serviceStatus/DA_SCS, DA_POC, ...
// E-141 (REA rea-media-path-noroute.md §5.3): this is one of the two
// server-side sources of the client's TCP candidates. FUN_1801f4ce0 expects
// s[250] @+0x01 plus two int ports @+0x40/+0x41 (stride 0x104); serve a
// superset that ALWAYS points at the DSS server/media host, never at a
// camera IP (the client must not learn 192.168.0.238 from here).
app.get('/admin/API/server/serviceStatus/:svc', async (req) => envelope({
  svc: String(req.params.svc),
  serverCode: String(req.params.svc),
  s: `rtsp://${PUBLIC_HOST}:${RTSP_PORT}`,
  ip: PUBLIC_HOST, host: PUBLIC_HOST, serverIp: PUBLIC_HOST,
  port: RTSP_PORT, rtspPort: RTSP_PORT, httpsPort: HTTPS_PORT,
  port1: RTSP_PORT, port2: HTTPS_PORT, ports: [RTSP_PORT, HTTPS_PORT],
  url: `rtsp://${PUBLIC_HOST}:${RTSP_PORT}`,
  status: 'online', serviceStatus: 'online', serverStatus: '1', state: 'online',
  online: true, onlineStatus: 1
}));
app.get('/admin/API/server/allServiceStatus', async () => envelope({
  list: [{ serverCode: 'DA_SCS', ip: PUBLIC_HOST, port: RTSP_PORT, url: `rtsp://${PUBLIC_HOST}:${RTSP_PORT}`, serviceStatus: 'online', online: true }],
  results: [{ serverCode: 'DA_SCS', ip: PUBLIC_HOST, port: RTSP_PORT, url: `rtsp://${PUBLIC_HOST}:${RTSP_PORT}`, serviceStatus: 'online', online: true }],
  serviceStatus: [], subServerIds: [], backupServerIds: [], switchType: '0', serverStatus: '1'
}));
// E-141: admin-API mirrors of the media-candidate list (allServiceStatus is
// registered once above for /admin/API; the /admin/api alias reuses it).
for (const host of ['/admin/API', '/admin/api']) {
  app.get(`${host}/server/video/list`, async () => envelope(buildVideoServerListPayload()));
  app.post(`${host}/server/video/list`, async () => envelope(buildVideoServerListPayload()));
}

// Device/org tree for the Qt stack (the "failed to get device data" blocker).
// E-037: the tree is now built with the REAL native contract recovered from
// the DSS Server V8.008 package:
//   GET  /admin/API/tree/deviceOrg -> DeviceOrgTreeVo{departments:[OrgNodeVo]}
//   POST /admin/API/tree/devices   -> DeviceTreeVo{devices:[DeviceInfoVo]}
// Before E-037 the gateway answered {orgList,deviceList,channelList}; the
// native client (DPSDK.dll string pool 0x180cdd138) parses "departments" and
// "devices", so the native tree was EMPTY -> the device never showed up in
// Live View / Monitoring / Storage (only the web SPA, which reads
// "deviceList", showed it). Both key sets are served, with real values only.
function adminTreePayload() {
  return buildNativeOrgTreePayload();
}
app.get('/admin/API/tree/deviceOrg', async () => envelope(adminTreePayload()));
app.get('/admin/api/tree/deviceOrg', async () => envelope(adminTreePayload()));

// E-035: menu availability. The previous answer was an INVENTED menu tree
// (ids 100..700, names like "Monitoring Center") which matches no real DSS
// menu code, so the launcher could not map a tile to its plugin.
// The REAL catalog comes from the server package seed (sys_menu, 86 rows) and
// the role grants from sys_role_menu_default_relation:
//   GET /brms/api/v1.1/menu/available/list?roleId=1
//     -> MenuController.getMenusById(Long) -> ResponseInfo<ListVo<MenuVo>>
//        ListVo{results}, MenuVo{menuCode, menuName, pid}
app.get('/brms/api/v1.1/menu/available/list', async (req) =>
  envelope(buildMenuAvailablePayload(req.query?.roleId ?? '1')));
// MenuController.checkMenuAvailable(code) -> MenuAvailableVo{available}
app.get('/brms/api/v1.1/menu/:code/available', async (req) =>
  envelope(buildMenuAvailableFlag(req.params?.code)));
// MenuController.getMenuFunctions(Integer) -> ListVo<MenuFunctionVo>
app.get('/brms/api/v1.1/menu/function/list', async () => envelope(buildFunctionListPayload()));

// System / config endpoints (shape unknown -> benign empties + dual keys).
// E-022: serve REAL functionConfig from leveldb cache.
app.get('/brms/api/v1.1/config/function', async () => envelope(REAL_FUNCTION_CONFIG));
app.get('/brms/api/v1.1/config/sira', async () => envelope({ siraEnable: 0, enable: false, status: '0' }));
app.get('/brms/api/v1.1/config/feature-analyse', async () => envelope({ enable: false, list: [] }));
app.get('/brms/api/v1.1/config/device-login-model', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
app.get('/brms/api/v1.1/config/interface/common/timeout', async () => envelope({ timeout: 300 }));
// (E-121: time-template/list + alarm/plan/alarm-type/list moved below with
// the real payloads)
app.get('/brms/api/v1.1/vtalk/sip/online/list', async () => envelope({ list: [] }));
app.get('/admin/API/config/videoIntercom', async () => envelope({ enable: 0, openState: '0' }));

// ===== E-108: the three genuinely-missing routes (live QA sweep 2026-11-07)
// 1) account/menu/list (DPSDK GetAccountMenuList, string pool @0xc9c8e0) - the
//    native menu list of the logged account. GetMenuRights already carries the
//    full 86-menu grant; serve the menu catalog with native string flags.
const accountMenuHandler = async (req) => {
  const payload = buildMenuAvailablePayload(String(req.query?.roleId || '1'));
  return envelope({ ...payload, menus: payload.results, menuList: payload.results });
};
// 2) config/videoIntercom - the /admin/API variant (66B) works; alias it on
//    the brms base the SPA calls (index-BhDUzoCV.js getVideoIntercom).
const videoIntercomHandler = async () => envelope({
  enable: '0', openState: '0', enableVideoIntercom: '0', status: '0', list: []
});
// 3) config/mail (SPA getMailConfig/updateMailConfig) - mail server config,
//    disabled by default, all string flags.
const mailConfigHandler = async () => envelope({
  enable: '0', enableMail: '0', status: '0', ssl: '0', useSsl: '0', useSSL: '0',
  server: '', host: '', ip: '', port: '25', userName: '', username: '', password: '',
  sender: '', senderName: '', senderAddress: '', address: '', nickName: '',
  encryptType: '0', testResult: '', remark: ''
});
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0', '/brms/api/v2.0', '/ipms/api/v1.1']) {
  app.get(`${host}/account/menu/list`, accountMenuHandler);
  app.post(`${host}/account/menu/list`, accountMenuHandler);
  app.get(`${host}/config/videoIntercom`, videoIntercomHandler);
  app.post(`${host}/config/videoIntercom`, videoIntercomHandler);
  app.get(`${host}/config/mail`, mailConfigHandler);
  app.post(`${host}/config/mail`, mailConfigHandler);
  app.put(`${host}/config/mail`, mailConfigHandler);
}

// ===== E-109: server list + storage endpoints (client FALLBACK hits) =======
import {
  buildServerListPayload, buildStoragePositionDevicePagePayload,
  buildLocalDiskListPayload, buildNetDiskListPayload, buildDiskGroupListPayload,
  buildVideoServerListPayload
} from './e109-storage.js';
// E-141: server/video/list carries the media candidates the client will TCP
// connect to (server host only). Register it explicitly so it never falls into
// the E-135 RPC catalog stub ('server.video.list' with servers: []).
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0', '/brms/api/v2.0', '/ipms/api/v1.1']) {
  app.get(`${host}/server/list`, async () => envelope(buildServerListPayload()));
  app.post(`${host}/server/list`, async () => envelope(buildServerListPayload()));
  app.get(`${host}/server/video/list`, async () => envelope(buildVideoServerListPayload()));
  app.post(`${host}/server/video/list`, async () => envelope(buildVideoServerListPayload()));
  // E-141 P1 (rea-remaining-gaps.md): real DPSDK FALLBACK still live.
  // data.warningServers[] + data.warningHappened STRING (SDK does atoi()).
  app.get(`${host}/storage/configure/picture/warning`, async () => envelope({ warningServers: [], warningHappened: '0' }));
  app.post(`${host}/storage/configure/picture/warning`, async () => envelope({ warningServers: [], warningHappened: '0' }));
  app.get(`${host}/storage/position/device/page`, async (req) => envelope(buildStoragePositionDevicePagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/storage/position/device/page`, async (req) => envelope(buildStoragePositionDevicePagePayload({ ...req.query, ...(req.body || {}) })));
  app.get(`${host}/storage/disk/local-disk/list`, async () => envelope(buildLocalDiskListPayload()));
  app.post(`${host}/storage/disk/local-disk/list`, async () => envelope(buildLocalDiskListPayload()));
  app.get(`${host}/storage/disk/net-disk/list`, async () => envelope(buildNetDiskListPayload()));
  app.post(`${host}/storage/disk/net-disk/list`, async () => envelope(buildNetDiskListPayload()));
  app.get(`${host}/storage/group/list`, async () => envelope(buildDiskGroupListPayload()));
  app.post(`${host}/storage/group/list`, async () => envelope(buildDiskGroupListPayload()));
}

// E-110: RE evidence (PluginFactory.dll @0x180ac3780/@0x180ac4370, DPSDK
// CheckLoginValid @0x1800d3080) shows the client may build config URLs on the
// /cfgs/api prefix too (GetLdapConfig 0x1801f75a7 picks the subsystem prefix).
// "Abnormal network" = ErrorId -18 (empty m_strToken), so a config call routed
// to an unserved prefix failed with the benign catch-all and no token context.
// Mirror the hot config endpoints on /cfgs/api so the prefix choice cannot
// break them.
for (const host of ['/cfgs/api/v1.1', '/cfgs/api/v1.0']) {
  app.get(`${host}/config/ldap`, async () => envelope(buildLdapConfigPayload()));
  app.post(`${host}/config/ldap`, async () => envelope(buildLdapConfigPayload()));
  app.get(`${host}/config/mail`, mailConfigHandler);
  app.post(`${host}/config/mail`, mailConfigHandler);
  app.get(`${host}/config/videoIntercom`, videoIntercomHandler);
  app.get(`${host}/config/function`, async () => envelope(REAL_FUNCTION_CONFIG));
  app.get(`${host}/config/sira`, async () => envelope({ siraEnable: 0, enable: false, status: '0' }));
  app.get(`${host}/config/interface/common/timeout`, async () => envelope({ timeout: 300 }));
  app.get(`${host}/account/menu/list`, accountMenuHandler);
  app.get(`${host}/account/user/level`, async () => envelope(buildUserLevelPayload()));
}

// ===== E-111: module coverage (Log / Alarm / License / TVWall / Config) =====
// Endpoints the SPA calls when opening each submenu that had no registration
// (SPA API inventory cross-check) - they now return real shapes instead of the
// benign catch-all, so every submenu opens populated.
import {
  buildSystemLogPagePayload, buildOperateLogPagePayload, buildSystemLogEventTypeListPayload,
  buildServiceStatusPayload, buildOmcServiceTypeListPayload, buildLogClientConfigPayload,
  buildAlarmPlanPagePayload, buildAlarmRecordPagePayload, buildAlarmPlanResourceConfigStatusPayload,
  buildLicenseItemListPayload, buildLicenseUsedListPayload, buildLicenseDetailPayload, buildLicenseComponentsPayload,
  buildTvWallWindowPayload, buildTvWallCapacityPayload,
  buildMessageStorageConfigPayload, buildTimeSyncConfigPayload, buildQuickCommandListPayload,
  buildTlsCertDetailPayload, buildSubOssPortPayload, buildExportPasswordPayload
} from './e111-modules.js';
{
  // --- Log module (useLogApi-BPm4Cd0K.js) ---
  const logPage = async (req) => envelope(buildSystemLogPagePayload({ ...req.query, ...(req.body || {}) }));
  const opLog = async (req) => envelope(buildOperateLogPagePayload({ ...req.query, ...(req.body || {}) }));
  for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
    app.post(`${host}/log/system-log/page`, logPage);
    app.get(`${host}/log/system-log/page`, logPage);
    app.post(`${host}/log/operate-log`, opLog);
    app.get(`${host}/log/operate-log`, opLog);
    app.get(`${host}/log/system-log/event-type/list`, async () => envelope(buildSystemLogEventTypeListPayload()));
    app.post(`${host}/log/system-log/event-type/list`, async () => envelope(buildSystemLogEventTypeListPayload()));
    app.get(`${host}/log/omc/service/type/list`, async () => envelope(buildOmcServiceTypeListPayload()));
    app.get(`${host}/log/service-log/service/:serviceId/status`, async () => envelope(buildServiceStatusPayload()));
    app.post(`${host}/log/service-log/service/:serviceId/status`, async () => envelope(buildServiceStatusPayload()));
    app.get(`${host}/log/client-config`, async () => envelope(buildLogClientConfigPayload()));
    app.post(`${host}/log/client-config`, async () => envelope(buildLogClientConfigPayload()));
  }
  // --- Alarm module (useEventApi-DiKk_pnU.js) ---
  // (E-121: alarm/plan/fetch/page moved there with the default plan payload)
  for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
    app.post(`${host}/alarm/plan`, async () => envelope({ success: true, planId: '1', id: '1' }));
    app.get(`${host}/alarm/plan/:planId`, async (req) => envelope({ planId: String(req.params?.planId || '1'), id: String(req.params?.planId || '1'), planName: 'Default Plan', enable: '1', status: '1' }));
    app.put(`${host}/alarm/plan/:planId`, async () => envelope({ success: true }));
    app.delete(`${host}/alarm/plan/:planId`, async () => envelope({ success: true }));
    app.post(`${host}/alarm/plan/delete/batch`, async () => envelope({ success: true, failedList: [] }));
    app.post(`${host}/alarm/plan/resource/config-status/fetch/batch/list`, async () => envelope(buildAlarmPlanResourceConfigStatusPayload()));
    app.post(`${host}/alarm/record/fetch/page`, async (req) => envelope(buildAlarmRecordPagePayload({ ...req.query, ...(req.body || {}) })));
    app.get(`${host}/alarm/record/fetch/page`, async (req) => envelope(buildAlarmRecordPagePayload({ ...req.query, ...(req.body || {}) })));
  }
  // --- License module (useLicenseApi) ---
  for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
    app.get(`${host}/license/item/list`, async () => envelope(buildLicenseItemListPayload()));
    app.get(`${host}/license/used/list`, async () => envelope(buildLicenseUsedListPayload()));
    app.get(`${host}/license/detail`, async () => envelope(buildLicenseDetailPayload()));
    app.get(`${host}/license/components`, async () => envelope(buildLicenseComponentsPayload()));
    for (const f of ['express-to-pro/active/file/export', 'care/active/file/export', 'deactivate/file/export', 'reactive/file/export']) {
      app.post(`${host}/license/${f}`, async () => envelope({ success: true, fileUrl: '', taskId: '1' }));
    }
  }
  // --- TVWall (useTVWallApi admin base) ---
  app.get('/admin/API/tvwall/window', async () => envelope(buildTvWallWindowPayload()));
  app.post('/admin/API/tvwall/window', async () => envelope(buildTvWallWindowPayload()));
  app.post('/admin/API/VMS/TvWall/GetTvWallCapacity', async () => envelope(buildTvWallCapacityPayload()));
  app.get('/brms/api/v1.1/tvwall/page', async (req) => envelope(buildAlarmPlanPagePayload({ ...req.query, ...(req.body || {}) })));
  // --- System config pages (index-BhDUzoCV.js) ---
  for (const host of ['/brms/api/v1.1', '/brms/api/v1.0', '/cfgs/api/v1.1']) {
    app.get(`${host}/config/message-storage`, async () => envelope(buildMessageStorageConfigPayload()));
    app.put(`${host}/config/message-storage`, async () => envelope(buildMessageStorageConfigPayload()));
    app.get(`${host}/config/time-sync`, async () => envelope(buildTimeSyncConfigPayload()));
    app.put(`${host}/config/time-sync`, async () => envelope(buildTimeSyncConfigPayload()));
    app.post(`${host}/config/time-sync/immediate`, async () => envelope({ success: true }));
    app.get(`${host}/config/quick/command/list`, async () => envelope(buildQuickCommandListPayload()));
    app.get(`${host}/config/tls/cert/detail`, async () => envelope(buildTlsCertDetailPayload()));
    app.post(`${host}/config/tls/cert/generate`, async () => envelope({ success: true, certId: '1' }));
    app.post(`${host}/config/tls/cert/import`, async () => envelope({ success: true, certId: '1' }));
    app.get(`${host}/config/tls/cert/export`, async () => envelope({ success: true, fileUrl: '' }));
    app.get(`${host}/config/sub-oss-port`, async () => envelope(buildSubOssPortPayload()));
    app.get(`${host}/config/export-password`, async () => envelope(buildExportPasswordPayload()));
  }
}

// ===== E-118: Event Center protocol (DPSDK string pool @0xcbba90 etc.) =====
import {
  buildEventCenterAlarmTypesPayload, buildEventCenterAlarmCountPayload,
  buildEventCenterSubscribePayload, toNativeAlarmEvent, DSS_ALARM_TYPE_CATALOG
} from './e118-event-center.js';
// The client opens the alarm pull queue here after GetMqConfig advertises it.
for (const host of ['/videoService', '/brms/api/v1.1', '/brms/api/v1.0']) {
  app.post(`${host}/eventCenter/messages/subscribe`, async (req) => envelope(buildEventCenterSubscribePayload({ ...req.query, ...(req.body || {}) })));
  app.get(`${host}/eventCenter/messages/subscribe`, async (req) => envelope(buildEventCenterSubscribePayload({ ...req.query, ...(req.body || {}) })));
  app.get(`${host}/eventCenter/alarmTypes`, async () => envelope(buildEventCenterAlarmTypesPayload()));
  app.post(`${host}/eventCenter/alarmTypes`, async (req) => envelope(buildEventCenterAlarmTypesPayload(req.body || req.query || {})));
  // E-142: the native client calls alarm count with POST (FUN_180248de0) and
  // parses a single numeric totalCount.
  app.get(`${host}/eventCenter/alarm/messages/count`, async () => envelope(buildEventCenterAlarmCountPayload()));
  app.post(`${host}/eventCenter/alarm/messages/count`, async () => envelope(buildEventCenterAlarmCountPayload()));
}

// ===== E-121: Event Config completion + TVWall + OMMS alert + subscription ===
import {
  buildAlarmPlanListPayload, buildAlarmTypeListPayload,
  buildMailTemplateListPayload, buildVacationTemplateListPayload, buildTimeTemplateListPayload,
  buildTvWallsPayload, buildTvWallDetailPayload,
  buildOmmsAlertListPayload, buildOmmsAlertRuleListPayload, buildOmmsAlertStatisticsPayload,
  buildIvssListPayload, buildEventSubscriptionPayload, buildAlarmOverviewSummaryPayload
} from './e121-modules-b.js';
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  // P0: the alarm-plan panel needs the REAL type catalog + a default plan
  app.get(`${host}/alarm/plan/alarm-type/list`, async () => envelope(buildAlarmTypeListPayload()));
  app.post(`${host}/alarm/plan/alarm-type/list`, async () => envelope(buildAlarmTypeListPayload()));
  app.post(`${host}/alarm/plan/fetch/page`, async (req) => envelope(buildAlarmPlanListPayload({ ...req.query, ...(req.body || {}) })));
  app.get(`${host}/alarm/plan/fetch/page`, async (req) => envelope(buildAlarmPlanListPayload({ ...req.query, ...(req.body || {}) })));
  // P2: alarm/plan sub-routes (templates, soft-trigger, transparence, pos, batch)
  for (const sub of ['alarm-type/custom', 'alarm-type/soft-trigger', 'alarm-type/transparence', 'alarm-type/pos', 'template']) {
    app.get(`${host}/alarm/plan/${sub}`, async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0', enable: '1', status: '1' }));
    app.post(`${host}/alarm/plan/${sub}`, async () => envelope({ success: true, id: '1' }));
    app.put(`${host}/alarm/plan/${sub}/:id`, async () => envelope({ success: true }));
    app.delete(`${host}/alarm/plan/${sub}/:id`, async () => envelope({ success: true }));
  }
  app.get(`${host}/alarm/plan/alarm-type/transparence/list`, async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
  app.post(`${host}/alarm/plan/alarm-type/:typeId/source/list`, async () => envelope(buildAlarmPlanResourceConfigStatusPayload()));
  app.post(`${host}/alarm/plan/status/update/batch`, async () => envelope({ success: true, results: [] }));
  app.post(`${host}/alarm/plan/source/delete/batch`, async () => envelope({ success: true, results: [] }));
  // templates (mail / vacation / time)
  app.get(`${host}/mail-template/list`, async () => envelope(buildMailTemplateListPayload()));
  app.get(`${host}/vacation-template/list`, async () => envelope(buildVacationTemplateListPayload()));
  app.get(`${host}/time-template/list`, async (req) => envelope(buildTimeTemplateListPayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/time-template`, async () => envelope({ success: true, templateId: '1' }));
  app.get(`${host}/time-template/:templateId`, async (req) => envelope({ templateId: String(req.params?.templateId || '1'), templateName: 'All Day', enable: '1', status: '1' }));
  // device ivss + alarm output + report export
  app.get(`${host}/device/ivss/list`, async () => envelope(buildIvssListPayload()));
  app.post(`${host}/device/channel/alarm-output/control`, async () => envelope({ success: true }));
  app.post(`${host}/alarm/overview/report/export`, async () => envelope({ success: true, taskId: '1', fileUrl: '' }));
  // P3: event subscription GET + overview summary v1.0 (v1.1 is served by the
  // bootstrap route below)
  if (host === '/brms/api/v1.0') {
    app.get(`${host}/event/subscription`, async () => envelope(buildEventSubscriptionPayload()));
    app.post(`${host}/event/subscription`, async () => envelope(buildEventSubscriptionPayload()));
    app.get(`${host}/alarm/overview/summary`, async (req) => envelope(buildAlarmOverviewSummaryPayload({ ...req.query, ...(req.body || {}) })));
  }
}
// P1/P2: TVWall SPA routes + RPC mirrors
app.get('/brms/api/v1.1/tvwalls', async () => envelope(buildTvWallsPayload()));
app.get('/brms/api/v1.0/tvwalls', async () => envelope(buildTvWallsPayload()));
app.get('/brms/api/v1.1/tvwall/:tvWallId', async (req) => envelope(buildTvWallDetailPayload(req.params?.tvWallId || '1')));
app.post('/admin/API/BRM/TvWall/GetTvWalls', async () => envelope({ method: 'BRM.TvWall.GetTvWalls', tvWalls: buildTvWallsPayload().list, list: buildTvWallsPayload().list, results: buildTvWallsPayload().list, info: buildTvWallsPayload(), data: buildTvWallsPayload() }));
app.post('/admin/API/BRM/TvWall/GetTvWall', async (req) => envelope({ method: 'BRM.TvWall.GetTvWall', ...buildTvWallDetailPayload(req.body?.tvWallId || '1'), info: buildTvWallDetailPayload(req.body?.tvWallId || '1'), data: buildTvWallDetailPayload(req.body?.tvWallId || '1') }));
// P2: OMMS alert routes (list / rules / statistics / handle-collect-procedure)
for (const host of ['/omms/api/v1.1', '/omms/api/v1.0']) {
  app.get(`${host}/alert/rule/list`, async () => envelope(buildOmmsAlertRuleListPayload()));
  app.post(`${host}/alert/rule/list`, async () => envelope(buildOmmsAlertRuleListPayload()));
  app.get(`${host}/alert/statistics`, async () => envelope(buildOmmsAlertStatisticsPayload()));
  app.get(`${host}/alert/message/list`, async () => envelope(buildOmmsAlertListPayload()));
  app.post(`${host}/alert/handle`, async (req) => envelope({ success: true, alertId: String(req.body?.alertId || '') }));
  app.post(`${host}/alert/collect`, async (req) => envelope({ success: true, alertId: String(req.body?.alertId || '') }));
  app.post(`${host}/alert/procedure`, async (req) => envelope({ success: true, procedureId: '1' }));
}

// ===== E-117: Event Center + Generic Event ingestion =======================
import {
  buildGeneralEventPagePayload, buildGeneralEventConfigPayload, buildAlertSubscribePayload,
  buildAlarmOverviewTopSourcePayload, buildAlarmOverviewTopTypePayload, buildAlarmOverviewTrendPayload,
  buildPrerecordChannelPagePayload, buildDisarmConfigPagePayload, buildStormRestrainAlarmTypePayload,
  buildCombinationSourcePagePayload, ingestGeneralEvent, findEventById, updateEventById
} from './e117-alarm-events.js';
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  // Generic Event ingest (DSS custom-event channel): the client lists events,
  // the operator/system creates them; every created event is pushed live to
  // the Event Center over MQ (brms.notifyAlarms + mq.alarm.msg.topic.*).
  app.get(`${host}/alarm/general/event/list`, async (req) => envelope(buildGeneralEventPagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/general/event/list`, async (req) => envelope(buildGeneralEventPagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/general/event`, async (req) => {
    const ev = ingestGeneralEvent({ ...req.query, ...(req.body || {}) });
    try { NOTIFY.alarmEvent(ev); } catch { /* hub not ready */ }
    // E-136: ingesta en el store persistente + cola del pull-queue del Event Center.
    try { e136Ctx.e136?.eventCenter?.publishAlarm(ev); } catch { /* e136 no cableado */ }
    return envelope({ success: true, eventId: ev.eventId, alarmId: ev.eventId });
  });
  app.get(`${host}/alarm/general/event/:eventId`, async (req, reply) => {
    const row = findEventById(req.params?.eventId);
    return row ? envelope(row) : reply.code(404).send(envelope(null, 404, 'event not found'));
  });
  // P0: the edit must PERSIST (the client lost its edits silently before)
  app.put(`${host}/alarm/general/event/:eventId`, async (req, reply) => {
    const ev = updateEventById(req.params?.eventId, { ...req.query, ...(req.body || {}) });
    return ev ? envelope({ success: true, eventId: ev.eventId, alarmId: ev.alarmId, ...ev }) : reply.code(404).send(envelope(null, 404, 'event not found'));
  });
  app.post(`${host}/alarm/general/event/:eventId`, async (req, reply) => {
    const ev = updateEventById(req.params?.eventId, { ...req.query, ...(req.body || {}) });
    return ev ? envelope({ success: true, eventId: ev.eventId }) : reply.code(404).send(envelope(null, 404, 'event not found'));
  });
  app.delete(`${host}/alarm/general/event/:eventId`, async (req) => envelope({ success: true }));
  app.get(`${host}/config/general/event`, async () => envelope(buildGeneralEventConfigPayload()));
  app.put(`${host}/config/general/event`, async () => envelope(buildGeneralEventConfigPayload()));
  // Event Center stats + config
  app.get(`${host}/alarm/overview/top/alarm-source/list`, async () => envelope(buildAlarmOverviewTopSourcePayload()));
  app.get(`${host}/alarm/overview/top/alarm-type/list`, async () => envelope(buildAlarmOverviewTopTypePayload()));
  app.get(`${host}/alarm/overview/trend`, async () => envelope(buildAlarmOverviewTrendPayload()));
  app.get(`${host}/alarm/config/prerecord/channel/page`, async (req) => envelope(buildPrerecordChannelPagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/config/prerecord/channel/page`, async (req) => envelope(buildPrerecordChannelPagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/config/prerecord/channel/update/batch`, async () => envelope({ success: true }));
  app.get(`${host}/alarm/disarm/config/page`, async (req) => envelope(buildDisarmConfigPagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/disarm/config/update/batch`, async () => envelope({ success: true }));
  app.get(`${host}/alarm/storm/restrain/alarm-type/list`, async () => envelope(buildStormRestrainAlarmTypePayload()));
  app.get(`${host}/alarm/combination/source/page`, async (req) => envelope(buildCombinationSourcePagePayload({ ...req.query, ...(req.body || {}) })));
  app.post(`${host}/alarm/combination/source/page`, async (req) => envelope(buildCombinationSourcePagePayload({ ...req.query, ...(req.body || {}) })));
}
// alert subscription (OMMS) - what the Event Center subscribes to
app.get('/omms/api/v1.1/alert/subscribe', async () => envelope(buildAlertSubscribePayload()));
app.post('/omms/api/v1.1/alert/subscribe', async (req) => envelope({ success: true, subscribe: '1' }));
app.get('/brms/api/v1.1/omms/alert/subscribe', async () => envelope(buildAlertSubscribePayload()));
// generic-event ingest bridge (no session token required for external systems)
app.post('/admin/API/GenericEvent/Report', async (req) => {
  const ev = ingestGeneralEvent(req.body || {});
  try { NOTIFY.alarmEvent(ev); } catch { /* hub not ready */ }
  // E-136: ingesta en el store persistente + cola del pull-queue del Event Center.
  try { e136Ctx.e136?.eventCenter?.publishAlarm(ev); } catch { /* e136 no cableado */ }
  return envelope({ success: true, eventId: ev.eventId });
});

// Licenses + system self-check warnings (all benign: no disk/license issues).
// E-112: the client's key-existence check (CommonFunc.cpp:149) marked these
// as "Invalid key" in the live log: QueryHostSpareWarning -> warningHappened,
// PacketGetMemoryOutOfServerList / PacketGetBasicServiceWarm -> results.
// E-126 (forensic report 2026-11-08): the live client log shows IsKeyValid
// failing on [warningTime] [warningHappened] [results] [abnormityType] ->
// 5x "The data returned by the service is abnormal" (ErrorId 3101) at every
// login even with code=1000. All validated keys are now present as STRINGS.
// E-132 (client log 2026-11-08 22:16:41 IsKeyValid ERR in the live session):
// [warningContent] + [warningType] were still missing -> ErrorId 3101 toasts.
// Full warning key set as STRINGS on every warning/abnormity endpoint.
const WARN_KEYS = {
  warning: 0, warningHappened: '0', warningHappenedNum: '0', warningTime: '0',
  warningContent: '', warningType: '0', warningLevel: '0', warningTitle: '',
  standbyServerRemainDays: '0', abnormityType: '0', abnormity: '0', abnormal: 0,
  expireRemainDays: '0',
  warningList: [], list: [], results: [], items: [], total: '0', totalCount: '0'
};
// E-133: disk/memory server lists carry one benign element with the per-row
// keys IsKeyValid checks (serverIp/serverType/warnDisks), not just results:[]
const DISK_ROWS = [{ serverIp: '127.0.0.1', serverName: 'BRMS-LAB', serverType: '1', status: '1', warnDisks: [], diskList: [], total: '0' }];
const MEM_ROWS = [{ serverIp: '127.0.0.1', serverName: 'BRMS-LAB', serverType: '1', status: '1', memoryUsage: '0', totalMemory: '0', usedMemory: '0', freeMemory: '0' }];
app.get('/brms/api/v1.1/license/warning', async () => envelope({ ...WARN_KEYS }));
app.get('/brms/api/v1.1/license/hot-spare/abnormity', async () => envelope({ ...WARN_KEYS }));
app.get('/brms/api/v1.1/system/hot-spare/switch/warning', async () => envelope({ ...WARN_KEYS }));
app.get('/brms/api/v1.1/system/warn/disk/list', async () => envelope({ ...WARN_KEYS, list: DISK_ROWS, results: DISK_ROWS, items: DISK_ROWS }));
app.get('/brms/api/v1.1/system/out/memory/server/list', async () => envelope({ ...WARN_KEYS, list: MEM_ROWS, results: MEM_ROWS, items: MEM_ROWS }));
app.get('/brms/api/v1.1/system/only-startup-basic-service/warning', async () => envelope({ ...WARN_KEYS }));
// E-133 (REA ses_e4217e907): the SPA calls these with POST - the GET-only
// registration left them on the 40B fallback {"data":{}} -> 3101 toasts.
for (const p of [
  '/brms/api/v1.1/license/warning',
  '/brms/api/v1.1/license/hot-spare/abnormity',
  '/brms/api/v1.1/license/hot-spare/info',
  '/brms/api/v1.1/system/hot-spare/switch/warning',
  '/brms/api/v1.1/system/only-startup-basic-service/warning',
  '/brms/api/v1.1/system/warn/disk/list',
  '/brms/api/v1.1/system/out/memory/server/list'
]) {
  app.post(p, async () => envelope({ ...WARN_KEYS, info: { ...WARN_KEYS } }));
}
// E-133: verb symmetry on the native tree org endpoint.
app.post('/admin/API/tree/deviceOrg', async () => envelope(adminTreePayload()));
app.post('/admin/api/tree/deviceOrg', async () => envelope(adminTreePayload()));

// Access (OBMS) + parking (IPMS) empty modules.
app.get('/obms/api/v1.1/acp/area/list', async () => envelope({ list: [], total: 0 }));
app.get('/obms/api/v1.1/acs/person-group/list', async () => envelope({ list: [], total: 0 }));
// E-093: the native CDevAdd "Organization" combo (cmbGroupName) is filled by
// DPSDK GetOrgList -> GET /ipms/api/v1.1/organization/list (FUN_1802af3d0,
// parser FUN_1804c5f00). It was served EMPTY ({list:[],total:0}, cl=59 -
// checklist 2026-11-05 ~04:05 UTC), so the combo listed nothing and
// join/batch went out with orgCode:"". Serve the persistent org store
// (001 root + VIGILAB) with dual keys list/results + total/count; item keys
// per RE-SCHEMA-DPSDK.md §5.2 (see buildOrganizationListPayload).
app.get('/ipms/api/v1.1/organization/list', async () => envelope(buildOrganizationListPayload()));
// Same contract under the BRMS prefix the web SPA calls (useDeviceApi getOrg
// -> /brms/api/v1.1/organization/list); registered before the /brms/api/*
// fallback below so the real orgs win over {list:[],total:0}.
app.get('/brms/api/v1.1/organization/list', async () => envelope(buildOrganizationListPayload()));
app.get('/brms/api/v1.0/organization/list', async () => envelope(buildOrganizationListPayload()));
app.post('/ipms/api/v1.1/organization/list', async () => envelope(buildOrganizationListPayload()));
app.get('/ipms/api/v1.1/parking-lot/detail/list', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
app.get('/IPMS/API/entrance/parking-lot/binding-vto-itc', async () => envelope({ list: [], count: 0 }));

// ===== E-020: remaining bootstrap 404s + launcher devices + fallbacks =====

// Qt-side device lists (observed 404: /admin/API/tree/devices).
// E-025: serve the live registry (manual adds + discoveries + auto-register)
// instead of the static mock so the tree always reflects the devices.
app.get('/admin/API/tree/devices', async () => {
  const p = adminTreePayload();
  return envelope({ ...p, list: p.deviceList, total: p.deviceList.length });
});
app.get('/admin/API/tree/equipment-tree', async () => envelope(adminTreePayload()));
app.get('/admin/API/tree/search', async () => {
  const p = adminTreePayload();
  return envelope({ list: p.deviceList, total: p.deviceList.length });
});

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
  // E-087 (real package, AvailableServerVo javap): the VO carries ONLY
  // {serverCode, serverName} - the Server combo of the Add Device dialog
  // shows the server by its `name`, which on a real DSS install is the
  // server IP (adm_server gets seeded with the local IP). Our lab therefore
  // serves serverName = PUBLIC_HOST while keeping the client's expected
  // serverCode "video#local" (PROLogic string pool, E-024 evidence).
  const results = DAHUA_AVAILABLE_SERVERS.map((s) => ({ ...s, serverName: PUBLIC_HOST }));
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
// E-095: overview must derive from the live registry, not hardcoded 1/1/0
// (the SPA home header reads deviceCount/onlineDeviceCount/offlineDeviceCount).
app.get('/brms/api/v1.1/account/device/overview', async () => {
  const devs = [...DEVICE_REGISTRY.values()];
  const dc = devs.length;
  const oc = devs.filter((d) => deviceOnlineOf(d)).length;
  const cc = devs.reduce((n, d) => n + Math.max(1, Number(d.channelNum) || 1), 0);
  return envelope({
    deviceCount: dc, onlineDeviceCount: oc, offlineDeviceCount: dc - oc,
    channelCount: cc, onlineChannelCount: oc, offlineChannelCount: cc - oc,
    overview: { deviceCount: dc, onlineDeviceCount: oc, offlineDeviceCount: dc - oc }
  });
});

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
  // E-025/E-039: push a device-added notification over WS AND the real MQ
  // notify topics so the native client refreshes its tree immediately instead
  // of expiring on the CDevAdd 30 s "Operation timed out" timer.
  try {
    NOTIFY.deviceEvent('DEVICE_ADDED', created);
  } catch (err) {
    console.log('[E025-ADD] notify broadcast failed:', err.message);
  }

  // E-034: per-device RTSP path. The path name is already known (it only
  // depends on the device code); the RTSP source is discovered from the
  // camera (ONVIF GetStreamUri, Dahua convention as last resort) and the
  // MediaMTX path is configured in the background so the client never waits.
  if (created) {
    setImmediate(async () => {
      try { await ensureDeviceStream(created); }
      catch (err) { console.log('[E034-STREAM] manual add failed:', err.message); }
      // E-097: no-refresh manual refresh - status push after provisioning.
      try { NOTIFY.deviceEvent('DEVICE_STATUS', created); } catch { /* best effort */ }
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
app.post('/brms/api/v1.1/device/delete/batch', async (req) => {
  const codes = [].concat(req.body?.deviceCodes || req.body?.codes || req.body?.list || []).filter(Boolean);
  const payload = buildDeviceDeleteBatchPayload(req.body);
  // E-039: deleted devices are pushed too (tree must drop them without relogin).
  for (const code of codes) {
    try { NOTIFY.deviceEvent('DEVICE_DELETED', { deviceCode: String(code), deviceId: String(code) }); } catch { /* best effort */ }
  }
  return envelope(payload);
});
app.post('/brms/api/v1.1/device/move/batch', async (req) => envelope(buildDeviceMoveBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/password/change/batch', async (req) => envelope(buildDevicePasswordChangeBatchPayload(req.body)));
app.post('/brms/api/v1.1/device/timezone/update/batch', async (req) => envelope(buildDeviceTimezoneUpdateBatchPayload(req.body)));
// E-144: device modify (Device Management edit). Updates name/ip/port/creds,
// invalidates the cached RTSP source and re-provisions the MediaMTX path
// inside the running process, then pushes DEVICE_STATUS so the tree refreshes.
for (const p of ['/brms/api/v1.1/device/modify/batch', '/brms/api/v1.0/device/modify/batch', '/brms/api/v1.1/device/update/batch', '/brms/api/v1.1/device/modify']) {
  app.post(p, async (req) => {
    const payload = buildDeviceModifyBatchPayload(req.body);
    // E-039: modified devices push too (tree reflects the edit without relogin).
    for (const r of payload.results || []) {
      if (r.success) { try { NOTIFY.deviceEvent('DEVICE_STATUS', { deviceCode: r.deviceCode, deviceId: r.deviceCode }); } catch { /* best effort */ } }
    }
    return envelope(payload);
  });
}

// ===== E-027: STORAGE PLAN / SS RECORD ROUTES =====
// Needed by the Storage Plan tab (003005) and the Device Config dialogs.
import {
  buildPlanConfigStatusPayload,
  getChannelRecordPlan,
  setChannelRecordPlan,
  buildSSQueryRecordPayload,
  buildSSRecordActionPayload
} from './e027-storage.js';
import {
  buildRecordPlanPagePayload,
  buildMotionDetectionRecordPlanPagePayload,
  buildUserLevelPayload,
  buildAreaTimezonePayload
} from './e029-spa-contracts.js';
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

// ===== E-029: real SPA response contracts =====
// These six routes previously fell through to the generic [FALLBACK] responder
// ({code:1000,data:{list:[],total:0}}), which is what produced the ~20
// "Abnormally returned the service or device data" toasts and left the Device
// Config view loading forever (its device tree is lazy-loaded from
// grade-device-tree). Shapes verified against the production bundle consumers:
//   grade-device-tree -> .pnpm-IcGsI3MK.js BatchLoadingTree.load
//                        {devices[], organizations[]} (+channels for search)
//   record-plan/page  -> index-6GKB6cBD.js recordPlan view {totalCount, pageData}
//   motion-detection-record-plan/page -> index-dpjg75Ex.js same shape
//   account/user/level -> index-BhDUzoCV.js bootstrap data.level
//   config/timezone/info -> index-BhDUzoCV.js bootstrap dst/enableDst/offset/dst*
// (E-124: the tree/grade-device-tree POST variants are registered below in the
// E-101 block with the full RE payload - the old E-029 stubs are removed.)
// E-101: the Users/Config permission dialog calls the GET variants with
// /full/ in the path (observed live 22:53:21Z -> fell into [FALLBACK]
// {list:[],total:0}, leaving the permission tree loading forever = AppHang).
// GET and POST, plain and /full/, v1.0 and v1.1 - query and body merged.
// E-124: both variants now serve the RE-verified full grade tree
// (organizations -> devices -> channels, every node with checked/hasAuthority
// as STRING so the native tree renders the checkboxes enabled/clickable).
import { buildFullGradeDeviceTreePayload, buildFullGradeDeviceTreeSearchPayload } from './e124-grade-tree.js';
// E-140: query wins over body so `orgCode` is always the one DPSDK sends as a
// query parameter on GET /v1.1/tree/full/grade-device-tree?orgCode=<node>&roleId=1
// (the native Resources tree lazy-loads one level per request; see
// e124-grade-tree.js buildFullGradeDeviceTreePayload scope logic).
const gdtHandler = async (req) => envelope(buildFullGradeDeviceTreePayload({ ...(req.body || {}), ...req.query }));
const gdtSearchHandler = async (req) => envelope(buildFullGradeDeviceTreeSearchPayload({ ...(req.body || {}), ...req.query }));
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  app.get(`${host}/tree/grade-device-tree`, gdtHandler);
  app.post(`${host}/tree/grade-device-tree`, gdtHandler);
  app.get(`${host}/tree/full/grade-device-tree`, gdtHandler);
  app.post(`${host}/tree/full/grade-device-tree`, gdtHandler);
  app.get(`${host}/tree/grade-device-tree/search/list`, gdtSearchHandler);
  app.get(`${host}/tree/full/grade-device-tree/search/list`, gdtSearchHandler);
  app.post(`${host}/tree/full/grade-device-tree/search/list`, gdtSearchHandler);
  app.post(`${host}/tree/grade-device-tree/search/list`, gdtSearchHandler);
}
// admin RPC mirror (BRMS.Tree.GetFullGradeDeviceTree, DPSDK 0xcdb070)
// E-140: the role/permission dialog must ALWAYS see the full tree, even if an
// orgCode sneaks into the request -> scope:'full' is evaluated before orgCode
// inside buildFullGradeDeviceTreePayload, so it wins over any incoming orgCode.
app.post('/admin/API/BRM/Tree/GetFullGradeDeviceTree', async (req) => {
  const p = buildFullGradeDeviceTreePayload({ scope: 'full', ...(req.body || {}), ...(req.query || {}) });
  return envelope({ method: 'BRMS.Tree.GetFullGradeDeviceTree', ...p, info: p, data: p });
});
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  app.get(`${host}/storage/plan/channel/record-plan/page`, async (req) => envelope(buildRecordPlanPagePayload(req.query)));
  app.get(`${host}/storage/plan/motion-detection-record-plan/page`, async (req) => envelope(buildMotionDetectionRecordPlanPagePayload(req.query)));
}
app.get('/brms/api/v1.1/account/user/level', async () => envelope(buildUserLevelPayload()));
app.get('/brms/api/v1.0/account/user/level', async () => envelope(buildUserLevelPayload()));
app.get('/brms/api/v1.1/config/timezone/info', async (req) => envelope(buildAreaTimezonePayload(req.query.area)));
app.get('/brms/api/v1.0/config/timezone/info', async (req) => envelope(buildAreaTimezonePayload(req.query.area)));

// E-095: user/list real (the SPA vtalk module calls getUserList?username=&roleId=;
// it was served by the empty FALLBACK). Registered explicitly so it wins over
// the FALLBACK_ROUTES loop below.
app.get('/brms/api/v1.1/user/list', async (req) => {
  const kw = String(req.query?.username ?? req.query?.keyword ?? '').trim().toLowerCase();
  const admin = {
    userId: '1', id: '1', username: 'admin', realName: 'Administrator',
    roleId: '1', roleName: 'Super Administrator', orgCode: '001',
    status: '1', enable: '1', online: '1', createTime: '2026-01-01 00:00:00'
  };
  const list = kw && !admin.username.includes(kw) ? [] : [admin];
  return envelope({
    list, results: list, items: list,
    total: list.length, totalCount: list.length,
    pageNo: 1, pageSize: 20
  });
});

// --- device lists ---
app.get('/brms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload(req.query)));
app.get('/brms/api/v1.0/device/page', async (req) => envelope(buildDevicePagePayload(req.query)));
app.post('/brms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload({ ...req.query, ...(req.body || {}) })));
app.get('/brms/api/v1.1/discover/device/page', async (req) => envelope(buildDiscoverDevicePagePayload(req.query)));
app.get('/brms/api/v1.1/device/channel/page', async () => {
  const list = allChannels();
  return envelope({ list, results: list, channelList: list, items: list, total: list.length, pageNo: 1, pageSize: list.length || 20 });
});

// E-094: the REAL web bundle's Device page (deviceTable, useDeviceApi
// getPageDevices) calls the OMMS namespace - GET /omms/api/v1.1/device/page
// with query params and reads data.pageData + data.totalCount. Without these
// routes the table fell into the empty fallback and showed "Total 0 record(s)"
// even though the device was registered (live evidence 2026-11-05 15:55 UTC:
// toast "Successfully added the devices" + discover row Initialized + table 0).
app.get('/omms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload(req.query)));
app.post('/omms/api/v1.1/device/page', async (req) => envelope(buildDevicePagePayload({ ...req.query, ...(req.body || {}) })));
app.get('/omms/api/v1.1/device/statistics/group-by-device-category/list', async (req) => envelope(buildStatisticsCategoryPayload(buildDeviceTypeResults(), req.query)));
app.post('/omms/api/v1.1/device/statistics/group-by-device-category/list', async (req) => envelope(buildStatisticsCategoryPayload(buildDeviceTypeResults(), { ...req.query, ...(req.body || {}) })));
// E-095: the top cards of the DeviceStatus page (RealDeviceStatus) call the
// BARE /omms/api/v1.1/device/statistics and read TOP-LEVEL .deviceCount /
// .onlineDeviceCount / .abnormalDeviceCount / .alertDeviceCount (RE-SPA-part3
// §3) - not the grouped list. Serve real aggregates from the registry.
app.get('/omms/api/v1.1/device/statistics', async () => {
  const devs = [...DEVICE_REGISTRY.values()];
  const dc = devs.length;
  const oc = devs.filter((d) => deviceOnlineOf(d)).length;
  return envelope({
    deviceCount: dc, onlineDeviceCount: oc, offlineDeviceCount: dc - oc,
    abnormalDeviceCount: 0, alertDeviceCount: 0,
    channelCount: devs.reduce((n, d) => n + Math.max(1, Number(d.channelNum) || 1), 0),
    results: buildStatisticsCategoryPayload(buildDeviceTypeResults(), {}).results
  });
});
// E-095: exportDevices (POST /omms/api/v1.1/device/export) reads .session/.fileUrl
app.post('/omms/api/v1.1/device/export', async () => envelope({
  session: genToken().slice(0, 16),
  fileUrl: '/omms/api/v1.1/device/export/file?session=' + genToken().slice(0, 16)
}));
app.get('/omms/api/v1.1/device/export', async (req) => envelope(buildDevicePagePayload(req.query)));
app.get('/omms/api/v1.1/channel/page', async () => {
  const list = allChannels();
  return envelope({ list, results: list, channelList: list, items: list, pageData: list, total: list.length, totalCount: list.length, pageNo: 1, pageSize: list.length || 20 });
});
app.get('/omms/api/v1.1/device/channel/page', async () => {
  const list = allChannels();
  return envelope({ list, results: list, channelList: list, items: list, pageData: list, total: list.length, totalCount: list.length, pageNo: 1, pageSize: list.length || 20 });
});
// E-095: DeviceStatus History tab - POST fetch/page reads .pageData[] rows with
// deviceCode/deviceName/deviceIp/deviceCategoryName/deviceTypeName/orgName/
// orgCode/status/statusName/startTime/endTime/duration + .totalCount (RE-SPA-part3 §4)
app.post('/omms/api/v1.1/device/status/history/record/fetch/page', async (req) => {
  const body = req.body || {};
  const now = Math.floor(Date.now() / 1000);
  const rows = [...DEVICE_REGISTRY.values()].map((d) => {
    const on = deviceOnlineOf(d);
    return {
      deviceCode: d.deviceCode, deviceName: d.deviceName, deviceIp: d.deviceIp,
      deviceCategory: String(d.deviceCategory || '1'),
      deviceCategoryName: d.deviceCategoryName || 'Encoder',
      deviceTypeName: d.deviceTypeName || String(d.deviceType || ''),
      orgCode: deviceOrgCode(d), orgName: orgName(deviceOrgCode(d)),
      status: on ? '1' : '0', statusName: on ? 'Online' : 'Offline',
      startTime: now - 3600, endTime: now, duration: 3600,
      updateTime: new Date().toISOString().replace('T', ' ').slice(0, 19)
    };
  });
  const page = Math.max(1, Number(body.page ?? 1) || 1);
  const size = Math.max(1, Number(body.pageSize ?? 20) || 20);
  const slice = rows.slice((page - 1) * size, page * size);
  return envelope({ pageData: slice, list: slice, results: slice, totalCount: rows.length, total: rows.length, pageNo: page, pageSize: size });
});
app.post('/omms/api/v1.1/device/status/history/record/export', async () => envelope({
  session: genToken().slice(0, 16),
  fileUrl: '/omms/api/v1.1/device/status/history/record/export/file?session=' + genToken().slice(0, 16)
}));
// E-095: disk status page (device detail tab) - .pageData[]/.totalCount
app.get('/omms/api/v1.1/device/disk/status/page', async () => {
  const rows = [...DEVICE_REGISTRY.values()].map((d) => ({
    id: d.deviceCode, deviceCode: d.deviceCode, deviceName: d.deviceName,
    diskStatus: '1', diskStatusName: 'Normal', totalCapacity: 0, freeCapacity: 0, usedCapacity: 0
  }));
  return envelope({ pageData: rows, list: rows, results: rows, totalCount: rows.length, total: rows.length });
});
// E-095: device detail (DeviceStatusDetail) - GET /omms/api/v1.1/device/{code}
// reads data.{deviceName,deviceIp,deviceCategory,status,statusName,offlineReason
// (only when status==="0"),faultStatus,faultStatusName,faultReason,updateTime}
app.get('/omms/api/v1.1/device/:deviceCode', async (req, reply) => {
  const base = findDevicePayloadByCode(req.params?.deviceCode);
  if (!base) return reply.code(404).send(envelope(null, 404, 'Device not found'));
  const row = buildDeviceTableRow(base);
  return envelope({
    ...row,
    faultReason: '',
    updateTime: new Date().toISOString().replace('T', ' ').slice(0, 19)
  });
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
// E-036: EVERY registration funnel (Discover join, Discover init, manual
// add, Dahua auto-register) persists the device AND provisions its own
// MediaMTX path, so the device is visible in every tree and playable.
// E-116: STREAM GUARDIAN. MediaMTX dynamic paths are lost whenever the
// mediamtx container is recreated or its config is reloaded (observed live
// 2026-11-07: `docker compose up -d --build mediamtx` dropped
// cam_D0238JDG3016 -> relay SETUP 400 -> Live View dead). Provisioning only
// ran at device-add time, so nothing healed. Now every 60s each registered
// device gets ensureDeviceStream (idempotent: ADD then PATCH), plus one
// pass 8s after boot.
function provisionAllDevices() {
  for (const d of [...DEVICE_REGISTRY.values()]) {
    if (d && d.deviceIp) scheduleStreamProvisioning(d);
  }
}
setTimeout(provisionAllDevices, 8000);
setInterval(provisionAllDevices, 60000);

function scheduleStreamProvisioning(devices) {
  const list = Array.isArray(devices) ? devices : [devices];
  for (const d of list) {
    if (!d || !d.deviceIp) continue;
    setImmediate(async () => {
      try { await ensureDeviceStream(d); }
      catch (err) { console.log('[E034-STREAM] provisioning failed:', err.message); }
      // E-097: once provisioning settles the device is Online - push the
      // status over the real MQ methods so the client updates the row WITHOUT
      // a manual refresh of the Device Management view.
      try { NOTIFY.deviceEvent('DEVICE_STATUS', d); } catch { /* best effort */ }
    });
  }
}
app.post('/brms/api/v1.1/discover/device/join/batch', async (req) => {
  const payload = buildDiscoverJoinBatchPayload(req.body);
  const created = payload.list || payload.deviceList || [];
  scheduleStreamProvisioning(created);
  // E-039: the native CDevAdd dialog issues join/batch - notify every created
  // device on the real topics so the dialog completes before its 30 s timer.
  for (const d of created) {
    try { NOTIFY.deviceEvent('DEVICE_ADDED', d); } catch { /* best effort */ }
  }
  return envelope(payload);
});
app.post('/brms/api/v1.1/discover/device/init', async (req) => {
  const payload = buildDiscoverDeviceInitPayload(req.body);
  const dev = payload.device || payload.deviceVo;
  scheduleStreamProvisioning(dev ? [dev] : []);
  try { NOTIFY.deviceEvent('DEVICE_INITIALIZED', dev); } catch { /* best effort */ }
  return envelope(payload);
});

// E-031: web SPA resource helpers (live view / storage / monitor trees read
// these; see EV-081b - they previously answered from the generic fallback).
app.post('/brms/api/v1.1/device/channel/list', async (req) => envelope(buildChannelListPayload(req.body || {})));
app.post('/brms/api/v1.1/device/organization/fetch/batch/list', async (req) =>
  envelope(buildDeviceOrganizationBatchPayload(req.body || {})));
app.get('/brms/api/v1.1/device/:deviceCode', async (req, reply) => {
  const payload = findDevicePayloadByCode(req.params?.deviceCode);
  if (!payload) return reply.code(404).send(envelope(null, 404, 'Device not found'));
  return envelope(payload);
});
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
app.post('/brms/api/v1.1/role/list', roleHandler); // E-107: client may POST list endpoints
app.get('/brms/api/v1.1/role/all/list', roleHandler);
app.post('/brms/api/v1.1/role/all/list', roleHandler);
// E-107: version/prefix fallback variants observed as [FALLBACK] hits (the
// generic catch-all answer code:1000 {list:[],total:0} is read as "Abnormal
// network" by DPSDK): v1.0 + the ipms prefix.
for (const host of ['/brms/api/v1.0', '/ipms/api/v1.1', '/ipms/api/v1.0', '/brms/api/v2.0']) {
  app.get(`${host}/role/list`, roleHandler);
  app.post(`${host}/role/list`, roleHandler);
  app.get(`${host}/role/all/list`, roleHandler);
  app.post(`${host}/role/all/list`, roleHandler);
  app.get(`${host}/role/page`, roleHandler);
  app.post(`${host}/role/page`, roleHandler);
}

// ===== E-096: User Management + Role Management (native UserLogical.dll path)
// Live evidence gw-last40m.log 02:55-02:58 UTC: /user/page, /user/group/list
// and /config/ldap hit the generic fallback -> the User Management view showed
// an empty table (no admin row) and Role/x buttons had no data. Contracts from
// the DPSDK.dll string pool (@0xc9cfe0-0xc9d898) - see e025-devices.js E-096.
const userPageHandler = async (req) => envelope(buildUserPagePayload({ ...req.query, ...(req.body || {}) }));
app.get('/brms/api/v1.1/user/page', userPageHandler);
app.post('/brms/api/v1.1/user/page', userPageHandler);
app.get('/brms/api/v1.1/user/group/list', async (req) => envelope(buildUserGroupListPayload(req.query)));
app.get('/brms/api/v1.1/user/group-by-role-level/list', async (req) => envelope(buildUserGroupListPayload(req.query)));
app.get('/brms/api/v1.1/config/ldap', async () => envelope(buildLdapConfigPayload()));
app.put('/brms/api/v1.1/config/ldap', async (req) => envelope(buildLdapConfigPayload()));
app.post('/brms/api/v1.1/config/ldap', async (req) => envelope(buildLdapConfigPayload()));
// E-107: v1.0 + ipms variants of the LDAP config (FALLBACK hits)
for (const host of ['/brms/api/v1.0', '/ipms/api/v1.1', '/brms/api/v2.0']) {
  app.get(`${host}/config/ldap`, async () => envelope(buildLdapConfigPayload()));
  app.put(`${host}/config/ldap`, async () => envelope(buildLdapConfigPayload()));
  app.post(`${host}/config/ldap`, async () => envelope(buildLdapConfigPayload()));
}
// E-107: token refresh - observed live 08:14:56Z as POST /admin/API/accounts/
// updateToken hitting [FALLBACK] (40B) which breaks the session renew.
const updateTokenHandler = async (req) => envelope(buildLoginSuccess(String(req.body?.userName || 'admin')));
app.post('/brms/api/v1.0/accounts/updateToken', updateTokenHandler);
app.post('/admin/API/accounts/updateToken', updateTokenHandler);
app.post('/admin/api/accounts/updateToken', updateTokenHandler);
app.get('/brms/api/v1.1/user/email/associate/list', async (req) => envelope(buildUserEmailListPayload(req.query)));
app.get('/brms/api/v1.1/user/detail/list', async (req) => envelope(buildUserPagePayload({ ...req.query, ...(req.body || {}) })));
// E-105: legacy /admin/API/ surface of the SAME native dialog
// (DPSDK CRestLogical GetUserGroup->"Rights/Groups" @0xc9cde8,
// GetUserBaseInfo->"Rights/Users" @0xc9ce70,
// GetUserDetailInfo->"Rights/User" @0xc9d028) - same payload shapes.
const rightsUsersHandler = async (req) => envelope(buildUserPagePayload({ ...req.query, ...(req.body || {}) }));
const rightsGroupsHandler = async (req) => envelope(buildUserGroupListPayload({ ...req.query, ...(req.body || {}) }));
for (const m of ['get', 'post']) {
  app[m]('/admin/API/Rights/Users', rightsUsersHandler);
  app[m]('/admin/API/Rights/User', async (req) => {
    const id = String(req.query?.userId || req.query?.id || req.body?.userId || req.params?.userId || '1');
    const row = buildUserDetailPayload(id);
    return row ? envelope(row) : envelope({ list: [], results: [], items: [], pageData: [], totalCount: '0', total: '0' });
  });
  app[m]('/admin/API/Rights/Groups', rightsGroupsHandler);
}
// user/detail/list + email page (DPSDK GetUserEmailsByPage)
app.get('/brms/api/v1.1/user/email/page', async (req) => envelope(buildUserEmailListPayload(req.query)));
// GetUser -> v1.1/user/:id (static paths above win over this param route)
app.get('/brms/api/v1.1/user/:userId', async (req, reply) => {
  const row = buildUserDetailPayload(req.params?.userId);
  if (!row) return reply.code(404).send(envelope(null, 404, 'User not found'));
  return envelope(row);
});
// SaveUser (v1.1/user/:id), AddUser (POST v1.1/user), Lock/UnLock, DeleteUser.
// All acknowledged as success - DSS server semantics, no real mutation needed
// (the native view keeps its own in-memory state after a 200).
const userWriteOk = async (req, reply) => {
  const code = String(req.params?.userId || '1');
  if (req.method === 'DELETE' || String(req.url || '').includes('/delete')) {
    // admin can never be deleted (UI lock is '0' but be safe server-side too)
    const ids = (req.body?.userIdList || []).map(String);
    if (ids.includes('1')) return reply.code(200).send(envelope({ success: false, failedList: [{ userId: '1' }] }));
  }
  const target = buildUserDetailPayload(code);
  const out = { success: true, userId: code, username: target?.username || '' };
  return envelope({ success: true, ...out, out, data: out });
};
for (const m of ['post', 'put', 'get']) {
  app[m]('/brms/api/v1.1/user/:userId/lock', userWriteOk);
  app[m]('/brms/api/v1.1/user/:userId/unlock', userWriteOk);
}
app.post('/brms/api/v1.1/user', userWriteOk);
app.put('/brms/api/v1.1/user', userWriteOk);
app.put('/brms/api/v1.1/user/:userId', userWriteOk);
app.post('/brms/api/v1.1/user/:userId', userWriteOk);
app.post('/brms/api/v1.1/user/delete', userWriteOk);
app.delete('/brms/api/v1.1/user/:userId', userWriteOk);
app.delete('/brms/api/v1.1/user', userWriteOk);
// Role detail (GetRole -> v1.1/role/:roleId) derived from the role page store.
app.get('/brms/api/v1.1/role/:roleId', async (req, reply) => {
  const id = String(req.params?.roleId || '');
  const roles = buildRolePagePayload().list || [];
  const role = roles.find((r) => String(r.roleId) === id || String(r.roleCode) === id)
    // E-096: the admin role is exposed under legacy ids too (GetUserRole uses
    // level==1); synthesize so a role id of '0'/'001' still resolves.
    // E-099: synthesized role keeps the E-095 string-flag contract (a numeric
    // status crashed the User Config dialog at 21:12 UTC 2026-11-06)
    // E-122: merge the FULL automatic grant (deviceCodes/channelIds/menuCodes/
    // functionCodes) from the catalog so the Role Details dialog opens with
    // every camera pre-authorized.
    || (id && !['page', 'all', 'list'].includes(id)
      ? { ...(roles.find((r) => String(r.roleId) === '1') || {}), roleId: id, id,
          roleCode: 'admin', roleName: 'Administrator', description: 'Built-in administrator', memo: 'Built-in administrator', roleType: '1', allowEdit: '0', userCount: '1', status: '1', statusName: 'Enable', level: '1', roleLevel: '1', default: '1', editable: '0', deletable: '0', checked: '1', permission: '1', operate: '1', hasAuthority: '1', createTime: '2026-01-01 00:00:00' }
      : null);
  if (!role) return reply.code(404).send(envelope(null, 404, 'Role not found'));
  return envelope(role);
});
// E-101: role write returns the REAL role row (string flags per E-095/E-099)
// instead of a static stub - the native dialog materializes menuCodes/
// functionCodes/channelIds/deviceCodes on the returned id (observed POST
// /role 22:53:29Z with empty arrays; a static roleId '1' can break the
// native assertion and abort the dialog).
const roleWriteOk = async (req) => {
  const b = req.body || {};
  const roles = buildRolePagePayload().list || [];
  const nextId = String(roles.length + 1);
  const id = String(b.roleId || req.params?.roleId || nextId);
  const role = {
    roleId: id, id,
    roleCode: b.roleCode || ('role' + id), roleName: b.roleName || 'New Role',
    description: b.description || '', userCount: '0',
    status: '1', statusName: 'Enable', level: String(b.level || id), roleLevel: String(b.level || id),
    default: '0', editable: '1', deletable: '1', checked: '1', permission: '1', operate: '1',
    orgCode: b.orgCode || '001',
    menuCodes: b.menuCodes || [], functionCodes: b.functionCodes || [],
    channelIds: b.channelIds || [], deviceCodes: b.deviceCodes || [],
    createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00'
  };
  return envelope({ success: true, ...role, role, data: role });
};
app.post('/brms/api/v1.1/role', roleWriteOk);
app.put('/brms/api/v1.1/role', roleWriteOk);
app.put('/brms/api/v1.1/role/:roleId', roleWriteOk);
app.post('/brms/api/v1.1/role/:roleId', roleWriteOk);
app.post('/brms/api/v1.1/role/delete', roleWriteOk);
app.delete('/brms/api/v1.1/role/:roleId', roleWriteOk);
app.delete('/brms/api/v1.1/role', roleWriteOk);

// ===== E-098: cascade permissions + per-org camera allocation (DPSDK
// GetResourceRoles/SetResourceRoles/ResourceAllocateGetOrgDevices; see
// e025-devices.js E-098). The permission-assignment dialog of User/Role
// Management reads the role list per resource and the device list per org.
const authorityRolesHandler = async (req) =>
  envelope(buildAuthorityResourceRolesPayload(req.params?.resourceId, { ...req.query, ...(req.body || {}) }));
app.get('/brms/api/v1.1/authority/resource/:resourceId/role/list', authorityRolesHandler);
app.post('/brms/api/v1.1/authority/resource/:resourceId/role/list', authorityRolesHandler);
app.get('/brms/api/v1.1/authority/resource/role/list', authorityRolesHandler);
app.post('/brms/api/v1.1/authority/resource/:resourceId/role', async (req) => envelope({ success: true, resourceId: String(req.params?.resourceId || '') }));
app.put('/brms/api/v1.1/authority/resource/:resourceId/role', async (req) => envelope({ success: true, resourceId: String(req.params?.resourceId || '') }));
// E-102: SetResourceRoles native contract is PUT .../role/update with body
// { roleIds: [string...], resourceId, resourceType } (DPSDK.dll FUN_1806e3420)
const roleUpdateHandler = async (req) => envelope({
  success: true,
  resourceId: String(req.params?.resourceId || req.body?.resourceId || ''),
  resourceType: String(req.body?.resourceType || '1'),
  roleIds: Array.isArray(req.body?.roleIds) ? req.body.roleIds.map(String) : []
});
app.put('/brms/api/v1.1/authority/resource/:resourceId/role/update', roleUpdateHandler);
app.post('/brms/api/v1.1/authority/resource/:resourceId/role/update', roleUpdateHandler);
const orgDevHandler = async (req) => envelope(buildResourceAllocateOrgDevicesPayload({ ...req.query, ...(req.body || {}) }));
app.get('/brms/api/v1.1/resource-allocate/organization/device/fetch/list', orgDevHandler);
app.post('/brms/api/v1.1/resource-allocate/organization/device/fetch/list', orgDevHandler);

// ===== E-099a: Organization combo of the User Config dialog ================
// DPSDK GetDomainOrganizations (UserLogical HandleQueryDomainOrganizations
// @0xc5720) -> v1.1/domain/organization/list. Serves the same org store as
// organization/list (001 root + VIGILAB) with pageData for the paged variant.
// E-102 native contract (DPSDK.dll FUN_1806ccde0, GetDomainOrganizations):
// root domainOrgExceeded + results[] items bind domainOrgType/domainOrgDn/
// pId/domainOrgPath/domainOrgName/domainOrgCode - ALL strings (tipo 2).
// Org aliases (orgCode/orgName/id) are kept as superset for the SPA.
const domainOrgHandler = async () => {
  const p = buildOrganizationListPayload();
  const results = p.list.map((o) => ({
    domainOrgCode: o.orgCode, domainOrgName: o.orgName, domainOrgPath: o.orgCode,
    domainOrgType: o.orgType || '1', domainOrgDn: `ou=${o.orgCode}`, pId: o.parentOrgCode || '0',
    orgCode: o.orgCode, orgName: o.orgName, id: o.id, code: o.code, name: o.name,
    hasChild: o.hasChild, checked: o.checked, parentOrgCode: o.parentOrgCode || '0'
  }));
  return envelope({
    ...p, results, list: results, pageData: results,
    domainOrgExceeded: '0',
    pageNo: '1', pageSize: String(results.length), pageCount: '1'
  });
};
app.get('/brms/api/v1.1/domain/organization/list', domainOrgHandler);
app.post('/brms/api/v1.1/domain/organization/list', domainOrgHandler);
app.get('/ipms/api/v1.1/domain/organization/list', domainOrgHandler);
app.post('/ipms/api/v1.1/domain/organization/list', domainOrgHandler);
app.get('/brms/api/v1.1/domain/import/organization/page', domainOrgHandler);
app.post('/brms/api/v1.1/domain/import/organization/page', domainOrgHandler);

// ===== E-099b: LIVE VIEW PRIVILEGE GATE (asset permission per channel) =====
// DPSDK CheckChannelFunction/GetChannelFunctions/CheckDeviceFunction ->
// v1.1/account/function/{channel,device}/check[/batch] (@0xc9ca80/@0xc7f0c0/
// @0xc9c978). The client checks the account's FunctionType codes per channel
// BEFORE opening Live View; we grant the full catalog (liveView 8, playback
// 9, ptzOperate 13, download 10, ...) on every registered channel, so
// D0238JDG3016$1$0$0 (org VIGILAB) opens immediately. All flags STRING.
const chFnCheck = async (req) => envelope(buildChannelFunctionCheckPayload({ ...req.query, ...(req.body || {}) }));
app.get('/brms/api/v1.1/account/function/channel/check', chFnCheck);
app.post('/brms/api/v1.1/account/function/channel/check', chFnCheck);
app.get('/brms/api/v1.1/account/function/channel/check/batch', chFnCheck);
app.post('/brms/api/v1.1/account/function/channel/check/batch', chFnCheck);
app.get('/brms/api/v1.0/account/function/channel/check', chFnCheck);
app.post('/brms/api/v1.0/account/function/channel/check/batch', chFnCheck);
const devFnCheck = async (req) => envelope(buildDeviceFunctionCheckPayload({ ...req.query, ...(req.body || {}) }));
app.get('/brms/api/v1.1/account/function/device/check', devFnCheck);
app.post('/brms/api/v1.1/account/function/device/check', devFnCheck);
// channel relation binding (resource-binding/channel/relation/page) so the
// asset-assignment tree shows the channel bound to the org/role
const chRelHandler = async (req) => {
  const chans = (buildChannelFunctionCheckPayload({ ...req.query, ...(req.body || {}) }).list || []);
  const list = chans.map((c) => ({
    channelCode: c.channelCode, channelId: c.channelId, deviceCode: c.deviceCode, orgCode: c.orgCode,
    resourceId: c.channelCode, resourceType: '1', relationId: c.channelCode,
    bindingStatus: '1', status: '1', checked: '1'
  }));
  return envelope({ list, results: list, items: list, total: String(list.length), totalCount: String(list.length), pageData: list, pageNo: '1', pageSize: '100', pageCount: '1' });
};
app.get('/brms/api/v1.1/resource-binding/channel/relation/page', chRelHandler);
app.post('/brms/api/v1.1/resource-binding/channel/relation/page', chRelHandler);
app.post('/brms/api/v1.1/resource-binding/channel/relation/update/batch', async () => envelope({ success: true }));
app.post('/brms/api/v1.1/resource-binding/channel/relation/delete/batch', async () => envelope({ success: true }));
// E-035: the REAL function catalog (FunctionType enum of the server package).
// The previous answer listed invented codes ("realtime", "playback", ...)
// while the real DSS addresses functions by numeric code.
// E-099: function/available/list serves the full available-function catalog
// (menu entries + FunctionType codes) with STRING enum flags - this is one of
// the calls the User Config dialog makes right before role/list (the last
// request seen before the 21:12 UTC crash); numeric flags are crash suspects
// per the E-095 lesson. Superset of both catalogs so every consumer binds.
const fnAvailHandler = async () => {
  const menus = buildFunctionAvailablePayload().list || [];
  const fns = (buildFunctionListPayload().results || []).map((f) => ({ ...f, status: '1', enable: '1', available: '1', type: '0' }));
  const seen = new Set(menus.map((m) => m.functionId || m.functionCode));
  const rows = [...menus, ...fns.filter((f) => !seen.has(f.functionCode))];
  return envelope({ results: rows, list: rows, items: rows, functionList: rows, availableList: rows, total: String(rows.length), totalCount: String(rows.length) });
};
app.get('/brms/api/v1.1/function/available/list', fnAvailHandler);
app.post('/brms/api/v1.1/function/available/list', fnAvailHandler);
app.get('/brms/api/v1.1/subsystem/available/list', async () => envelope(buildSubsystemAvailablePayload()));
// E-141 (rea-remaining-gaps.md §3.3): real contract is warningSubsystems[]
// {subsystemCode, center, subsystemName, subsystemIp} + warningHappened STRING.
app.get('/brms/api/v1.1/subsystem/register/warning', async () => envelope({
  warningSubsystems: [], warningHappened: '0',
  warningList: [], list: [], total: '0', totalCount: '0'
}));
// OMMS (alarm service) previously 404'd -> "abnormal data" in the Event Center.
app.get('/omms/api/v1.1/alert/rule/alert-type/list', async () => envelope(buildAlertTypeListPayload()));
app.post('/omms/api/v1.1/alert/rule/alert-type/list', async () => envelope(buildAlertTypeListPayload()));

// --- GET variants of the tree (launcher prefetch used GET -> fallback) ---
// E-037: they answer with the REAL native contract (departments/devices).
// E-139: each GET/POST also merges the PAGED contract ({totalCount, results[]}
// with online string / parentId / nodeType / hasChild) that FUN_18071dac0 parses.
app.get('/brms/api/v1.0/tree/orgs', async () => {
  const paged = buildPagedOrgsPayload();
  const base = buildNativeOrgTreePayload();
  return envelope({ ...base, orgList: base.departments, totalCount: paged.totalCount, results: paged.results });
});
app.get('/brms/api/v1.0/tree/devices', async () => {
  const paged = buildPagedDevicesPayload({});
  return envelope({ ...buildNativeDeviceTreePayload({}), deviceList: paged.results, list: paged.results, items: paged.results, total: paged.totalCount, totalCount: paged.totalCount, results: paged.results });
});
app.get('/brms/api/v1.0/tree/channels', async () => {
  const channelList = allChannels().map((c) => ({ ...c, deviceIp: maskDeviceIp(c) }));
  const paged = buildPagedChannelsPayload();
  return envelope({ channelList, list: channelList, total: channelList.length, totalCount: paged.totalCount, results: paged.results });
});

// ===== E-021: exact contracts for the routes that hit [FALLBACK] in the live
// launcher trace (E-021 objective 1) =====

// POST /admin/API/tree/devices arrives with a filter body: {categories: [],
// sourceTypes: [], orgCode: "", deviceCodes: [], containVirtualDevice: "1"}.
// E-037: the answer now carries the REAL DeviceTreeVo.devices array (the
// native client parses "devices"); "deviceList"/"list" stay as aliases for
// the web SPA.
app.post('/admin/API/tree/devices', async (req) => {
  const b = req.body || {};
  const p = buildNativeDeviceTreePayload(b);
  return envelope(p);
});
app.post('/admin/api/tree/devices', async (req) => envelope(buildNativeDeviceTreePayload(req.body || {})));
// favorite/tree = Dpsdk::CRestLogical::GetCollectionTree (favorites tree).
app.get('/brms/api/v1.1/account/favorite/tree', async () => envelope({
  list: [], orgList: [], channelList: [], tree: [], favoriteList: []
}));
// share/unread/list = GetUnReadCollections / GetUnreadShareViews.
app.get('/brms/api/v1.1/account/favorite/organization/share/unread/list', async () => envelope({ list: [], unreadCount: 0 }));
// E-033: the monitor/view endpoints follow the REAL ViewController contract
// recovered from the DSS Server V8.008 package (see e033-monitor-views.js):
//   GET  monitor/view/view-tree?viewType=N -> ViewTreeVo{viewInfos:[{viewType,viewDirs:[]}]}
//   POST monitor/view/view-dir              -> ViewDirVo{viewDirCode,viewDirName}
//   GET  monitor/view/view-dir/{code}       -> ViewDirVo
//   PUT  monitor/view/view-dir/{code}       -> ViewDirVo
//   POST monitor/view/view-dir/delete/batch -> ResultsVo{results}
//   POST monitor/view                       -> viewCode
//   PUT  monitor/view/{code}                -> viewCode
//   PUT  monitor/view/{code}/rename         -> viewCode
//   POST monitor/view/delete/batch          -> ResultsVo{results}
//   POST monitor/view/share                 -> ViewShareRecordVo
//   POST monitor/view/share/ack             -> ack
//   GET  monitor/view/share/{code}          -> ViewShareRecordVo
//   GET  monitor/view/share/unread/list     -> ResultsVo<UnreadViewVo>
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0']) {
  app.get(`${host}/monitor/view/view-tree`, async (req) =>
    envelope(buildViewTreePayload(req.query?.viewType ?? 1)));
  // E-115b: the SPA web module POSTs the view tree too (POST used to fall to
  // the catch-all {data:{}} and the Monitor view opened empty).
  app.post(`${host}/monitor/view/view-tree`, async (req) =>
    envelope(buildViewTreePayload(req.query?.viewType ?? req.body?.viewType ?? 1)));
  app.post(`${host}/monitor/view/view-dir`, async (req) => {
    const r = addViewDir(req.body || {});
    if (r.error) return envelope(null, 1001, r.error);
    return envelope(r);
  });
  app.get(`${host}/monitor/view/view-dir/:code`, async (req, reply) => {
    const r = buildViewDirPayload(req.params?.code);
    if (!r) return reply.code(404).send(envelope(null, 404, 'View dir not found'));
    return envelope(r);
  });
  app.put(`${host}/monitor/view/view-dir/:code`, async (req, reply) => {
    const r = updateViewDir(req.params?.code, req.body || {});
    if (!r) return reply.code(404).send(envelope(null, 404, 'View dir not found'));
    return envelope(r);
  });
  app.post(`${host}/monitor/view/view-dir/delete/batch`, async (req) =>
    envelope(batchDeleteViewDir(req.body || {})));
  app.post(`${host}/monitor/view`, async (req) => {
    const r = addView(req.body || {});
    if (r.error) return envelope(null, 1001, r.error);
    return envelope(r);
  });
  app.put(`${host}/monitor/view/:code/rename`, async (req, reply) => {
    const r = renameView(req.params?.code, req.body || {});
    if (!r) return reply.code(404).send(envelope(null, 404, 'View not found'));
    return envelope(r);
  });
  app.put(`${host}/monitor/view/:code`, async (req, reply) => {
    const r = updateView(req.params?.code, req.body || {});
    if (!r) return reply.code(404).send(envelope(null, 404, 'View not found'));
    return envelope(r);
  });
  app.post(`${host}/monitor/view/delete/batch`, async (req) => envelope(batchDeleteView(req.body || {})));
  app.post(`${host}/monitor/view/del`, async (req) => envelope(batchDeleteView(req.body || {})));
  app.post(`${host}/monitor/view/share/ack`, async (req) => envelope(ackShareView(req.body || {})));
  app.post(`${host}/monitor/view/share`, async (req) => {
    const r = shareView(req.body || {});
    if (r.error) return envelope(null, 1001, r.error);
    return envelope(r);
  });
  app.get(`${host}/monitor/view/share/unread/list`, async () => envelope(buildUnreadShareViewsPayload()));
  app.get(`${host}/monitor/view/share/:code`, async (req, reply) => {
    const r = buildShareViewPayload(req.params?.code);
    if (!r) return reply.code(404).send(envelope(null, 404, 'Share record not found'));
    return envelope(r);
  });
}
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

// ===== E-115: RTSP relay (Dahua client handshake <-> MediaMTX) =============
// The real DSS Client does SETUP+PLAY on the SAME url with interleaved TCP
// and zero DESCRIBE (pcap evidence); MediaMTX requires SETUP <path>/trackID=0
// + PLAY <path>. The relay makes both worlds meet - without it Live View
// receives 400 on SETUP and never opens.
import { startRtspRelay } from './e115-rtsp-relay.js';
// E-118: the alarm notifier publishes the NATIVE event schema
setNativeAlarmMapper(toNativeAlarmEvent);
const RTSP_UPSTREAM_HOST = process.env.MEDIAMTX_HOST || 'mediamtx';
const RTSP_UPSTREAM_PORT = parseInt(process.env.MEDIAMTX_RTSP_PORT || '8554', 10);
if (!process.env.DISABLE_RTSP_RELAY) {
  startRtspRelay({
    port: RTSP_PORT,
    upstreamHost: RTSP_UPSTREAM_HOST,
    upstreamPort: RTSP_UPSTREAM_PORT,
    // token validation: permissive during bring-up, logged for audit
    validateToken: (token, path, from) => {
      const known = RTSP_SESSIONS.has(token);
      if (!known) console.log('[E115-RTSP] unknown token', (token || '').slice(0, 12) + '...', 'path=' + path, 'from=' + from);
    }
  });
}

// Catch-all benign responders for the rest of the microservice families
// (172-path client inventory: accessControl, alarm-host, alarmBusiness,
// vtalk, devicesManager, system/timezone, menus/client ...). Nothing in the
// bootstrap may 404 or a module aborts with "data abnormal". [FALLBACK]
// marks the exact hit so shapes get refined next cycle.
// E-025: every service prefix the client's DPSDK inventory knows about, so an
// unknown route returns code 1000 instead of the 404 that produced the
// "network abnormal / abnormal data" toasts (observed: /omms/api 404).
function fallbackLog(req) {
  const line = '[FALLBACK] ' + JSON.stringify({ timestamp: new Date().toISOString(), method: req.method, url: req.url, code: 1000 });
  console.log(line);
  journal(line); // E-109b: survive container recreation
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

// E-114: the heartbeat is the token RENEWAL, not a ping. RE evidence
// (DPSDK CRestLogicalImplPro::Heartbeat 0x20f290 -> "Heartbeat is success,
// m_strToken = %s" @0xc95670): the client stores the token from the
// keepalive response. Our old {success:true} left m_strToken empty and the
// session died with -18 exactly ~30 min after login (observed 54x every 5 min
// in the client log 2026-11-07 05:14-06:40). Keepalive now returns a fresh
// login envelope (new token, 24h TTL) so the session never expires; the VSL
// heartbeat base (accounts/token/keepalive) is registered too.
async function keepaliveHandler(req) {
  const userName = req.user?.userName || String(req.body?.userName || 'admin');
  return envelope(buildLoginSuccess(userName));
}
app.post('/brms/api/v1.0/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.get('/brms/api/v1.1/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.post('/brms/api/v1.1/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.post('/brms/api/v1.0/accounts/token/keepalive', { preHandler: auth }, keepaliveHandler);
app.post('/brms/api/v1.1/accounts/token/keepalive', { preHandler: auth }, keepaliveHandler);
app.post('/admin/API/accounts/keepalive', { preHandler: auth }, keepaliveHandler);
app.post('/admin/API/accounts/token/keepalive', { preHandler: auth }, keepaliveHandler);
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

app.get('/brms/api/v1.0/accounts/current', { preHandler: auth }, currentHandler);
app.post('/brms/api/v1.0/accounts/unauthorize', { preHandler: auth }, unauthorizeHandler);
// Mirrors on the admin API base (client Qt stack may call these after login).
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

// E-122: the desktop client compares its own build (V8.006...) against
// data.version on EVERY version endpoint - a fixed V8.008 here is what makes
// it toast "Client & server versions don't match. Please reinstall..." right
// after login. Mirror the client's own version (same logic as
// /videoService/version, E-021 decompile).
app.get('/brms/api/v1.0/version', { preHandler: auth }, async (req) => {
  const v = selectPlatformVersion(req);
  const self = v.replace(/^V/, '').replace(/\.\d{9,10}$/, '');
  const majorV = 'V' + ((v.match(/\d+\.\d+\.\d+\.\d+/) || [self])[0]);
  const fix = (v.match(/R\.(\d{8})/) || [])[1] || '20261107';
  return envelope({
    version: self,
    softwareVersion: majorV,
    serverVersion: majorV,
    buildDate: '2026-11-07',
    buildNumber: 'R.' + fix,
    productName: 'DSS Ultimate',
    protocolVersion: '1.0'
  });
});

app.get('/brms/api/v1.0/system/version', { preHandler: auth }, async (req) => {
  const v = selectPlatformVersion(req);
  const self = v.replace(/^V/, '').replace(/\.\d{9,10}$/, '');
  const majorV = 'V' + ((v.match(/\d+\.\d+\.\d+\.\d+/) || [self])[0]);
  return envelope({
    version: self,
    softwareVersion: majorV,
    serverVersion: majorV,
    buildDate: '2026-11-07',
    buildNumber: 'R.20261107',
    productName: 'DSS Ultimate'
  });
});

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
// E-037: they now answer with the REAL native contract (departments/devices).
app.post('/brms/api/v1.0/tree/orgs', { preHandler: auth }, async () => {
  const paged = buildPagedOrgsPayload();
  const base = buildNativeOrgTreePayload();
  return envelope({ ...base, orgList: base.departments, totalCount: paged.totalCount, results: paged.results });
});
app.post('/brms/api/v1.0/tree/devices', { preHandler: auth }, async (req) => {
  const body = req.body || {};
  const paged = buildPagedDevicesPayload(body);
  return envelope({ ...buildNativeDeviceTreePayload(body), deviceList: paged.results, list: paged.results, items: paged.results, total: paged.totalCount, totalCount: paged.totalCount, results: paged.results });
});
app.post('/brms/api/v1.0/tree/channels', { preHandler: auth }, async () => {
  // E-143a: the channelList alias of this tree endpoint is masked too
  const channelList = allChannels().map((c) => ({ ...c, deviceIp: maskDeviceIp(c) }));
  const paged = buildPagedChannelsPayload();
  return envelope({ channelList, list: channelList, total: channelList.length, totalCount: paged.totalCount, results: paged.results });
});
// E-037: the v1.1 tree helpers of the web SPA and of the native stack.
app.get('/brms/api/v1.1/tree/device-tree', async () => envelope(buildNativeOrgTreePayload()));
app.post('/brms/api/v1.1/tree/device-tree', async () => envelope(buildNativeOrgTreePayload()));
// (E-124 full/grade-device-tree is registered up in the E-101 block above)

// The client also probes the org tree with POST on the v1.1 + v1.0 bases.
app.get('/brms/api/v1.1/tree/deviceOrg', async () => envelope(buildNativeOrgTreePayload()));
app.post('/brms/api/v1.1/tree/deviceOrg', async () => envelope(buildNativeOrgTreePayload()));
app.post('/brms/api/v1.0/tree/deviceOrg', async () => envelope(buildNativeOrgTreePayload()));
app.post('/brms/api/v1.1/tree/devices', async (req) => envelope(buildNativeDeviceTreePayload(req.body || {})));
app.post('/brms/api/v1.0/tree/deviceOrgs', async () => envelope(buildNativeOrgTreePayload()));

// ===== MTS VIDEO =====
// E-034: the Live View opens the URL returned here. Every registered device
// owns its own MediaMTX path (cam_<deviceCode>) so the stream of the camera
// the operator picked is the stream that is played.
// E-134 D2 (REA auditor ses_e41b71d20): el cliente nativo envia el envelope
// RPC {method, data:{channelId,...}} en /admin/API/MTS/... - leer SIEMPRE
// body.data si existe, si no el body plano (v1.0/v1.1).
function mtsBody(req) {
  const b = req.body || {};
  return (b.data && typeof b.data === 'object' && !Array.isArray(b.data)) ? b.data : b;
}

// E-145: playback target resolution WITHOUT a default-camera fallback.
// Previously an unknown channel id fell back to MEDIAMTX_CAMERA_PATH, so the
// client played somebody else's stream (or burned 30 s on "RTSP SETUP timed
// out" for stale tree rows). Now an unknown channel is a real error (1001) and
// a known device always resolves to its OWN path: if its source is not
// provisioned MediaMTX answers 404 immediately, which the client surfaces at
// once instead of timing out.
function resolvePlaybackTarget(channelId) {
  const device = findDeviceByChannelId(channelId);
  if (!device) return { error: envelope(null, 1001, 'channel not found: ' + String(channelId || '')) };
  return { device, path: device.mediamtxPath || mediaMtxPathForDevice(device) };
}
app.post('/brms/api/v1.0/MTS/Video/StartVideo', { preHandler: auth }, async (req) => {
  const { channelId, streamType, dataType, enableMulticast, enableRtsps, extend, fakeSdp, forceSynPlay, keyCode, operateType, planId, trackId } = mtsBody(req);
  const token = genToken();
  const session = genToken().slice(0, 16);
  const vkId = 'vk-' + genToken().slice(0, 8);
  const target = resolvePlaybackTarget(channelId);
  if (target.error) return target.error;
  const { device, path: pathName } = target;
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${pathName}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now(), path: pathName, deviceCode: device?.deviceCode || '' });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1',
    // E-141 (REA rea-media-path-noroute.md §2.2): the native parser FUN_1802145f0
    // reads rtspUrl/rtspUrls and base64-decodes them; keep url/url2 for older paths.
    // E-146 (REA RTSP_URLS_DTO_SHAPE.md): the native DTO is an ARRAY OF
    // OBJECTS {streamType, rtspUrl} carrying PLAIN urls (not base64);
    // streamType "0" = main, "1" = sub. The singular base64 rtspUrl is kept
    // for older harness consumers (inert for the native DTO).
    rtspUrl: Buffer.from(url).toString('base64'),
    rtspUrls: [
      { streamType: '0', rtspUrl: url },
      { streamType: '1', rtspUrl: url + '&sub=1' }
    ],
    vkId, vkValue: genToken().slice(0, 16),
    hlsUrl, fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
  });
});
app.post('/brms/api/v1.0/MTS/Video/StopVideo', { preHandler: auth }, async (req) => {
  const { token } = req.body;
  if (token) RTSP_SESSIONS.delete(token);
  return envelope({ success: true });
});
app.post('/brms/api/v1.0/MTS/Video/KeepAlive', { preHandler: auth }, async () => envelope({ success: true }));
// E-115b: HLS fallback path. The client's StartVideo hands hlsUrl
// (https://<host>:1443/brms/api/v1.1/video/live/channel/<id>/hls); it must
// proxy the MediaMTX HLS m3u8 (it was a 59B catch-all before = dead fallback).
const MEDIAMTX_HLS = process.env.MEDIAMTX_HLS_URL || 'http://mediamtx:8888';
app.get('/brms/api/v1.1/video/live/channel/:channelId/hls', async (req, reply) => {
  const ch = String(req.params?.channelId || '');
  const target = resolvePlaybackTarget(ch);
  // E-145: no default-camera fallback. A channel the registry does not know,
  // or a device without a configured source, is a 404 (not somebody else's
  // camera).
  if (target.error) return reply.code(404).send(envelope(null, 404, 'no stream for channel ' + ch));
  const path = target.path;
  const sub = String(req.query?.sub || '');
  const file = String(req.query?.file || 'index.m3u8');
  try {
    const r = await fetch(`${MEDIAMTX_HLS}/${path}${sub ? '_sub' : ''}/${file}`);
    if (!r.ok) return reply.code(502).send(envelope(null, 502, 'hls upstream ' + r.status));
    const body = await r.text();
    // rewrite segment/playlist URLs so the client keeps hitting us
    const rewritten = body.replace(/(^|["'\s])([A-Za-z0-9_.\-]+\.(?:m3u8|ts))/g, (m0, pre, f) => `${pre}${req.url.split('?')[0]}?file=${f}`);
    return reply.type(r.headers.get('content-type') || 'application/vnd.apple.mpegurl').send(rewritten);
  } catch (e) {
    return reply.code(502).send(envelope(null, 502, 'hls upstream unreachable'));
  }
});
// E-113: the same media/session routes on the v1.1 base. The client's web
// stack (and future native probes) call MTS/SS on v1.1 - an unserved verb
// returns the 40B catch-all {data:{}} which the Live View reads as "no
// video URL" (verified live: v1.1 StartVideo -> data:{}).
app.post('/brms/api/v1.1/MTS/Video/StartVideo', { preHandler: auth }, async (req) => {
  const { channelId, streamType, trackId, extend, fakeSdp, forceSynPlay, keyCode } = mtsBody(req);
  const token = genToken();
  const session = genToken().slice(0, 16);
  const vkId = 'vk-' + genToken().slice(0, 8);
  const target = resolvePlaybackTarget(channelId);
  if (target.error) return target.error;
  const { device, path: pathName } = target;
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${pathName}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now(), path: pathName, deviceCode: device?.deviceCode || '' });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1',
    // E-141 (REA rea-media-path-noroute.md §2.2): the native parser FUN_1802145f0
    // reads rtspUrl/rtspUrls and base64-decodes them; keep url/url2 for older paths.
    // E-146 (REA RTSP_URLS_DTO_SHAPE.md): the native DTO is an ARRAY OF
    // OBJECTS {streamType, rtspUrl} carrying PLAIN urls (not base64);
    // streamType "0" = main, "1" = sub. The singular base64 rtspUrl is kept
    // for older harness consumers (inert for the native DTO).
    rtspUrl: Buffer.from(url).toString('base64'),
    rtspUrls: [
      { streamType: '0', rtspUrl: url },
      { streamType: '1', rtspUrl: url + '&sub=1' }
    ],
    vkId, vkValue: genToken().slice(0, 16),
    hlsUrl, fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
  });
});
app.post('/brms/api/v1.1/MTS/Video/StopVideo', { preHandler: auth }, async (req) => {
  if (req.body?.token) RTSP_SESSIONS.delete(String(req.body.token));
  return envelope({ success: true });
});
app.post('/brms/api/v1.1/MTS/Video/KeepAlive', { preHandler: auth }, async () => envelope({ success: true }));

// ===== E-125: admin-API mirrors of the MTS media RPCs ========================
// Live journal (2026-11-08 02:5x UTC, real client, host 10.10.20.120:1443):
// the native Monitoring Center calls POST /admin/API/MTS/Video/StartVideo and
// it fell into the 40B catch-all -> Live View read "no video URL" -> empty
// window. Mirror the same session logic on the /admin/API base (plus the
// Stop/KeepAlive pair and the TvWall task info RPC).
const mtsStartVideo = async (req) => {
  const { channelId, streamType, trackId, extend, fakeSdp, forceSynPlay, keyCode } = mtsBody(req);
  const token = genToken();
  const session = genToken().slice(0, 16);
  const vkId = 'vk-' + genToken().slice(0, 8);
  const target = resolvePlaybackTarget(channelId);
  if (target.error) return target.error;
  const { device, path: pathName } = target;
  const url = `rtsp://${PUBLIC_HOST}:${RTSP_PORT}/${pathName}?token=${token}`;
  const hlsUrl = `https://${PUBLIC_HOST}:${HTTPS_PORT}/brms/api/v1.1/video/live/channel/${channelId}/hls`;
  RTSP_SESSIONS.set(token, { channelId, session, created: Date.now(), path: pathName, deviceCode: device?.deviceCode || '' });
  return envelope({
    connectType: 1, ip: PUBLIC_HOST, minRate: 0, multicastIp: '239.0.0.1', multicastPort: 5000,
    port: RTSP_PORT, protocol: 'RTSP', session, stopTime: '', stunEnable: 1, stunPort: 3478,
    token, trackId: trackId || '', url, url2: url + '&sub=1',
    // E-141 (REA rea-media-path-noroute.md §2.2): the native parser FUN_1802145f0
    // reads rtspUrl/rtspUrls and base64-decodes them; keep url/url2 for older paths.
    // E-146 (REA RTSP_URLS_DTO_SHAPE.md): the native DTO is an ARRAY OF
    // OBJECTS {streamType, rtspUrl} carrying PLAIN urls (not base64);
    // streamType "0" = main, "1" = sub. The singular base64 rtspUrl is kept
    // for older harness consumers (inert for the native DTO).
    rtspUrl: Buffer.from(url).toString('base64'),
    rtspUrls: [
      { streamType: '0', rtspUrl: url },
      { streamType: '1', rtspUrl: url + '&sub=1' }
    ],
    vkId, vkValue: genToken().slice(0, 16),
    hlsUrl, fakeSdp: fakeSdp || 0, forceSynPlay: forceSynPlay || 0, extend: extend || '', keyCode: keyCode || ''
  });
};
const mtsStopVideo = async (req) => {
  if (req.body?.token) RTSP_SESSIONS.delete(String(req.body.token));
  return envelope({ success: true });
};
app.post('/admin/API/MTS/Video/StartVideo', mtsStartVideo);
app.post('/admin/API/MTS/Video/StopVideo', mtsStopVideo);
app.post('/admin/API/MTS/Video/KeepAlive', async () => envelope({ success: true }));
app.post('/admin/api/MTS/Video/StartVideo', mtsStartVideo);
app.post('/admin/api/MTS/Video/StopVideo', mtsStopVideo);
// SS record RPC mirrors on admin base
for (const m of ['QueryRecord', 'StartRecord', 'StopRecord', 'LockRecord', 'UnLockRecord', 'QueryLock', 'DeleteRecord']) {
  app.post(`/admin/API/SS/Record/${m}`, async () => {
    const map = {
      QueryRecord: () => envelope({ pageCount: 1, session: genToken().slice(0, 16), records: [] }),
      StartRecord: () => envelope({ now: new Date().toISOString().slice(0, 19).replace('T', ' '), planId: '' }),
      StopRecord: () => envelope({ success: true }),
      LockRecord: () => envelope({ id: genToken().slice(0, 8) }),
      UnLockRecord: () => envelope({ success: true }),
      QueryLock: () => envelope({ lockInfos: [] }),
      DeleteRecord: () => envelope({ success: true })
    };
    return map[m]();
  });
}
// TvWall task info (was 40B catch-all in the live journal)
app.post('/admin/API/VMS/TvWall/GetTvWallTaskInfo', async () => envelope({ method: 'VMS.TvWall.GetTvWallTaskInfo', taskInfos: [], list: [], results: [], items: [], total: '0', totalCount: '0' }));
// alarm soft-trigger per channel (was 59B catch-all)
app.get('/brms/api/v1.1/alarm/plan/source/:channel/alarm-type/soft-trigger/list', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
app.post('/brms/api/v1.1/alarm/plan/source/:channel/alarm-type/soft-trigger/list', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
// video tracking points per channel (was 59B catch-all)
app.get('/brms/api/v1.1/video/tracking/channel/:channel/point/list', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
// map resource config status (was 40B catch-all)
app.post('/brms/api/v1.1/map/resource/config-status/fetch/batch/list', async () => envelope({ list: [], results: [], items: [], total: '0', totalCount: '0' }));
// remaining small catch-alls seen in the live journal are already covered by
// existing handlers (config/ai/privacy + fish-eye + face repository in
// e026-video.js, system/license/obms/ipms warnings above, accounts/
// unauthorize at line ~2529) - nothing else to add here.
for (const m of ['QueryRecord', 'StartRecord', 'StopRecord', 'LockRecord', 'UnLockRecord', 'QueryLock', 'DeleteRecord']) {
  app.post(`/brms/api/v1.1/SS/Record/${m}`, { preHandler: auth }, async (req) => {
    // delegate to the v1.0 handler by reusing the same builders via a local fetch-free shim
    const map = {
      QueryRecord: () => envelope({ pageCount: 1, session: genToken().slice(0, 16), records: [] }),
      StartRecord: () => envelope({ now: new Date().toISOString().slice(0, 19).replace('T', ' '), planId: '' }),
      StopRecord: () => envelope({ success: true }),
      LockRecord: () => envelope({ id: genToken().slice(0, 8) }),
      UnLockRecord: () => envelope({ success: true }),
      QueryLock: () => envelope({ lockInfos: [] }),
      DeleteRecord: () => envelope({ success: true })
    };
    return map[m]();
  });
}

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

// E-142 (rea-flows-v3 §7, FUN_180211270): the native client calls the PLURAL
// `SS/Record/QueryRecords`. Response root needs pageCount STRING + session
// STRING + totalCount INT; each record carries 13 STRING keys.
const ssQueryRecordsPlural = async (req) => {
  const b = { ...(req.query || {}), ...(req.body || {}) };
  const session = genToken().slice(0, 16);
  const fmt = (ts) => new Date(ts).toISOString().slice(0, 19).replace('T', ' ');
  const now = Date.now();
  const channelId = String(b.channelId || 'D0238JDG3016$1$0$0');
  const records = [{
    ssId: 'ss-1', forgotten: '0', endTime: fmt(now), streamType: String(b.streamType ?? '0'),
    recordName: `rec-${channelId}`, diskId: 'disk-1', recordType: String(b.recordType ?? '1'),
    streamId: 'main', planId: '', recordSource: String(b.recordSource ?? '0'),
    startTime: fmt(now - 3600000), channelId, fileLength: '1024000'
  }];
  return envelope({
    pageCount: '1', totalCount: records.length, session, records,
    page: String(b.page ?? '1'), startIndex: String(b.startIndex ?? '0'), endIndex: String(b.endIndex ?? '3600')
  });
};
for (const host of ['/brms/api/v1.1', '/brms/api/v1.0', '/admin/API', '/videoService']) {
  app.post(`${host}/SS/Record/QueryRecords`, { preHandler: auth }, ssQueryRecordsPlural);
}

// ===== EVENTS =====
// (E-121: event/subscription POST moved into the E-121 loop above)
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
    // E-039: log every inbound frame - the next operator session must show
    // exactly what the client subscribes to / expects on this socket.
    ws.on('message', (data, isBinary) => {
      console.log('[WS-MSG]', isBinary ? `<binary ${data.length}B>` : data.toString('utf8').slice(0, 500));
    });
    ws.send(JSON.stringify({ type: 'WELCOME', message: 'Event WebSocket connected' }));
  });
  console.log('WebSocket Server listening on wss://0.0.0.0:' + HTTPS_PORT + '/brms/api/v1.0/event/ws');
  return wss;
}

// ===== ARS TCP Binary Server (DVRIP/DHIP) =====
// E-119: accept BOTH framings - the RE-verified binary header + JSON payload
// (Dahua AutoRegister.cpp @0x01366578) and the legacy 32B string framing.
import { parseDahuaFrame, parseRegisterJson, buildDahuaAck, buildRegisterAckJson, ARS_MAX_PAYLOAD, ARS_MAX_BUFFER } from './e119-ars-protocol.js';
import { registerP0Coverage } from './e127-p0-coverage.js';
import { registerP1Coverage } from './e129-p1-coverage.js';
// E-135: motor del catalogo RPC (2.024 metodos cosechados del string-pool del
// cliente en src/data/rpc-method-catalog.txt) + raices de subsistema faltantes.
// Envelope alineado a code 1000 (rpcEnvelope de arriba).
import { register as registerE135RpcCatalog, buildRpcPayload as e135BuildRpcPayload } from './e135-rpc-catalog.js';
import { register as registerE135Roots } from './e135-roots.js';
// E-136: Event Center (stores persistentes alarmas/planes/usuarios/roles +
// pull-queue messages/subscribe) y hub WS MSG.exe (subscribe methods[] +
// NotifyNormalMsg/NotifyFrequentMsg).
import { register as registerE136EventCenter } from './e136-eventcenter.js';
import { register as registerE136WsHub } from './e136-ws-hub.js';
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

      // E-119: RE-verified DVRIP/DHIP framing (8B magic + 0x19930522 + JSON)
      // takes precedence when the peer speaks it.
      // E-128 (DevOps audit): frame reassembly + DoS caps. A fragmented frame
      // must NOT be consumed until headerLen+declared payloadLen have arrived;
      // a bogus payloadLen (>1MiB) or a buffer >4MiB without a valid frame
      // destroys the socket instead of accumulating forever.
      if (buffer.length > 0 && (buffer.subarray(0, 5).toString('latin1') === 'DVRIP' || buffer.subarray(0, 4).toString('latin1') === 'DHIP')) {
        if (buffer.length > ARS_MAX_BUFFER) { console.log('[ARS TCP] buffer overflow, dropping peer', clientKey); socket.destroy(); return; }
        const frame = parseDahuaFrame(buffer);
        if (frame.ok) {
          if (frame.payloadLen > ARS_MAX_PAYLOAD) { console.log('[ARS TCP] payloadLen too large (' + frame.payloadLen + '), dropping peer', clientKey); socket.destroy(); return; }
          const totalLen = frame.jsonAt >= 0 ? frame.jsonAt + frame.payloadLen : frame.headerLen;
          if (frame.jsonAt === -1 || buffer.length < totalLen) return; // wait for the full JSON
          const packet = buffer.subarray(0, totalLen);
          buffer = buffer.subarray(totalLen);
          const info = parseRegisterJson(packet.subarray(frame.jsonAt));
          console.log('[ARS TCP] DVRIP/DHIP frame', frame.magic, 'json ' + (info ? 'parsed' : 'unparsed'), 'len ' + packet.length, 'from', socket.remoteAddress);
          const method = info ? '' : '';
          let rawJson = null;
          try { rawJson = JSON.parse(packet.subarray(frame.jsonAt).toString('utf8').replace(/\0+$/, '')); } catch { /* not json */ }
          const jmethod = rawJson && typeof rawJson === 'object' ? String(rawJson.method || rawJson.Method || rawJson.cmd || '') : '';
          // E-128: keepalive / logout also arrive on the binary framing -
          // refresh lastSeen and ACK instead of Ret:400.
          if (/keepalive|keep-alive|heartbeat/i.test(jmethod) || frame.command === 0x0004) {
            if (session.deviceId) { const d = ARS_DEVICES.get(session.deviceId); if (d) { d.lastSeen = Date.now(); d.status = 1; } }
            socket.write(buildDahuaAck(frame.magic, frame.command || 0x0004, frame.sequence, { Ret: 100, RetMsg: 'OK', KeepAliveSecond: '60' }));
            return;
          }
          if (/logout/i.test(jmethod) || frame.command === 0x0005) {
            if (session.deviceId) ARS_DEVICES.delete(session.deviceId);
            socket.write(buildDahuaAck(frame.magic, frame.command || 0x0005, frame.sequence, { Ret: 100, RetMsg: 'OK' }));
            return;
          }
          if (info && (info.deviceId || info.machineAddress)) {
            const deviceId = info.deviceId || info.serialNo || ('NVR-' + Date.now());
            session.sequence = frame.sequence;
            session.deviceId = deviceId;
            session.authenticated = true;
            ARS_DEVICES.set(deviceId, {
              deviceId: 'ARS-' + deviceId, originalId: deviceId, serialNo: info.serialNo,
              deviceName: info.deviceName || ('NVR ' + deviceId), ip: info.ip,
              port: info.port, username: info.username, password: info.password,
              deviceType: info.deviceType, channelNum: info.channelCount,
              deviceClass: info.deviceClass, protocol: 'Dahua', source: 'auto-register',
              status: 1, registeredAt: Date.now(), lastSeen: Date.now()
            });
            try {
              const registered = registerArsDevice({
                deviceId: deviceId, deviceName: info.deviceName || ('NVR ' + deviceId),
                ip: info.ip, port: info.port, username: info.username, password: info.password,
                deviceType: info.deviceType, channelCount: info.channelCount, protocol: 'Dahua'
              });
              scheduleStreamProvisioning(registered);
            } catch (err) { console.log('[ARS TCP] registerArsDevice failed:', err.message); }
            try { NOTIFY.deviceEvent('DEVICE_ADDED', { deviceCode: 'ARS-' + deviceId }); } catch { /* best effort */ }
            socket.write(buildDahuaAck(frame.magic, frame.command || 0x0001, frame.sequence, buildRegisterAckJson(deviceId, PUBLIC_HOST, ARS_PORT)));
          } else {
            socket.write(buildDahuaAck(frame.magic, frame.command || 0x0001, frame.sequence, { Ret: 400, RetMsg: 'Bad register payload' }));
          }
          return;
        }
        if (frame.needMore) return; // valid magic, incomplete header/JSON: wait
        // magic present but version mismatch -> fall through to legacy framing
      }

      // Process complete DVRIP packets (32-byte header + payload)
      while (buffer.length >= 32) {
        const header = parseDHIPHeader(buffer);
        if (!header) break;

        const totalLen = 32 + header.payloadLen;
        // E-128: bogus payloadLen (e.g. 0xFFFFFFFF) must not accumulate forever
        if (header.payloadLen > ARS_MAX_PAYLOAD || buffer.length > ARS_MAX_BUFFER) {
          console.log('[ARS TCP] legacy frame payloadLen too large (' + header.payloadLen + '), dropping peer', clientKey);
          socket.destroy();
          return;
        }
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
            // E-034/E-036: they also need their own MediaMTX path.
            try {
              const registered = registerArsDevice(deviceInfo);
              scheduleStreamProvisioning(registered);
              // E-039: auto-registered devices push the notify event too.
              try { NOTIFY.deviceEvent('DEVICE_ADDED', registered); } catch { /* best effort */ }
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

// ===== E-127: P0 coverage closure (residual REA report 2026-11-08) =====
// Registered LAST so hasRoute() sees every explicit handler above and skips
// duplicates - the catch-all below must stay the last resort.
registerP0Coverage(app, envelope);
registerP1Coverage(app, envelope);

// E-135: registrar DESPUES de todos los handlers explicitos (find-my-way da
// prioridad static > param > wildcard, asi que no pisa rutas existentes).
// Motor RPC BRMS.* del catalogo + 18 raices de subsistema con dispatcher
// generico al catalogo. Ninguna ruta del catalogo vuelve a caer en 40B.
const e135Ctx = {};
registerE135RpcCatalog(app, e135Ctx);
registerE135Roots(app, e135Ctx);

// E-136: el preHandler de e136-eventcenter intercepta los RPC/REST del Event
// Center (BRMS.Alarm.*, AlarmPlan.*, User.*, Role.*, Rights/Nodes, ...) sin
// pisar el resto (devuelve undefined cuando no es suyo). El parche de
// WebSocketServer.prototype.on (e136-ws-hub) DEBE instalarse antes de que
// start() cree el wss (createWebSocketServer) para que el hub reciba las
// conexiones MSG.exe. notifyHub = NOTIFY (e039: alarmEvent/topicEvent MQ+WS).
const e136Ctx = { envelope, notifyHub: NOTIFY, wsClients: WS_CLIENTS };
// WS hub PRIMERO: crea el hub y lo expone en e136Ctx; luego el Event Center
// cierra sobre notifyHub (MQ via NOTIFY) + wsHub (WS via publishNotify).
const e136WsHub = registerE136WsHub(app, e136Ctx);
e136Ctx.wsHub = e136WsHub;
registerE136EventCenter(app, e136Ctx);
// E-136: cada alarmEvent (MQ via e039) tambien se rutea al hub WS MSG.exe
// como NotifyNormalMsg para las sesiones suscritas a brms.notifyAlarms.
const e136OrigAlarmEvent = NOTIFY.alarmEvent;
NOTIFY.alarmEvent = (ev) => {
  e136OrigAlarmEvent(ev);
  try { e136WsHub.publishNotify('brms.notifyAlarms', ev); } catch { /* best effort */ }
};

async function start() {
  try {
    // E-028: same keep-alive policy as the TLS listeners (Node default 5s is
    // too short for the real client holding a connection across the add flow).
    app.server.keepAliveTimeout = 65000;
    app.server.headersTimeout = 66000;
    app.server.requestTimeout = 120000;
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
      // E-028: Node's default keepAliveTimeout is 5s. The native DPSDK client
      // holds one TLS connection across the whole add flow (cost-time ->
      // summary -> POST /device, which can take 10s while the ONVIF probe
      // runs) and then polls on it. The server closed the idle socket, the
      // next request died with ECONNRESET before it reached Fastify and the
      // client reported "Operation timed out". Keep the socket alive long
      // enough for the real client.
      httpsServer.keepAliveTimeout = 65000;
      httpsServer.headersTimeout = 66000;
      httpsServer.requestTimeout = 120000;
      // E-028: Node answers malformed/keep-alive-desynced requests with a bare
      // 400 before Fastify ever sees them (the client then reports
      // "Operation timed out"). Log the parser error so it is diagnosable.
      httpsServer.on('clientError', (err, socket) => {
        let dump = '';
        try { const b = socket.read(); if (b) dump += b.toString('latin1'); } catch { /* ignore */ }
        console.error('[E028-CLIENT-ERR] ' + (err && err.code ? err.code : '') + ' ' + (err && err.message ? err.message : err) + ' raw=' + JSON.stringify(dump.slice(0, 200)));
        try { socket.destroy(); } catch { /* ignore */ }
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
      httpsServer2.keepAliveTimeout = 65000;
      httpsServer2.headersTimeout = 66000;
      httpsServer2.requestTimeout = 120000;
      httpsServer2.on('clientError', (err, socket) => {
        console.error('[E028-CLIENT-ERR-9443] ' + (err && err.code ? err.code : '') + ' ' + (err && err.message ? err.message : err));
        try { socket.destroy(); } catch { /* ignore */ }
      });
      createWebSocketServer(httpsServer2);
    }

    // Start ARS TCP Server (DVRIP/DHIP on port 9500)
    console.log('[DEBUG] Starting ARS TCP Server on port', ARS_PORT);
    createARSTCPServer();
    console.log('[DEBUG] ARS TCP Server creation returned');

    // E-039: MQTT notify broker for the real brms.notify* topics advertised
    // by GetMqConfig (MQType "mqtt"). Device add/delete publish here.
    MQTT.listen(MQTT_PORT, '0.0.0.0')
      .then((addr) => console.log(`[MQTT] Notify broker listening on 0.0.0.0:${addr.port} (topics brms.notify*)`))
      .catch((err) => console.log('[MQTT] broker start failed:', err.message));

    // E-040: STOMP publisher to ActiveMQ Classic (OpenWire 61616 is served by
    // the activemq service; this gateway only publishes via STOMP 61613).
    if (AMQ) {
      AMQ.start();
      console.log(`[E040-AMQ] STOMP publisher targeting ${AMQ_HOST}:${AMQ_STOMP_PORT} (OpenWire advertised on ${PUBLIC_HOST}:${AMQ_PORT})`);
    }

    // SIP Server (DSS Client intercom/voice registration)
    // E-130 (REA ses_e451b4956ffeQdao3cVAOkhYQp): DPSDK arranca 'tcp start
    // server' (0xc56d30) y 'tls start server' (0xc56528) ademas de UDP -
    // sin SIP TCP 5080 / TLS 5061 el INVITE de intercom no completa.
    const SIP_TLS_PORT = parseInt(process.env.SIP_TLS_PORT || '5061', 10);
    function handleSipMessage(text, remoteAddr, sendFn, transport) {
      console.log(`[SIP ${transport}] ${remoteAddr} -> ${text.substring(0, 200)}`);
      if (!text.includes('SIP/2.0')) return;
      const lines = text.split('\r\n');
      const headers = {};
      let callId = '', fromTag = '', via = '', cseq = '', rawFrom = '', rawTo = '';
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.startsWith('Via:')) via = line.substring(4).trim();
        else if (line.startsWith('From:')) { rawFrom = line; const m = line.match(/tag=([^;>]+)/); if (m) fromTag = m[1]; }
        else if (line.startsWith('To:')) rawTo = line;
        else if (line.startsWith('Call-ID:')) callId = line.substring(8).trim();
        else if (line.startsWith('CSeq:')) cseq = line.substring(5).trim();
      }
      const respTag = crypto.randomBytes(8).toString('hex');
      // E-134 D6 (REA auditor, sipCallHandler_checkReq 0x180a90850): Via ya
      // trae ;branch= -> NO duplicarlo, solo anadir received=; From/To se
      // devuelven textuales (host y tag originales preservados).
      const viaOut = via + `;received=${remoteAddr}`;
      const fromOut = rawFrom || `From: <sip:8888881000@${PUBLIC_HOST}>;tag=${fromTag}`;
      const toOut = (rawTo ? rawTo + `;tag=${respTag}` : `To: <sip:8888881000@${PUBLIC_HOST}>;tag=${respTag}`);
      let response;
      if (text.includes('REGISTER')) {
        response = [
          'SIP/2.0 200 OK',
          `Via: ${viaOut}`,
          fromOut,
          toOut,
          `Call-ID: ${callId}`,
          `CSeq: ${cseq}`,
          `Contact: <sip:8888881000@${PUBLIC_HOST}:${SIP_PORT};transport=${transport}>`,
          'Expires: 3600', 'Content-Length: 0', '', ''
        ].join('\r\n');
      } else {
        // OPTIONS/INVITE/MESSAGE/etc: generic 200 OK so the UA proceeds
        response = [
          'SIP/2.0 200 OK',
          `Via: ${viaOut}`,
          fromOut,
          toOut,
          `Call-ID: ${callId}`,
          `CSeq: ${cseq}`,
          'Content-Length: 0', '', ''
        ].join('\r\n');
      }
      sendFn(response, (err) => {
        if (err) console.log('[SIP] Response error:', err.message);
        else console.log(`[SIP] 200 OK sent to ${remoteAddr} (${transport})`);
      });
    }

    // SIP UDP 5080
    const sipUdp = dgram.createSocket('udp4');
    sipUdp.on('message', (msg, rinfo) => {
      handleSipMessage(msg.toString().trim(), rinfo.address, (resp, cb) => sipUdp.send(resp, rinfo.port, rinfo.address, cb), 'udp');
    });
    sipUdp.on('error', (err) => { console.error('[SIP UDP] Error:', err.message); });
    sipUdp.bind(SIP_PORT, '0.0.0.0', () => {
      console.log(`SIP UDP Server listening on 0.0.0.0:${SIP_PORT}`);
    });

    // E-130: SIP TCP 5080 (mismo puerto, transporte tcp)
    const sipTcp = net.createServer((socket) => {
      let buf = '';
      socket.on('data', (chunk) => {
        buf += chunk.toString();
        let idx;
        while ((idx = buf.indexOf('\r\n\r\n')) !== -1) {
          const msg = buf.slice(0, idx + 4);
          buf = buf.slice(idx + 4);
          handleSipMessage(msg.trim(), socket.remoteAddress, (resp, cb) => socket.write(resp, cb), 'tcp');
        }
        if (buf.length > 64 * 1024) { socket.destroy(); } // anti-flood
      });
      socket.on('error', () => {});
      socket.setTimeout(120000, () => socket.destroy());
    });
    sipTcp.on('error', (err) => { console.error('[SIP TCP] Error:', err.message); });
    sipTcp.listen(SIP_PORT, '0.0.0.0', () => {
      console.log(`SIP TCP Server listening on 0.0.0.0:${SIP_PORT}`);
    });

    // E-130: SIP over TLS 5061 (cert lab existente)
    try {
      const sipTls = tls.createServer({
        key: fs.readFileSync(SSL_KEY),
        cert: fs.readFileSync(SSL_CERT)
      }, (socket) => {
        let buf = '';
        socket.on('data', (chunk) => {
          buf += chunk.toString();
          let idx;
          while ((idx = buf.indexOf('\r\n\r\n')) !== -1) {
            const msg = buf.slice(0, idx + 4);
            buf = buf.slice(idx + 4);
            handleSipMessage(msg.trim(), socket.remoteAddress, (resp, cb) => socket.write(resp, cb), 'tls');
          }
          if (buf.length > 64 * 1024) socket.destroy();
        });
        socket.on('error', () => {});
        socket.setTimeout(120000, () => socket.destroy());
      });
      sipTls.on('error', (err) => { console.error('[SIP TLS] Error:', err.message); });
      sipTls.listen(SIP_TLS_PORT, '0.0.0.0', () => {
        console.log(`SIP TLS Server listening on 0.0.0.0:${SIP_TLS_PORT}`);
      });
    } catch (err) {
      console.error('[SIP TLS] no se pudo abrir 5061:', err.message);
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