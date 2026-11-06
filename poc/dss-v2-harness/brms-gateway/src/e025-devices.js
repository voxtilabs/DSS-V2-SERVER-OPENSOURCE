// ===== E-025: DEVICE ADD / DISCOVERY / NETWORK / TIMEZONE / AUTO-REGISTER =====
//
// Root causes fixed by this module (all confirmed from the live gateway trace,
// E-025 log harvest: 23 [FALLBACK] hits + 2 404s + failed ONVIF add):
//
//   1) The client's "Add Device" flow never returns from /device/discover/*
//      because our server answered the generic empty fallback envelope. The
//      real client (useDeviceApi-CXeZa_J4.js) calls, in this exact order:
//        POST /brms/api/v1.1/device/discover/cost-time   {deviceIp,devicePort,...}
//        POST /brms/api/v1.1/device/discover/summary     {deviceIp,devicePort,...}
//        POST /brms/api/v1.1/device                      {full form + loginPass}
//        GET  /brms/api/v1.1/device/page
//        GET  /brms/api/v1.1/discover/device/page
//   2) /config/server/timezone, /config/timezone/list, /system/network/list,
//      /device/statistics/count-by-device-category/list, /role/page,
//      /function/available/list, /subsystem/available/list and
//      /omms/api/v1.1/alert/rule/alert-type/list served the generic empty
//      fallback -> "abnormal data" toasts.
//   3) GET /brms/api/v1.0/tree/orgs|devices|channels were only registered for
//      POST, so the launcher page's prefetch hit the fallback.
//
// EVIDENCE for the payloads in this file:
//   - Route inventory + DTO key names: DPSDK.dll string table (313 REST paths,
//     items/param1/param2, deviceCategoryName/deviceTypes/deviceTypeName,
//     manufacturerCode/manufacturerName).
//   - Discover/add request bodies: live gateway [REQ-BODY] lines (E-025).
//   - ONVIF identity: REAL GetDeviceInformation SOAP response captured from the
//     operator's camera 192.168.0.238:8021 (Manufacturer/Model/FirmwareVersion/
//     SerialNumber/HardwareId) -> the probe below queries the device for real
//     instead of inventing identity data.
//   - Easy4IP/P2P: DPSDK.dll "CP2PServerManager" strings ->
//       POST http://www.easy4ip.com/webservice/GetDeviceInterface?wsdl
//       Content-Type: text/xml; charset=UTF-8
//       <soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
//         <soap:Body>
//           <ns2:getDeviceByDevSequence xmlns:ns2='http://webservice.ddns.dahua.com/'>
//             <devSequence>%s</devSequence>
//           </ns2:getDeviceByDevSequence>
//         </soap:Body>
//       </soap:Envelope>
//     parsed back for <devSequence>/<ipAddress> (P2PServerManager.cpp).
//     P2P server candidates from the same binary: www.easy4ip.com,
//     www.easy4ipcloud.com, www.dahuap2p.com, www.dahuap2pcloud.com,
//     p2p.myeasyip.com.
//
// Nothing here stores credentials: the client sends loginPass as an MD5 hash and
// we never echo or persist it (ADR-0003/0004).

import fs from 'node:fs';
import http from 'node:http';
import dns from 'node:dns';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  discoverOnvifStreamUri,
  configureMediaMTXPath,
  removeMediaMTXPath,
  mediaMtxPathForDevice,
  dahuaRtspUri
} from './e026-video.js';
import { dirname } from 'node:path';
// E-041: the default org of a new device is the persisted org VIGILAB (the
// native add dialog sends orgCode "" - attempt-2 log - which must not stay
// empty; an empty orgCode also made the org-filtered tree drop the device).
import { DEFAULT_ORG_CODE, deviceOrgCode, orgName, getOrg } from './e041-orgs.js';

// ---------------------------------------------------------------------------
// 0) Tunables (no secrets, no hostnames from the lab config)
// ---------------------------------------------------------------------------
export const ONVIF_PROBE_TIMEOUT_MS = Number(process.env.E025_ONVIF_TIMEOUT_MS || 1500);
export const EASY4IP_PROBE_TIMEOUT_MS = Number(process.env.E025_EASY4IP_TIMEOUT_MS || 2500);
export const DISCOVER_COST_TIME_FLOOR_MS = Number(process.env.E025_COST_TIME_FLOOR_MS || 20);

// ---------------------------------------------------------------------------
// 1) Unified Device Store - RAM + disk persistence (data/devices.json)
//    Survives restarts and is shared by device/page, tree/*, statistics,
//    auto-register, P2P and manual add flows.
// ---------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
export const DEVICE_STORE_PATH = path.join(__dirname, '..', 'data', 'devices.json');

export const DEVICE_REGISTRY = new Map();
export const DISCOVERED_DEVICES = new Map();
let deviceSeq = 0;

function ensureDataDir() {
  const dir = path.dirname(DEVICE_STORE_PATH);
  try { fs.mkdirSync(dir, { recursive: true }); } catch { /* dir exists */ }
}

export function loadDevicesFromDisk() {
  try {
    ensureDataDir();
    const raw = fs.readFileSync(DEVICE_STORE_PATH, 'utf8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      for (const rec of arr) {
        DEVICE_REGISTRY.set(rec.deviceCode, rec);
      }
      if (arr.length) deviceSeq = arr.length;
      console.log(`[E026-STORE] Loaded ${arr.length} devices from ${DEVICE_STORE_PATH}`);
    }
  } catch (err) {
    console.log(`[E026-STORE] No existing device store (${DEVICE_STORE_PATH}), starting fresh`);
  }
}

export function saveDevicesToDisk() {
  try {
    ensureDataDir();
    const arr = [...DEVICE_REGISTRY.values()];
    // Strip loginPass / sensitive fields before persisting
    const safe = arr.map((d) => {
      const { loginPass, password, ...rest } = d;
      return rest;
    });
    fs.writeFileSync(DEVICE_STORE_PATH, JSON.stringify(safe, null, 2));
  } catch (err) {
    console.error('[E026-STORE] Failed to persist devices:', err.message);
  }
}

export function persistDevice(record) {
  DEVICE_REGISTRY.set(record.deviceCode, record);
  saveDevicesToDisk();
}

// E-034: give EVERY registered device a working RTSP path, no matter how it
// was registered (manual add, Discover join/batch, ONVIF add, Dahua
// auto-register). The Live View plays the URL returned by
// MTS/Video/StartVideo, so the device must own its MediaMTX path.
//
// Discovery order (real, never simulated):
//   1) the camera's own ONVIF GetStreamUri (the lab camera answers on 8021)
//   2) the Dahua native RTSP convention (EV-013) when the camera is not ONVIF
export async function ensureDeviceStream(device) {
  if (!device || !device.deviceIp) return null;
  const ip = String(device.deviceIp);
  const port = Number(device.devicePort) || 37777;
  const protocol = String(device.protocolType || '');
  let rtspUri = String(device.rtspUri || '');
  let source = 'cached';

  if (!rtspUri) {
    const creds = { userName: device.userName || device.loginName, password: device.loginPass || device.password };
    if (protocol === '99' || port === 8021) {
      const uri = await discoverOnvifStreamUri(ip, port, creds);
      if (uri) { rtspUri = uri; source = 'onvif'; }
    }
    if (!rtspUri && port !== 8021) {
      // the camera may still expose ONVIF on the standard ONVIF port
      const uri = await discoverOnvifStreamUri(ip, 8021, creds);
      if (uri) { rtspUri = uri; source = 'onvif-8021'; }
    }
    if (!rtspUri) {
      rtspUri = dahuaRtspUri(ip);
      source = 'dahua-convention';
    }
  } else {
    source = String(device.streamSource || 'cached');
  }

  // The path name only depends on the device code, so it is already set at
  // creation time (the RTSP source may still be unknown).
  const pathName = device.mediamtxPath || mediaMtxPathForDevice(device);
  const configured = await configureMediaMTXPath(pathName, rtspUri);
  device.rtspUri = rtspUri;
  device.mediamtxPath = pathName;
  device.streamSource = source;
  device.streamConfigured = !!configured;
  persistDevice(device);
  console.log('[E034-STREAM]', JSON.stringify({
    deviceCode: device.deviceCode, deviceIp: ip, devicePort: port,
    rtspUri, mediamtxPath: pathName, source, configured
  }));
  return device;
}

// Resolve the device that owns a channel id ("<deviceCode>$1$0$0").
export function findDeviceByChannelId(channelId) {
  const code = String(channelId || '').split('$')[0];
  if (!code) return null;
  return DEVICE_REGISTRY.get(code) || null;
}

export function nextDeviceCode(ip, prefix = 'D') {
  deviceSeq += 1;
  const stamp = Date.now().toString(36).slice(-4).toUpperCase();
  const tail = String(ip || '').replace(/\D/g, '').slice(-4) || '0000';
  return `${prefix}${tail}${stamp}${String(deviceSeq).padStart(3, '0')}`;
}

const VALID_PROTOCOLS = ['1', '2', '68', '98', '99', '100', '110', '120', '185'];

// Canonical add-device input (live [REQ-BODY] keys from DSS Client 8.006).
export function normalizeDeviceInput(body = {}) {
  const rawPort = body.devicePort ?? body.port ?? body.devicePortNumber;
  const port = Number(rawPort);
  const protocolType = String(body.protocolType ?? body.protocol ?? '99');
  const rawCount = body.encoderChannelCount ?? body.channelCount ?? body.channelNum ?? body.channelNumber ?? 1;
  const channelCount = Math.max(1, Number(rawCount) | 0 || 1);
  const ip = String(body.deviceIp ?? body.ip ?? body.host ?? '').trim();
  return {
    deviceIp: ip,
    devicePort: Number.isFinite(port) && port > 0 ? port : 37777,
    protocolType: VALID_PROTOCOLS.includes(protocolType) ? protocolType : '99',
    deviceCategory: String(body.deviceCategory ?? body.category ?? '1'),
    deviceType: String(body.deviceType ?? body.type ?? '1'),
    deviceName: String(body.deviceName ?? body.name ?? '').trim() || 'Device',
    serverCode: String(body.serverCode ?? body.server ?? 'video#local'),
    manufacturer: String(body.manufacturer ?? '').trim(),
    orgCode: String(body.orgCode ?? '').trim() || DEFAULT_ORG_CODE,
    channelCount,
    userName: String(body.userName ?? body.loginName ?? body.username ?? '').trim(),
    devSequence: String(body.devSequence ?? body.sn ?? body.serialNumber ?? '').trim(),
    deviceCode: String(body.deviceCode ?? body.deviceId ?? '').trim(),
    raw: { ...body }
  };
}

function protocolName(code) {
  return ({
    '1': 'Dahua', '2': 'Hikvision', '68': 'RTSP', '98': 'SNMP', '99': 'ONVIF',
    '100': 'SIA-CID', '110': 'SIA-DCS', '120': 'DDIP', '185': 'Jiuzhou'
  })[code] || 'ONVIF';
}

// ---------------------------------------------------------------------------
// 2) REAL ONVIF probe (GetDeviceInformation over SOAP 1.2)
//    Operator's camera answers on http://192.168.0.238:8021/onvif/device_service
//    -> Manufacturer "AI Sentinel", Model "EBA1_LECTOR_FHD_H265",
//       FirmwareVersion "2.1.0-H265", SerialNumber "SENTINEL_8021".
// ---------------------------------------------------------------------------
const ONVIF_SOAP_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <env:Body><tds:GetDeviceInformation/></env:Body>
</env:Envelope>`;

function soapTag(xml, tag) {
  const m = xml.match(new RegExp(`<(?:[\\w-]+:)?${tag}[^>]*>([^<]*)</(?:[\\w-]+:)?${tag}>`, 'i'));
  return m ? m[1].trim() : '';
}

export function probeOnvifDevice(ip, port, timeoutMs = ONVIF_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const started = Date.now();
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, costTimeMs: Date.now() - started });
    };
    if (!ip) return finish({ ok: false, offline: true, error: 'empty deviceIp' });

    // AbortController guarantees hard stop at timeoutMs (never blocks UI).
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), Math.max(200, timeoutMs | 0));

    const req = http.request({
      host: ip,
      port: Number(port) || 80,
      path: '/onvif/device_service',
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'Content-Length': Buffer.byteLength(ONVIF_SOAP_BODY),
        Accept: '*/*'
      }
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; if (data.length > 65536) data = data.slice(0, 65536); });
      res.on('end', () => {
        clearTimeout(abortTimer);
        const manufacturer = soapTag(data, 'Manufacturer');
        const model = soapTag(data, 'Model');
        const serialNumber = soapTag(data, 'SerialNumber');
        if (manufacturer || model) {
          finish({
            ok: true,
            online: true,
            manufacturer: manufacturer || 'ONVIF',
            model: model || '',
            firmwareVersion: soapTag(data, 'FirmwareVersion'),
            serialNumber,
            hardwareId: soapTag(data, 'HardwareId')
          });
        } else {
          finish({ ok: false, online: true, error: 'no GetDeviceInformation fields in response', httpStatus: res.statusCode });
        }
      });
    });
    req.on('aborted', () => { clearTimeout(abortTimer); if (!settled) finish({ ok: false, online: false, error: 'onvif probe aborted' }); });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, online: false, error: 'onvif probe timeout' }); });
    req.on('error', (err) => { clearTimeout(abortTimer); finish({ ok: false, online: false, error: err.code || err.message }); });
    req.end(ONVIF_SOAP_BODY);
  });
}

// No fallback identity is ever injected. If the ONVIF probe fails or times out,
// the device is still created with the user-supplied fields and empty identity
// fields. Never invent manufacturer/model/serial for an unknown device.

// ---------------------------------------------------------------------------
// 3) REAL Easy4IP / P2P lookup (getDeviceByDevSequence)
// ---------------------------------------------------------------------------
const EASY4IP_NAMESPACE = 'http://webservice.ddns.dahua.com/';
export const EASY4IP_SOAP_TEMPLATE = (devSequence) => `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
  <soap:Body>
    <ns2:getDeviceByDevSequence xmlns:ns2='${EASY4IP_NAMESPACE}'>
      <devSequence>${String(devSequence).replace(/[<>&]/g, '')}</devSequence>
    </ns2:getDeviceByDevSequence>
  </soap:Body>
</soap:Envelope>`;

export function probeEasy4IP(devSequence, host = 'www.easy4ip.com', timeoutMs = EASY4IP_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const started = Date.now();
    const body = EASY4IP_SOAP_TEMPLATE(devSequence);
    let settled = false;
    const finish = (r) => { if (!settled) { settled = true; resolve({ ...r, host, costTimeMs: Date.now() - started }); } };
    if (!devSequence) return finish({ ok: false, error: 'missing devSequence' });
    const req = http.request({
      host,
      port: 80,
      path: '/webservice/GetDeviceInterface?wsdl',
      method: 'POST',
      timeout: Math.max(200, timeoutMs | 0),
      headers: {
        'Content-Type': 'text/xml; charset=UTF-8',
        'Content-Length': Buffer.byteLength(body),
        Host: host,
        Accept: '*/*'
      }
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        const ipAddress = soapTag(data, 'ipAddress');
        // A well-formed serial that the cloud does not publish returns
        // HTTP 200 with an EMPTY <return/> (observed live for SENTINEL_8021).
        const answered = data.includes('<return');
        const returnEmpty = answered && !/<return[^>]*>[^<]+<\/return>/.test(data);
        finish({
          ok: true,
          httpStatus: res.statusCode,
          devSequence: soapTag(data, 'devSequence') || String(devSequence),
          ipAddress,
          port: soapTag(data, 'httpport') || soapTag(data, 'privport') || '',
          registered: !!ipAddress,
          answered,
          returnEmpty,
          raw: data.slice(0, 4000)
        });
      });
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, error: 'easy4ip timeout' }); });
    req.on('error', (err) => finish({ ok: false, error: err.code || err.message }));
    req.end(body);
  });
}

// ---------------------------------------------------------------------------
// 3b) Easy4IP / P2P reachability of the real endpoint set (DPSDK.dll):
//     www.easy4ip.com / www.easy4ipcloud.com / www.dahuap2p.com /
//     www.dahuap2pcloud.com / p2p.myeasyip.com
// ---------------------------------------------------------------------------
export const EASY4IP_HOSTS = [
  { host: 'www.easy4ip.com', transport: 'http', primary: true },
  { host: 'www.easy4ipcloud.com', transport: 'https', primary: false },
  { host: 'www.dahuap2p.com', transport: 'http', primary: true },
  { host: 'www.dahuap2pcloud.com', transport: 'https', primary: false },
  { host: 'p2p.myeasyip.com', transport: 'http', primary: false }
];

function tcpReachable(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let settled = false;
    const sock = net.createConnection({ host, port, timeout: timeoutMs }, () => {
      settled = true; sock.end(); resolve(true);
    });
    sock.on('timeout', () => { if (!settled) { settled = true; sock.destroy(); resolve(false); } });
    sock.on('error', () => { if (!settled) { settled = true; resolve(false); } });
    sock.on('close', () => { if (!settled) { settled = true; resolve(false); } });
  });
}

export async function probeEasy4IPReachability() {
  const results = [];
  for (const entry of EASY4IP_HOSTS) {
    const item = { ...entry, dns: null, http: null, https: null };
    try {
      const addresses = await dns.promises.lookup(entry.host);
      item.dns = addresses.address;
    } catch { item.dns = null; }
    item.http = await tcpReachable(entry.host, 80);
    item.https = await tcpReachable(entry.host, 443);
    item.up = item.http || item.https;
    results.push(item);
  }
  return results;
}

// ---------------------------------------------------------------------------
// 4) Device creation (manual add / discovery join / auto-register)
// ---------------------------------------------------------------------------
export function createDeviceRecord(input, identity = {}) {
  const code = input.deviceCode || nextDeviceCode(input.deviceIp, input.devSequence ? 'P2P' : 'D');
  const channelCount = Math.max(1, Number(input.channelCount) || 1);
  const materialized = input.deviceIp || identity.ipAddress || '';
  const record = {
    deviceId: code,
    deviceCode: code,
    deviceName: input.deviceName,
    deviceIp: materialized,
    devicePort: Number(input.devicePort) || 37777,
    protocolType: input.protocolType,
    protocolName: protocolName(input.protocolType),
    deviceCategory: input.deviceCategory,
    deviceType: input.deviceType,
    manufacturer: identity.manufacturer || input.manufacturer || '',
    model: identity.model || '',
    firmwareVersion: identity.firmwareVersion || '',
    serialNumber: identity.serialNumber || input.devSequence || '',
    hardwareId: identity.hardwareId || '',
    serverCode: input.serverCode,
    orgCode: input.orgCode,
    channelNum: channelCount,
    encoderChannelCount: channelCount,
    alarmInNum: channelCount,
    alarmOutNum: channelCount,
    diskNum: 1,
    status: 1,
    online: 1,
    isOnline: 1,
    isOnLine: 1,
    deviceStatus: 'online',
    collected: 1,
    createTime: new Date().toISOString(),
    updateTime: new Date().toISOString(),
    source: identity.source || 'manual',
    // E-034: the MediaMTX path of this device is derived from its code, so it
    // is known before the RTSP source is probed. MTS/Video/StartVideo resolves
    // the path from the channel id, so every device owns its own stream.
    mediamtxPath: mediaMtxPathForDevice({ deviceCode: code })
  };
  // E-032: persist immediately. The discovery "join/batch" path creates the
  // record here (not via POST /device, which persists on its own), so without
  // this write the device only lived in RAM and vanished on the next restart.
  persistDevice(record);
  return record;
}

export function findDeviceByIpPort(ip, port) {
  for (const d of DEVICE_REGISTRY.values()) {
    if (d.deviceIp === ip && Number(d.devicePort) === Number(port)) return d;
  }
  return null;
}

// E-038: the DSS channel code layout is
//     <deviceCode>$<unitType>$0$<channelSeq>
// proven in the PRODUCTION DSS web bundle (web-module/js/device-JBrSmGvP.js):
//     UNIT_TYPE:{ENC:"1",DEC:"2",ALARM_IN:"3",...}
// and in web-module/js/index-Cr8Ld85_.js:
//     I.editDeviceInfo.deviceCode + "$" + xe.UNIT_TYPE.ENC + "$0$" + e.channelSeq
// The server package confirms the same layout:
//   com.dcc.admin.common.constants.device.UnitType  (Encoder = 1, Decoder = 2, ...)
//   com.dcc.admin.biz.device.constants.DeviceResourceEnum.getChannelResourceType()
//       -> ChannelIdUtils.getUnitType(channelId) -> UnitType.getByType(...)
//          -> the unit type is the SECOND segment of the channel code.
// Before E-038 the gateway wrote "<code>$<channelNo>$0$0", so the second
// segment carried the channel number: a 2nd channel was parsed as a DECODER
// channel (unit type 2) by the client and by the server logic.
export const DSS_UNIT_TYPE_ENC = '1';

export function dssChannelCode(deviceCode, channelSeq) {
  return `${deviceCode}$${DSS_UNIT_TYPE_ENC}$0$${channelSeq}`;
}

function channelVo(device, no) {
  const channelSeq = Math.max(0, Number(no) - 1);
  return {
    channelId: dssChannelCode(device.deviceCode, channelSeq),
    channelCode: dssChannelCode(device.deviceCode, channelSeq),
    channelSeq,
    unitType: DSS_UNIT_TYPE_ENC,
    channelNo: no,
    channelName: no === 1 ? device.deviceName : `${device.deviceName} CH${no}`,
    deviceCode: device.deviceCode,
    deviceName: device.deviceName,
    orgCode: device.orgCode,
    channelType: 1,
    videoEncode: 'H.265',
    audioEncode: '',
    ptz: 0,
    audio: 1,
    record: 0,
    // E-095: channel cards compare channelStatus === DEVICE_STATUS_TYPE.ONLINE
    // (strict ===, string "1" - index-CW-2lZHA.js), so status/online must be
    // strings, plus the channelStatus alias the cards read.
    status: '1',
    online: '1',
    onlineStatus: '1',
    channelStatus: '1',
    // E-095: device detail channel tab reads statusName/faultStatusName/updateTime
    statusName: 'Channel Online',
    faultStatus: '0',
    faultStatusName: 'Normal',
    updateTime: new Date().toISOString().replace('T', ' ').slice(0, 19),
    deviceType: device.deviceType,
    deviceIp: device.deviceIp,
    devicePort: device.devicePort,
    protocolType: device.protocolType,
    serverCode: device.serverCode
  };
}

export function allChannels() {
  const out = [];
  for (const d of DEVICE_REGISTRY.values()) {
    for (let i = 1; i <= Math.max(1, d.channelNum); i++) out.push(channelVo(d, i));
  }
  return out;
}

// ---------------------------------------------------------------------------
// 5) Payload builders - every shape mirrors the DTO keys recovered from
//    DPSDK.dll + the live client requests (no invented keys, dual-key only
//    when the native parser and the web SPA disagree on the wrapper).
// ---------------------------------------------------------------------------
export function buildDeviceAddPayload(body, identity = {}, publicHost = '10.10.20.120', rtspPort = 9100) {
  const input = normalizeDeviceInput(body);
  const existing = findDeviceByIpPort(input.deviceIp, input.devicePort);
  const device = existing || createDeviceRecord(input, identity);
  persistDevice({ ...device, ...identity, deviceIp: input.deviceIp || device.deviceIp });
  const created = DEVICE_REGISTRY.get(device.deviceCode);
  const channels = [];
  for (let i = 1; i <= created.channelNum; i++) channels.push(channelVo(created, i));
  // Build the RTSP URL that the client should use. The camera may not expose
  // RTSP on the standard port 554 (observed: closed on 192.168.0.238:554,
  // open on :8554). We proxy the stream via MediaMTX on :9100 so the client
  // connects to *our* server instead of dialing the camera directly.
  const rtspUrl = `rtsp://${publicHost}:${rtspPort}/cam1`;
  // results[] is what the web SPA reads (E-024 shape discovery); device is the
  // single object the native DPSDK parser walks. Include every alias the
  // client may walk so it doesn't time out waiting for a missing field.
  return {
    desc: 'Success',
    id: created.deviceCode,
    code: created.deviceCode,
    results: [created],
    list: [created],
    device: created,
    deviceVo: created,
    deviceInfo: created,
    deviceCode: created.deviceCode,
    deviceId: created.deviceCode,
    deviceName: created.deviceName,
    deviceIp: created.deviceIp,
    devicePort: created.devicePort,
    protocolType: created.protocolType,
    protocolName: created.protocolName,
    deviceCategory: created.deviceCategory,
    deviceType: created.deviceType,
    manufacturer: created.manufacturer,
    model: created.model,
    firmwareVersion: created.firmwareVersion,
    serialNumber: created.serialNumber,
    hardwareId: created.hardwareId,
    serverCode: created.serverCode,
    orgCode: created.orgCode,
    channelNum: created.channelNum,
    encoderChannelCount: created.encoderChannelCount,
    alarmInNum: created.alarmInNum,
    alarmOutNum: created.alarmOutNum,
    diskNum: created.diskNum,
    status: created.status,
    online: created.online,
    isOnline: created.isOnline,
    isOnLine: created.isOnLine,
    deviceStatus: created.deviceStatus,
    collected: created.collected,
    createTime: created.createTime,
    updateTime: created.updateTime,
    source: created.source,
    // RTSP stream URL proxied via our MediaMTX (so the client does not need
    // to dial the camera's RTSP port directly).
    rtspUrl,
    url: rtspUrl,
    streamUrl: rtspUrl,
    playUrl: rtspUrl,
    channels,
    channelList: channels,
    channelCount: channels.length,
    total: 1,
    success: true
  };
}

// ---------------------------------------------------------------------------
// RTSP URL lookup for an existing device
// ---------------------------------------------------------------------------
export function buildDeviceRtspUrlPayload(deviceCode, publicHost = '10.10.20.120', rtspPort = 9100) {
  const device = DEVICE_REGISTRY.get(String(deviceCode));
  if (!device) return null;
  return {
    code: 1000,
    desc: 'Success',
    data: {
      deviceCode: device.deviceCode,
      deviceName: device.deviceName,
      rtspUrl: `rtsp://${publicHost}:${rtspPort}/cam1`,
      url: `rtsp://${publicHost}:${rtspPort}/cam1`,
      deviceIp: device.deviceIp,
      devicePort: device.devicePort,
      protocolType: device.protocolType
    }
  };
}

export function buildDiscoverCostTimePayload(body, identity = {}) {
  const input = normalizeDeviceInput(body);
  const key = `${input.deviceIp}:${input.devicePort}:${input.protocolType}`;
  DISCOVERED_DEVICES.set(key, {
    ...input,
    probe: identity,
    discoveredAt: Date.now()
  });
  return {
    costTime: Math.max(DISCOVER_COST_TIME_FLOOR_MS, Number(identity.costTimeMs) || 0),
    costTimeMs: Math.max(DISCOVER_COST_TIME_FLOOR_MS, Number(identity.costTimeMs) || 0),
    totalTime: Math.max(DISCOVER_COST_TIME_FLOOR_MS, Number(identity.costTimeMs) || 0),
    deviceIp: input.deviceIp,
    devicePort: input.devicePort,
    deviceCount: identity.online === false ? 0 : 1,
    online: identity.online !== false ? 1 : 0,
    results: identity.online === false ? [] : [{
      deviceIp: input.deviceIp,
      devicePort: input.devicePort,
      protocolType: input.protocolType,
      costTime: Math.max(DISCOVER_COST_TIME_FLOOR_MS, Number(identity.costTimeMs) || 0)
    }]
  };
}

export function buildDiscoverSummaryPayload(body, identity = {}) {
  const input = normalizeDeviceInput(body);
  const online = identity.online !== false;
  const summary = {
    deviceCode: input.deviceCode,
    deviceIp: input.deviceIp,
    devicePort: input.devicePort,
    protocolType: input.protocolType,
    deviceCategory: input.deviceCategory,
    deviceType: input.deviceType,
    deviceName: input.deviceName,
    channelCount: input.channelCount,
    // display fallback: the protocol name (what the combo shows) until the
    // probe returns a real manufacturer; empty only means "not probed yet".
    manufacturer: identity.manufacturer || input.manufacturer || protocolName(input.protocolType),
    model: identity.model || '',
    firmwareVersion: identity.firmwareVersion || '',
    serialNumber: identity.serialNumber || input.devSequence || '',
    hardwareId: identity.hardwareId || '',
    online: online ? 1 : 0,
    status: online ? 1 : 0,
    deviceStatus: online ? 'online' : 'offline',
    errorCode: identity.ok === false ? 1001 : 0,
    errorMsg: identity.error || ''
  };
  return {
    ...summary,
    summary,
    deviceVo: summary,
    deviceInfo: summary,
    results: [summary],
    list: [summary],
    total: 1,
    success: true
  };
}

export function buildDiscoverDetailPayload(body, identity = {}) {
  const input = normalizeDeviceInput(body);
  const summary = buildDiscoverSummaryPayload(body, identity);
  return { ...summary, channels: [], channelList: [], capabilities: [] };
}

// E-095: exact row contract of the REAL bundle's deviceTable component
// (web-module/js/index-yv7-szZK.js, Device Status -> "Real-Time" tab).
// Column props read from the minified source (verified, not guessed):
//   "NO"(client-set) "deviceName" "deviceIp" "deviceCategoryName"
//   "deviceTypeName" "orgName" "statusName" "faultStatusName"
//   "channelFaultStatusName" "deviceRecordWholenessStatusName"
//   "diskStatusName" "pendingCount"; Operate uses deviceCode/orgCode/orgName/
//   deviceCategory. The "Online/Offline Status" column has prop "statusName"
//   and renders row.statusName as text plus an icon from row.status
//   (0==offline, 1==online, loose ==). Its filter model sends status as a
//   comma string ("0,1"). deviceTable loads via getPageDevices
//   (GET /omms/api/v1.1/device/page) reading data.pageData + data.totalCount.
// E-095: registry records store online as boolean/1/"1" interchangeably.
export function deviceOnlineOf(d) {
  return !(d.online === false || d.online === 0 || d.online === '0');
}

export function buildDeviceTableRow(d) {
  const online = deviceOnlineOf(d);
  return {
    ...d,
    id: d.deviceCode,
    orgCode: deviceOrgCode(d),
    orgName: orgName(deviceOrgCode(d)),
    deviceCategoryName: d.deviceCategoryName || d.deviceCategory || '',
    deviceTypeName: d.deviceTypeName || d.deviceType || '',
    // "Online/Offline Status" column: prop "statusName" + icon from "status".
    // E-095 root cause of the "Offline" label: the SPA tables compare with
    // STRICT === against DEVICE_STATUS.ONLINE which is the STRING "1"
    // (device-JBrSmGvP.js: DEVICE_STATUS:{OFFLINE:"0",ONLINE:"1",SLEEP:"2"};
    // index-DsQ1Ve9V.js: e.status === DEVICE_STATUS.ONLINE). A numeric 1
    // never matches, so the row fell into the else -> "Offline". The omms
    // deviceTable icon uses loose == (1==a), which also matches "1".
    statusName: online ? 'Online' : 'Offline',
    status: online ? '1' : '0',
    onlineStatus: online ? '1' : '0',
    online: online ? '1' : '0',
    isOnline: online ? '1' : '0',
    isOnLine: online ? '1' : '0',
    deviceStatus: online ? 'online' : 'offline',
    offlineReason: online ? '' : (d.errorMsg || 'offline'),
    errorCode: online ? 0 : 1,
    // "Device Status" column: prop "faultStatusName" + icon from "faultStatus"
    // (bundle filter enum: Normal "0" / Abnormal "1")
    faultStatusName: 'Normal',
    faultStatus: '0',
    // Channel Status / Video Integrity / Disk Status columns render the *Name
    // only when the flag is truthy, otherwise "--"
    channelFaultStatusName: 'Normal',
    channelFaultStatus: 1,
    deviceRecordWholenessStatusName: 'Normal',
    deviceRecordWholenessStatus: 1,
    diskStatusName: 'Normal',
    diskStatus: 1,
    // "Alerts to be Processed from Last 7 Days" (renders pendingCount||"--")
    pendingCount: 0
  };
}

// Query params may arrive as a comma string ("0,1") or as an array
// (qs extended parser) - the deviceTable sends comma strings.
function queryList(v) {
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return String(v).split(',').map((x) => x.trim()).filter(Boolean);
}

export function buildDevicePagePayload(query = {}) {
  const page = Math.max(1, Number(query.pageNo ?? query.page ?? 1) || 1);
  const size = Math.max(1, Number(query.pageSize ?? query.page) || 20);
  const keyword = String(query.keyword ?? '').trim();
  const orgFilter = String(query.orgCode ?? '').trim();
  let list = [...DEVICE_REGISTRY.values()];
  if (orgFilter) {
    // containChild=1 (the Device page always sends it): an org matches when it
    // IS the selected org or a descendant of it.
    const isDescendant = (code) => {
      let cur = code, guard = 0;
      while (cur && guard++ < 16) { if (cur === orgFilter) return true; cur = getOrg(cur)?.parentCode || ''; }
      return false;
    };
    list = list.filter((d) => isDescendant(deviceOrgCode(d)));
  }
  if (keyword) list = list.filter((d) => d.deviceName.includes(keyword) || d.deviceIp.includes(keyword));
  // E-095: deviceTable filter params (verified in index-yv7-szZK.js):
  //   status:"0,1" faultStatus:"0,1" deviceTypes:"1,2" deviceCategory deviceCode
  const statusSet = queryList(query.status);
  if (statusSet.length) list = list.filter((d) => statusSet.includes(d.online === false ? '0' : '1'));
  const faultSet = queryList(query.faultStatus);
  if (faultSet.length) list = list.filter(() => faultSet.includes('0')); // all rows are faultStatus 0 (Normal)
  const catFilter = String(query.deviceCategory ?? '').trim();
  if (catFilter) list = list.filter((d) => String(d.deviceCategory ?? '') === catFilter);
  const typesSet = queryList(query.deviceTypes);
  if (typesSet.length) list = list.filter((d) => typesSet.includes(String(d.deviceType ?? '')));
  const codeSet = queryList(query.deviceCode);
  if (codeSet.length) list = list.filter((d) => codeSet.includes(String(d.deviceCode ?? '')));
  const start = (page - 1) * size;
  const slice = list.slice(start, start + size);
  // E-094/E-095: the web SPA device table reads data.pageData + data.totalCount;
  // rows carry the exact column props the bundle reads (buildDeviceTableRow).
  const rows = slice.map((d) => buildDeviceTableRow(d));
  return {
    list: rows,
    results: rows,
    deviceList: rows,
    items: rows,
    pageData: rows,
    pageNo: page,
    pageSize: size,
    total: list.length,
    totalCount: list.length,
    pageCount: Math.max(1, Math.ceil(list.length / size)),
    onlineCount: list.filter((d) => deviceOnlineOf(d)).length
  };
}

// E-027: the real client polls this page with `initialized=` after adding a
// device and keeps waiting until the added device shows up with
// initialized === "1" (INITIALIZED) or "2" (MODIFY_IP) - enum extracted verbatim
// from the production bundle (real-index-BIzql2yJ.js). An empty list made the
// native add dialog wait forever -> DPSDK "Operation timed out".
// E-028: ONE row per ip:port. A scanned-but-not-yet-added device used to be
// emitted first with initialized:"" and the registered copy second with
// initialized:"1"; the client matched the first row and kept waiting until the
// 30s timeout. Registered devices now always win the row.
export function buildDiscoverDevicePagePayload(query = {}) {
  const key = (ip, port) => `${ip}:${Number(port)}`;
  const registered = new Map();
  for (const d of DEVICE_REGISTRY.values()) registered.set(key(d.deviceIp, d.devicePort), d);

  const list = [];
  const emitted = new Set();
  const registeredRow = (d) => ({
    // E-029: the Add-Discover page (index-DsQ1Ve9V.js) reads rows as
    //   x.value = data.pageData; addIds = map(rows, "id");
    //   row.initStatus ("0" Uninitialized / "1" Initialized), row.protocol
    // (compared against DEV_PROTOCOL_TYPE.DAHUA "1" / ONVIF "99").
    id: d.deviceCode,
    deviceIp: d.deviceIp,
    devicePort: String(d.devicePort ?? ''),
    protocolType: d.protocolType,
    protocol: d.protocolType,
    initStatus: '1',
    deviceCategory: d.deviceCategory,
    deviceType: d.deviceType,
    deviceName: d.deviceName,
    deviceCode: d.deviceCode,
    deviceId: d.deviceId || d.deviceCode,
    manufacturer: d.manufacturer || '',
    model: d.model || '',
    serialNumber: d.serialNumber || '',
    firmwareVersion: d.firmwareVersion || '',
    online: d.online === false ? 0 : 1,
    initialized: '1',
    modifiedIp: '0',
    status: 1,
    deviceStatus: 'online',
    errorCode: 0,
    errorMsg: '',
    channelNum: d.channelNum || 1,
    discoveredAt: d.createTime || d.discoveredAt || ''
  });
  const discoveredRow = (d) => ({
    // E-029: stable row id the scene-level join/batch resolves back to this
    // discovered record (probe fields come along, the device is created on add).
    id: `DSC-${d.deviceIp}:${d.devicePort}`,
    deviceIp: d.deviceIp,
    devicePort: String(d.devicePort ?? ''),
    protocolType: d.protocolType,
    protocol: d.protocolType,
    initStatus: d.registered ? '1' : '0',
    deviceCategory: d.deviceCategory,
    deviceType: d.deviceType,
    deviceName: d.deviceName,
    deviceCode: '',
    deviceId: '',
    manufacturer: d.probe?.manufacturer || '',
    model: d.probe?.model || '',
    serialNumber: d.probe?.serialNumber || '',
    firmwareVersion: d.probe?.firmwareVersion || '',
    online: d.probe?.online === false ? 0 : 1,
    initialized: d.registered ? '1' : '',
    modifiedIp: '0',
    status: 1,
    deviceStatus: d.probe?.online === false ? 'offline' : 'online',
    errorCode: 0,
    errorMsg: '',
    discoveredAt: d.discoveredAt
  });

  for (const d of DISCOVERED_DEVICES.values()) {
    const k = key(d.deviceIp, d.devicePort);
    if (emitted.has(k)) continue;
    emitted.add(k);
    list.push(registered.has(k) ? registeredRow(registered.get(k)) : discoveredRow(d));
  }
  for (const [k, d] of registered) {
    if (emitted.has(k)) continue;
    emitted.add(k);
    list.push(registeredRow(d));
  }
  // the client may filter by initialization state
  const wanted = query && query.initialized !== undefined && query.initialized !== null && String(query.initialized) !== '';
  const filtered = wanted ? list.filter((r) => r.initialized === String(query.initialized)) : list;
  return {
    // E-029: the Add-Discover page reads data.pageData (x.value = l.pageData).
    pageData: filtered,
    list: filtered,
    results: filtered,
    items: filtered,
    total: filtered.length,
    totalCount: filtered.length,
    pageNo: 1,
    pageSize: Math.max(20, filtered.length)
  };
}

export function buildDiscoverDeviceInitPayload(body = {}) {
  const input = normalizeDeviceInput(body);
  const existing = findDeviceByIpPort(input.deviceIp, input.devicePort);
  const device = existing || createDeviceRecord(input, { source: 'discovery' });
  const channels = [];
  for (let i = 1; i <= device.channelNum; i++) channels.push(channelVo(device, i));
  return {
    device,
    deviceVo: device,
    deviceCode: device.deviceCode,
    deviceId: device.deviceCode,
    channels,
    channelList: channels,
    capabilities: device.channelNum,
    total: 1,
    success: true
  };
}

// E-029 details (index-DsQ1Ve9V.js batchAddDiscoverDlg / detail dialog):
//   const{code:l,data:s}=await addDiscoverDevices({...base, ids: chunk});
//   for (const r of s.results) {
//     "0"===r.result                                              -> succeed row
//     r.result==Ve.DEVICE_NOT_SUPPORT_IN_AREA (110262)            -> failure row
//     r.result==Ve.DEVICE_PROTOCOL_NOT_SUPPORT (110113)           -> failure row
//   }
// The SPA prefixes r.deviceName in its failure detail and fills errorMsg itself
// per code, so the server sends result + deviceName (+empty errorMsg). ids[]
// are the row ids plucked from /discover/device/page (registered rows: device
// code; discovered rows: "DSC-ip:port" - resolved against DISCOVERED_DEVICES).
const DEVICE_PROTOCOL_NOT_SUPPORT = 110113;
const DEVICE_NOT_SUPPORT_IN_AREA = 110262;

export function buildDiscoverJoinBatchPayload(body = {}) {
  const outcomeOf = (row, code) => ({
    result: code === 0 ? '0' : String(code),
    id: row.id || row.deviceCode || '',
    deviceIp: row.deviceIp || '',
    devicePort: String(row.devicePort ?? ''),
    deviceName: row.deviceName || '',
    deviceCode: row.deviceCode || '',
    errorMsg: ''
  });
  // E-030: results carries ONLY failure rows. Evidence — the real bundle
  // index-DsQ1Ve9V.js `je` handler: the single-add dialog sets its failure flag
  // on EVERY row it iterates ("0"===a.result?(e=!0,...) ...) and shows
  // "Failed to add device" whenever results is non-empty, so a success row in
  // results mislabels a successful add. The batch dialog
  // (batchAddDiscoverDlg) counts succeed = chunk.length - results.length, so
  // an empty results array on full success is correct for BOTH consumers.

  const ensureDevice = (raw) => {
    if (!raw || typeof raw !== 'object') return null;
    const input = normalizeDeviceInput(raw);
    if (!input.deviceIp) return null;
    const identity = { source: 'discovery', manufacturer: raw.manufacturer, model: raw.model, firmwareVersion: raw.firmwareVersion, serialNumber: raw.serialNumber };
    return findDeviceByIpPort(input.deviceIp, input.devicePort) || createDeviceRecord(input, identity);
  };

  const toPayload = (outcomes, created) => ({
    results: outcomes.filter((o) => o.result !== '0'),
    list: created,
    deviceList: created,
    items: created,
    total: created.length,
    success: true,
    failList: outcomes.filter((o) => o.result !== '0')
  });

  const ids = Array.isArray(body.ids) ? body.ids : null;
  if (ids) {
    const outcomes = [];
    const created = [];
    const discovered = [...DISCOVERED_DEVICES.values()];
    for (const id of ids) {
      if (id != null && typeof id === 'object') {
        const device = ensureDevice(id);
        if (device) { created.push(device); outcomes.push(outcomeOf(device, 0)); }
        else outcomes.push(outcomeOf({}, DEVICE_PROTOCOL_NOT_SUPPORT));
        continue;
      }
      const key = String(id);
      let device = DEVICE_REGISTRY.get(key);
      if (!device && discovered.length) {
        const hit = discovered.find((d) =>
          `${d.deviceIp}:${d.devicePort}` === key || `DSC-${d.deviceIp}:${d.devicePort}` === key);
        if (hit) device = ensureDevice(hit);
      }
      if (device) { created.push(device); outcomes.push(outcomeOf(device, 0)); }
      else outcomes.push(outcomeOf({}, DEVICE_PROTOCOL_NOT_SUPPORT));
    }
    return toPayload(outcomes, created);
  }

  const items = Array.isArray(body.devices) ? body.devices
    : Array.isArray(body.list) ? body.list
      : Array.isArray(body.items) ? body.items : [body];
  const created2 = [];
  const outcomes = [];
  for (const raw of items) {
    const device = ensureDevice(raw);
    if (device) { created2.push(device); outcomes.push(outcomeOf(device, 0)); }
    else outcomes.push(outcomeOf({}, DEVICE_PROTOCOL_NOT_SUPPORT));
  }
  return toPayload(outcomes, created2);
}

export function buildDeviceAddBatchPayload(body = {}) {
  return buildDiscoverJoinBatchPayload(body);
}

// E-031: web SPA resource helpers (proven from useDeviceApi-CXeZa_J4.js +
// u-device-Clmrne3b.js + index-BQObycDy.js; all three previously answered from
// the generic fallback, which left live-view/storage/monitor trees without
// channel rows and produced the broken GET /device/undefined requests).
//   getChannels     -> POST /brms/api/v1.1/device/channel/list {ids:[...]}
//                      consumer: `const{code,data}=await c({ids}); return data.results`
export function buildChannelListPayload(body = {}) {
  const all = allChannels();
  const ids = Array.isArray(body.ids) ? body.ids.map(String) : [];
  const results = ids.length ? all.filter((ch) => ids.includes(ch.channelId)) : all;
  return { results, list: results, total: results.length };
}

//   getDeviceOrganizations
//     -> POST /brms/api/v1.1/device/organization/fetch/batch/list
//        {deviceCodes:[...]}; consumers iterate the DATA ARRAY itself
//        (index-B8bjlgBo.js: const{data:l}; _(l,(e)=>e.deviceCode===e.id))
export function buildDeviceOrganizationBatchPayload(body = {}) {
  const codes = Array.isArray(body.deviceCodes) ? body.deviceCodes.map(String) : [];
  const rows = [];
  for (const d of DEVICE_REGISTRY.values()) {
    if (codes.length && !codes.includes(String(d.deviceCode))) continue;
    rows.push({
      deviceCode: d.deviceCode,
      deviceName: d.deviceName,
      orgCode: deviceOrgCode(d),
      orgName: orgName(deviceOrgCode(d)) || 'Root Org',
      pId: getOrg(deviceOrgCode(d))?.parentCode || '0'
    });
  }
  return rows;
}

//   getDevice       -> GET /brms/api/v1.1/device/{deviceCode}
//                      consumer: `getDeviceInfo` returns `data` untouched
export function findDevicePayloadByCode(deviceCode) {
  if (!deviceCode) return null;
  return DEVICE_REGISTRY.get(String(deviceCode)) || null;
}

export function buildDeviceCheckExistPayload(body = {}) {
  const input = normalizeDeviceInput(body);
  const existing = findDeviceByIpPort(input.deviceIp, input.devicePort);
  const byCode = input.deviceCode ? DEVICE_REGISTRY.get(input.deviceCode) : null;
  const hit = existing || byCode;
  return {
    exist: !!hit,
    isExist: !!hit ? 1 : 0,
    exists: !!hit ? 1 : 0,
    deviceCode: hit ? hit.deviceCode : '',
    deviceName: hit ? hit.deviceName : '',
    results: [],
    list: [],
    total: hit ? 1 : 0,
    success: true
  };
}

export function buildDeviceUnauthorizedPagePayload() {
  return { list: [], results: [], items: [], total: 0, totalCount: 0, pageNo: 1, pageSize: 20 };
}

export function buildDeviceDeleteBatchPayload(body = {}) {
  const codes = [].concat(body.deviceCodes || body.codes || body.list || []).filter(Boolean);
  let removed = 0;
  for (const code of codes) {
    if (DEVICE_REGISTRY.delete(String(code))) removed += 1;
    // E-034 hygiene: the deleted device vacates its MediaMTX path too.
    if (code) {
      setImmediate(() => { if (!removeMediaMTXPath(mediaMtxPathForDevice({ deviceCode: code }))) console.log('[E034-STREAM] path removal ignored for', code); });
    }
  }
  // E-032: rewrite the store so deleted devices do NOT come back after a
  // restart (the registry and devices.json used to drift apart).
  if (removed) saveDevicesToDisk();
  return { success: true, removed, deleted: removed, results: [], list: [], total: removed };
}

export function buildDeviceMoveBatchPayload() { return { success: true, results: [], list: [] }; }
export function buildDevicePasswordChangeBatchPayload() { return { success: true, results: [], list: [], failList: [] }; }
export function buildDeviceTimezoneUpdateBatchPayload() { return { success: true, results: [], list: [], failList: [] }; }

export function buildDeviceDiscoverAsyncBatchPayload() {
  return { taskId: 'disc-' + Date.now().toString(36), status: 'success', progress: 100, results: [], total: 0 };
}

// ---------------------------------------------------------------------------
// 6) Statistics / network / timezone / roles / functions / subsystems
// ---------------------------------------------------------------------------
export function buildStatisticsCategoryPayload(catalog, query = {}) {
  const counts = new Map();
  const onlineCounts = new Map();
  for (const d of DEVICE_REGISTRY.values()) {
    const key = String(d.deviceCategory || '1');
    counts.set(key, (counts.get(key) || 0) + 1);
    // E-095: onlineCount must reflect the real online state, not equal deviceCount
    if (deviceOnlineOf(d)) onlineCounts.set(key, (onlineCounts.get(key) || 0) + 1);
  }
  const list = catalog.map((g) => ({
    deviceCategory: g.deviceCategory,
    deviceCategoryName: g.deviceCategoryName,
    deviceCount: counts.get(String(g.deviceCategory)) || 0,
    onlineCount: onlineCounts.get(String(g.deviceCategory)) || 0,
    channelCount: (counts.get(String(g.deviceCategory)) || 0) * 1,
    type: g.deviceCategory,
    name: g.deviceCategoryName,
    value: counts.get(String(g.deviceCategory)) || 0
  }));
  return {
    results: list,
    list,
    items: list,
    dictionaryList: list,
    total: list.length,
    totalCount: list.length,
    keyword: String(query.keyword ?? ''),
    orgCode: String(query.orgCode ?? ''),
    sourceType: String(query.sourceType ?? '1'),
    permitted: String(query.permitted ?? '0'),
    domain: String(query.domain ?? '0'),
    containChild: String(query.containChild ?? '1')
  };
}

export function buildNetworkListPayload() {
  const interfaces = os.networkInterfaces();
  const primary = Object.values(interfaces).flat().find((n) => n.family === 'IPv4' && !n.internal);
  const list = Object.entries(interfaces).flatMap(([name, addrs]) => addrs.filter((a) => a.family === 'IPv4').map((a) => ({
    nicName: name,
    nicId: name,
    name,
    ip: a.address,
    ipAddress: a.address,
    mask: a.netmask,
    gateway: '0.0.0.0',
    mac: a.mac,
    macAddress: a.mac,
    status: 1,
    online: 1,
    dhcp: 1,
    isDefault: a.address === (primary && primary.address),
    type: a.internal ? 'loopback' : 'ethernet'
  })));
  return {
    results: list,
    list,
    items: list,
    networkList: list,
    nicList: list,
    total: list.length,
    totalCount: list.length
  };
}

export function buildServerTimezonePayload(timezone) {
  const name = timezone || 'UTC';
  return {
    id: '1',
    timezoneId: '1',
    timeZone: name,
    timezone: name,
    name,
    offset: 0,
    gmt: 'GMT+00:00',
    dstEnable: 0,
    ntpEnable: 0,
    ntpServer: 'pool.ntp.org',
    serverTime: new Date().toISOString(),
    results: [{
      id: '1',
      timeZone: name,
      timezone: name,
      name,
      offset: 0,
      gmt: 'GMT+00:00'
    }]
  };
}

const ZONE_NAMES = [
  ['UTC+14', 'UTC+14:00 Kiritimati'], ['UTC+13', 'UTC+13:00 Samoa'], ['UTC+12', 'UTC+12:00 Auckland'],
  ['UTC+11', 'UTC+11:00 Solomon Islands'], ['UTC+10', 'UTC+10:00 Australian Eastern'],
  ['UTC+9', 'UTC+09:00 Tokyo'], ['UTC+8', 'UTC+08:00 Beijing'], ['UTC+7', 'UTC+07:00 Bangkok'],
  ['UTC+6', 'UTC+06:00 Dhaka'], ['UTC+5', 'UTC+05:00 Karachi'], ['UTC+4', 'UTC+04:00 Dubai'],
  ['UTC+3', 'UTC+03:00 Moscow'], ['UTC+2', 'UTC+02:00 Athens'], ['UTC+1', 'UTC+01:00 Paris'],
  ['UTC+0', 'UTC+00:00 London'], ['UTC-1', 'UTC-01:00 Azores'], ['UTC-2', 'UTC-02:00 Mid-Atlantic'],
  ['UTC-3', 'UTC-03:00 Sao Paulo'], ['UTC-4', 'UTC-04:00 New York'], ['UTC-5', 'UTC-05:00 Chicago'],
  ['UTC-6', 'UTC-06:00 Denver'], ['UTC-7', 'UTC-07:00 Los Angeles'], ['UTC-8', 'UTC-08:00 Anchorage']
];

export function buildTimezoneListPayload() {
  const list = ZONE_NAMES.map(([code, name], i) => ({
    timezoneId: String(i + 1),
    id: String(i + 1),
    code,
    name,
    timezone: name,
    timeZone: name,
    offset: Number(code.split('+')[1] || code.split('-')[1] || 0) * (code.includes('-') ? -1 : 1),
    gmt: code + ':00',
    dstEnable: 0
  }));
  return { results: list, list, items: list, timezoneList: list, total: list.length, totalCount: list.length };
}

export function buildRolePagePayload() {
  const list = [
    { roleId: '1', roleCode: 'admin', roleName: 'Administrator', description: 'Built-in administrator', userCount: 1, status: 1, level: 1, roleLevel: 1, default: 1, editable: 0, deletable: 0, createTime: '2026-01-01 00:00:00' },
    { roleId: '2', roleCode: 'operator', roleName: 'Operator', description: 'Built-in operator', userCount: 0, status: 1, level: 2, roleLevel: 2, default: 0, editable: 1, deletable: 0, createTime: '2026-01-01 00:00:00' }
  ];
  return {
    list, results: list, items: list, roleList: list, total: list.length, totalCount: list.length, pageNo: 1, pageSize: 20,
    pageCount: 1
  };
}

export const DSS_FUNCTIONS_AVAILABLE = [
  { functionId: '1', functionCode: 'realtime', functionName: 'Real-Time Video', moduleCode: '002001', status: 1, type: 'menu' },
  { functionId: '2', functionCode: 'playback', functionName: 'Playback', moduleCode: '002001', status: 1, type: 'menu' },
  { functionId: '3', functionCode: 'emap', functionName: 'E-map', moduleCode: '002002', status: 1, type: 'menu' },
  { functionId: '4', functionCode: 'tvWall', functionName: 'TV Wall', moduleCode: '002013', status: 1, type: 'menu' },
  { functionId: '5', functionCode: 'deepXplore', functionName: 'DeepXplore', moduleCode: '004003', status: 1, type: 'module' },
  { functionId: '6', functionCode: 'maintenance', functionName: 'Maintenance Center', moduleCode: '004004', status: 1, type: 'module' },
  { functionId: '7', functionCode: 'accessCenter', functionName: 'Access Center', moduleCode: '004005', status: 1, type: 'module' },
  { functionId: '8', functionCode: 'intelligenceCenter', functionName: 'Intelligence Center', moduleCode: '004007', status: 1, type: 'module' },
  { functionId: '9', functionCode: 'faceRecognition', functionName: 'Face Recognition', moduleCode: '004008', status: 1, type: 'module' },
  { functionId: '10', functionCode: 'logSearch', functionName: 'Log Search', moduleCode: '010001', status: 1, type: 'menu' },
  { functionId: '11', functionCode: 'recordDownload', functionName: 'Record Download', moduleCode: '010002', status: 1, type: 'menu' },
  { functionId: '12', functionCode: 'p2p', functionName: 'P2P Service', moduleCode: '003005', status: 1, type: 'config' },
  { functionId: '13', functionCode: 'videoTalk', functionName: 'Video Talk', moduleCode: '002006', status: 1, type: 'menu' },
  { functionId: '14', functionCode: 'attendance', functionName: 'Attendance', moduleCode: '002007', status: 1, type: 'menu' },
  { functionId: '15', functionCode: 'visitor', functionName: 'Visitor', moduleCode: '002008', status: 1, type: 'menu' },
  { functionId: '16', functionCode: 'parking', functionName: 'Parking Lot', moduleCode: '002009', status: 1, type: 'menu' }
];

export function buildFunctionAvailablePayload() {
  return { results: DSS_FUNCTIONS_AVAILABLE, list: DSS_FUNCTIONS_AVAILABLE, items: DSS_FUNCTIONS_AVAILABLE, functionList: DSS_FUNCTIONS_AVAILABLE, total: DSS_FUNCTIONS_AVAILABLE.length };
}

export const DSS_SUBSYSTEMS_AVAILABLE = [
  { subsystemId: '1', subsystemCode: 'brms', subsystemName: 'Business Center', prefix: '/brms/api', status: 1, online: 1 },
  { subsystemId: '2', subsystemCode: 'cfg', subsystemName: 'Config Center', prefix: '/cfgs/api', status: 1, online: 1 },
  { subsystemId: '3', subsystemCode: 'video', subsystemName: 'Video Service', prefix: '/videoService', status: 1, online: 1 },
  { subsystemId: '4', subsystemCode: 'obms', subsystemName: 'Access Control Service', prefix: '/obms/api', status: 1, online: 1 },
  { subsystemId: '5', subsystemCode: 'ipms', subsystemName: 'Parking Service', prefix: '/ipms/api', status: 1, online: 1 },
  { subsystemId: '6', subsystemCode: 'emap', subsystemName: 'E-map Service', prefix: '/emap/api', status: 1, online: 1 },
  { subsystemId: '7', subsystemCode: 'omms', subsystemName: 'Alarm Service', prefix: '/omms/api', status: 1, online: 1 },
  { subsystemId: '8', subsystemCode: 'otms', subsystemName: 'Operation Service', prefix: '/otms/api', status: 1, online: 1 },
  { subsystemId: '9', subsystemCode: 'iams', subsystemName: 'Identity Service', prefix: '/iams/api', status: 1, online: 1 },
  { subsystemId: '10', subsystemCode: 'erms', subsystemName: 'Event Service', prefix: '/erms/api', status: 1, online: 1 },
  { subsystemId: '11', subsystemCode: 'ecos', subsystemName: 'Face Service', prefix: '/ecos/api', status: 1, online: 1 },
  { subsystemId: '12', subsystemCode: 'psib', subsystemName: 'Public Service', prefix: '/psib/api', status: 1, online: 1 },
  { subsystemId: '13', subsystemCode: 'ccms', subsystemName: 'Alarm Host Service', prefix: '/alarmhost/v1', status: 1, online: 1 },
  { subsystemId: '14', subsystemCode: 'vehicle', subsystemName: 'Parking/Vehicle Server', prefix: '/vehicleServer', status: 1, online: 1 },
  { subsystemId: '15', subsystemCode: 'sira', subsystemName: 'SIRA Cloud Service', prefix: '/sira/api', status: 1, online: 1 }
];

export function buildSubsystemAvailablePayload() {
  return {
    results: DSS_SUBSYSTEMS_AVAILABLE,
    list: DSS_SUBSYSTEMS_AVAILABLE,
    items: DSS_SUBSYSTEMS_AVAILABLE,
    subsystemList: DSS_SUBSYSTEMS_AVAILABLE,
    subsystemRegisterWarnings: [],
    total: DSS_SUBSYSTEMS_AVAILABLE.length
  };
}

export const OMMS_ALERT_TYPES = [
  { alertType: '1', alertTypeName: 'Video Loss', alertName: 'Video Loss', category: 'video', level: 2, enable: 1 },
  { alertType: '2', alertTypeName: 'Motion Detection', alertName: 'Motion Detection', category: 'video', level: 1, enable: 1 },
  { alertType: '3', alertTypeName: 'Tamper Detection', alertName: 'Tamper Detection', category: 'video', level: 1, enable: 1 },
  { alertType: '4', alertTypeName: 'Disk Full', alertName: 'Disk Full', category: 'device', level: 1, enable: 1 },
  { alertType: '5', alertTypeName: 'Disk Error', alertName: 'Disk Error', category: 'device', level: 2, enable: 1 },
  { alertType: '6', alertTypeName: 'Device Offline', alertName: 'Device Offline', category: 'device', level: 2, enable: 1 },
  { alertType: '7', alertTypeName: 'Alarm In', alertName: 'Alarm In', category: 'device', level: 1, enable: 1 },
  { alertType: '8', alertTypeName: 'Face Detection', alertName: 'Face Detection', category: 'ai', level: 1, enable: 1 },
  { alertType: '9', alertTypeName: 'Perimeter Line', alertName: 'Perimeter Line', category: 'ai', level: 1, enable: 1 },
  { alertType: '10', alertTypeName: 'Intrusion', alertName: 'Intrusion', category: 'ai', level: 1, enable: 1 },
  { alertType: '11', alertTypeName: 'Loiter Detection', alertName: 'Loiter Detection', category: 'ai', level: 1, enable: 1 },
  { alertType: '12', alertTypeName: 'Person Gather', alertName: 'Person Gather', category: 'ai', level: 1, enable: 1 },
  { alertType: '13', alertTypeName: 'ANPR', alertName: 'ANPR', category: 'ai', level: 1, enable: 1 },
  { alertType: '14', alertTypeName: 'Fire Detection', alertName: 'Fire Detection', category: 'ai', level: 2, enable: 1 },
  { alertType: '15', alertTypeName: 'Temperature Alarm', alertName: 'Temperature Alarm', category: 'ai', level: 2, enable: 1 }
];

// ===== E-096: USER MANAGEMENT + ROLE MANAGEMENT (native client path) =========
//
// The DSS Client User Management view is NATIVE: UserLogical.dll ->
// DPSDK_GetUserManagerUsers -> GET /brms/api/v1.1/user/page (CRestLogical::
// GetUserManagerUsers, DPSDK.dll @0xc9cf50). The SPA "userGroupView"
// (index-BQObycDy.js @29711) reads data.pageData rows as {value:e.id,label:
// e.username}. Native REST surface extracted from the DPSDK string pool
// (@0xc9cfe0-0xc9d898):
//   GetUserManagerUsers  -> v1.1/user/page        (query: username=,online=,
//                                                  groupId=,pageSize=20,
//                                                  roleIds=,page=1,userType=)
//   GetUser              -> v1.1/user/:id
//   GetUserDetailInfo    -> Rights/User detail
//   AddUser              -> POST v1.1/user
//   SaveUser             -> v1.1/user/:id         (save/modify)
//   LockUser/UnLockUser  -> v1.1/user/:id/lock|unlock
//   DeleteUser           -> pUserIdList (DELETE/POST /user + /user/delete)
//   GetUserEmailsByPage  -> v1.1/user/email/page
//   AssociateUserEmails  -> v1.1/user/email/associate/list?keyword=
//   GetGroupUsers        -> v1.1/user/group-by-role-level/list
//   GetUserManagerRoles  -> v1.1/role/page  GetRole->v1.1/role/:id
//   AddRole/UpdateRole/DeleteRole -> v1.1/role...  pRoleIdList
// E-095 lesson (EVIDENCE device-JBrSmGvP.js DEVICE_STATUS.ONLINE==="1"): every
// boolean/enum field is served as a STRING ("1"/"0") - the client compares with
// strict ===. The native parser ignores unknown keys (RE-SCHEMA-DPSDK), so rows
// are a superset: username/loginName/realName/id/userId all covered.
//
// The user store is intentionally minimal but REAL: admin (lock=0, online
// follows the login session) + operator. Deleting admin is rejected server-side.

export const USER_STORE = [
  {
    id: '1', userId: '1', userUuid: '1',
    username: 'admin', loginName: 'admin', userName: 'admin',
    realName: 'Administrator', employeeName: 'Administrator',
    userType: '1', userTypeName: 'Administrator', adminFlag: '1', isAdmin: '1',
    status: '1', statusName: 'Normal', online: '1', enable: '1', locked: '0', lock: '0',
    roleIds: ['1'], roleId: '1', roleNames: ['Super Administrator'], roleName: 'Super Administrator',
    groupId: '1', groupName: 'Default', userGroupName: 'Default',
    orgCode: '001', domainId: '0',
    email: 'admin@vigilab.local', telephone: '', mobile: '',
    passwordExpired: '0', passwordModifyTime: '2026-01-01 00:00:00',
    createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00',
    remarks: 'Built-in administrator', remark: 'Built-in administrator', deletable: '0'
  },
  {
    id: '2', userId: '2', userUuid: '2',
    username: 'operator', loginName: 'operator', userName: 'operator',
    realName: 'Operator', employeeName: 'Operator',
    userType: '0', userTypeName: 'Normal', adminFlag: '0', isAdmin: '0',
    status: '1', statusName: 'Normal', online: '0', enable: '1', locked: '0', lock: '0',
    roleIds: ['2'], roleId: '2', roleNames: ['Operator'], roleName: 'Operator',
    groupId: '1', groupName: 'Default', userGroupName: 'Default',
    orgCode: '001', domainId: '0',
    email: '', telephone: '', mobile: '',
    passwordExpired: '0', passwordModifyTime: '2026-01-01 00:00:00',
    createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00',
    remarks: '', remark: '', deletable: '1'
  }
];

export const USER_GROUP_STORE = [
  {
    id: '1', groupId: '1', groupName: 'Default', name: 'Default',
    parentId: '0', parentCode: '0', description: 'Default user group',
    remark: 'Default user group', userCount: String(USER_STORE.length),
    sort: 1, modifyTime: '2026-01-01 00:00:00'
  }
];

export function buildUserPagePayload(query = {}) {
  const q = (key) => String(query[key] ?? '').trim();
  const username = q('username').toLowerCase();
  const online = q('online');
  const groupId = q('groupId');
  const roleIds = q('roleIds');
  const userType = q('userType');
  const page = Math.max(1, Number(q('page') || q('pageNo') || 1) || 1);
  const pageSize = Math.max(1, Number(q('pageSize') || 20) || 20);
  let rows = USER_STORE.filter((u) => {
    if (username && !u.username.toLowerCase().includes(username)) return false;
    if (online !== '' && u.online !== online) return false;
    if (groupId && u.groupId !== groupId) return false;
    if (roleIds && !u.roleIds.includes(roleIds)) return false;
    if (userType && u.userType !== userType) return false;
    return true;
  });
  const totalCount = rows.length;
  const start = (page - 1) * pageSize;
  const pageData = rows.slice(start, start + pageSize);
  return {
    pageData, list: pageData, results: pageData, items: pageData, userList: pageData,
    totalCount, total: totalCount, pageNo: String(page), page: String(page),
    pageSize: String(pageSize), pageCount: String(Math.max(1, Math.ceil(totalCount / pageSize)))
  };
}

export function buildUserDetailPayload(userId) {
  const row = USER_STORE.find((u) => String(userId) === u.id || String(userId) === u.userId);
  return row ? { ...row } : null;
}

export function buildUserGroupListPayload(query = {}) {
  const kw = String(query?.keyword ?? '').trim().toLowerCase();
  const list = USER_GROUP_STORE.filter((g) => !kw || g.groupName.toLowerCase().includes(kw));
  return {
    list, results: list, items: list, userGroupList: list, groupList: list,
    total: list.length, totalCount: list.length
  };
}

export function buildLdapConfigPayload() {
  return {
    enable: '0', enableLdap: '0', status: '0',
    ip: '', address: '', port: '', baseDn: '', baseDN: '',
    userName: '', password: '', useSsl: '0', useSSL: '0', encryptType: '0',
    usernameAttribute: 'uid', remark: ''
  };
}

export function buildUserEmailListPayload(query = {}) {
  const kw = String(query?.keyword ?? '').trim().toLowerCase();
  const hits = USER_STORE.filter((u) => u.email && (!kw || u.email.toLowerCase().includes(kw) || u.username.toLowerCase().includes(kw)));
  const list = hits.map((u) => ({ id: u.id, userId: u.id, username: u.username, email: u.email }));
  return { list, results: list, items: list, emailList: list, total: list.length, totalCount: list.length };
}

// ===== E-098: CASCADE PERMISSIONS + per-org camera allocation ===============
//
// DPSDK contract (string pool, confirmed):
//   GetResourceRoles       -> GET/POST v1.1/authority/resource/{id}/role/list
//                             (fragments "v1.1/authority/resource/" @0xc9c238
//                              + "/role/list"; pResultRoleList out param)
//   SetResourceRoles       -> PUT/POST  v1.1/authority/resource/{id}/role
//                             (DPSDK_SetResourceRoles, UserLogical
//                              HandleSetResourceRoleIdList @0xc4ec8)
//   ResourceAllocateGetOrgDevices -> v1.1/resource-allocate/organization/
//                             device/fetch/list (pOrgDevList @0xca5bd0)
// The permission dialog binds the role rows with checked flags; the admin
// role (roleId 1) is granted on every resource (cascade), the operator role is
// only granted on VIGILAB resources. Parser ignores unknown keys
// (RE-SCHEMA-DPSDK) so rows are a superset of checked/permission/operate.
export function buildAuthorityResourceRolesPayload(resourceId, body = {}) {
  const rid = String(resourceId ?? '').trim();
  const isOrgResource = rid === '' || rid === '001' || rid === 'VIGILAB';
  const roles = buildRolePagePayload().list || [];
  const list = roles.map((r) => {
    // cascade: admin (roleId 1) is granted everywhere; operator only on VIGILAB
    const checked = String(r.roleId) === '1' || (isOrgResource && String(r.roleId) === '2');
    return {
      roleId: String(r.roleId), roleCode: r.roleCode, roleName: r.roleName,
      checked: checked ? '1' : '0',
      permission: checked ? '1' : '0',
      operate: checked ? '1' : '0',
      resourceId: rid, inputChecked: checked ? 1 : 0,
      status: r.status, level: r.level, roleLevel: r.roleLevel,
      userCount: r.userCount, editable: r.editable, deletable: r.deletable,
      default: r.default, createTime: r.createTime
    };
  });
  return {
    list, results: list, items: list, roleList: list, roles: list,
    total: list.length, totalCount: list.length, resourceId: rid
  };
}

export function buildResourceAllocateOrgDevicesPayload(body = {}) {
  const q = (key) => String(body?.[key] ?? '').trim();
  const orgCode = q('orgCode') || '';
  const keywords = q('keyword').toLowerCase();
  const devs = [...DEVICE_REGISTRY.values()].filter((d) => {
    // root org (001) sees everything (the client queries it with containChild);
    // any other org only returns devices under it.
    if (orgCode && orgCode !== '001' && deviceOrgCodeOf(d) !== orgCode) return false;
    if (keywords && !String(d.deviceName || '').toLowerCase().includes(keywords)
      && !String(d.deviceCode || '').toLowerCase().includes(keywords)) return false;
    return true;
  });
  const list = devs.map((d) => {
    const channels = allChannels().filter((c) => c.deviceCode === d.deviceCode);
    return {
      deviceId: d.deviceId || d.deviceCode, deviceCode: d.deviceCode,
      deviceName: d.deviceName, deviceIp: d.deviceIp, devicePort: d.devicePort,
      deviceType: d.deviceType || '1', deviceCategory: d.deviceCategory || '1',
      orgCode: deviceOrgCodeOf(d), status: deviceOnlineOf(d) ? '1' : '0',
      online: deviceOnlineOf(d) ? '1' : '0',
      channels: channels.map((c) => ({
        channelId: c.channelId || c.channelCode, channelCode: c.channelCode,
        channelName: c.channelName || d.deviceName, channelSeq: c.channelSeq ?? 0,
        deviceCode: d.deviceCode, orgCode: deviceOrgCodeOf(d), status: '1'
      }))
    };
  });
  return {
    list, results: list, items: list, deviceList: list, orgDeviceList: list,
    total: list.length, totalCount: list.length
  };
}

function deviceOrgCodeOf(d) {
  return d.orgCode || d.orgName || 'VIGILAB';
}


export function buildAlertTypeListPayload() {
  return {
    results: OMMS_ALERT_TYPES,
    list: OMMS_ALERT_TYPES,
    items: OMMS_ALERT_TYPES,
    alertTypeList: OMMS_ALERT_TYPES,
    dictionaryList: OMMS_ALERT_TYPES,
    total: OMMS_ALERT_TYPES.length
  };
}

// ---------------------------------------------------------------------------
// 7) Auto-register (ARS): native devices registered on TCP 9500 become real
//    devices in the tree/page/statistics responses.
// ---------------------------------------------------------------------------
export function registerArsDevice(deviceInfo) {
  const input = normalizeDeviceInput({
    deviceIp: deviceInfo.ip,
    devicePort: deviceInfo.port || 37777,
    protocolType: '1',
    deviceCategory: '1',
    deviceType: String(deviceInfo.deviceType || '2'),
    deviceName: deviceInfo.deviceName || `Auto-Reg ${deviceInfo.deviceId}`,
    serverCode: 'video#local',
    channelCount: deviceInfo.channelCount || 1,
    manufacturer: 'Dahua',
    deviceCode: 'ARS-' + String(deviceInfo.deviceId || '')
  });
  const record = createDeviceRecord(input, { source: 'auto-register' });
  return record;
}

export function buildArsListPayload() {
  const list = [...DEVICE_REGISTRY.values()].filter((d) => d.source === 'auto-register').map((d) => ({
    deviceId: d.deviceCode,
    deviceCode: d.deviceCode,
    deviceName: d.deviceName,
    ip: d.deviceIp,
    port: d.devicePort,
    deviceType: d.deviceType,
    channelNum: d.channelNum,
    status: d.online,
    protocol: d.protocolName,
    source: d.source
  }));
  return { devices: list, results: list, list, total: list.length };
}

// ---------------------------------------------------------------------------
// 8) P2P status (real Easy4IP endpoints from DPSDK.dll)
// ---------------------------------------------------------------------------
export function buildP2PStatusPayload() {
  return {
    status: 'P2P/Easy4IP not enabled on this self-built server',
    p2pEnable: 0,
    easy4ipEnable: 0,
    servers: [
      { name: 'www.easy4ip.com', protocol: 'http', soapPath: '/webservice/GetDeviceInterface?wsdl' },
      { name: 'www.easy4ipcloud.com', protocol: 'https', soapPath: '/webservice/GetDeviceInterface?wsdl' },
      { name: 'www.dahuap2p.com', protocol: 'http', soapPath: '/webservice/GetDeviceInterface?wsdl' },
      { name: 'www.dahuap2pcloud.com', protocol: 'https', soapPath: '/webservice/GetDeviceInterface?wsdl' },
      { name: 'p2p.myeasyip.com', protocol: 'http', soapPath: '/webservice/GetDeviceInterface?wsdl' }
    ],
    registered: 0,
    message: 'P2P/auto-register only from a device serial (devSequence) via Easy4IP SOAP; outbound cloud not registered by this build.'
  };
}

// ---------------------------------------------------------------------------
// 9) Seed device: RETIRED in E-028.
//    The seeded mock ("Test Camera" @127.0.0.1:37777, manufacturer "Dahua",
//    model "MockIPC") was an invented device identity, the same class of
//    fabrication E-026 removed for the ONVIF fallback. The registry now only
//    contains devices the operator really added, with the identity reported
//    by the device itself.
// ---------------------------------------------------------------------------
