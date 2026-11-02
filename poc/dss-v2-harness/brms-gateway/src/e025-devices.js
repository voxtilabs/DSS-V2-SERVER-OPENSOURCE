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
import { dirname } from 'node:path';

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
    orgCode: String(body.orgCode ?? '001'),
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
    source: identity.source || 'manual'
  };
  DEVICE_REGISTRY.set(code, record);
  return record;
}

export function findDeviceByIpPort(ip, port) {
  for (const d of DEVICE_REGISTRY.values()) {
    if (d.deviceIp === ip && Number(d.devicePort) === Number(port)) return d;
  }
  return null;
}

function channelVo(device, no) {
  return {
    channelId: `${device.deviceCode}$${no}$0$0`,
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
    status: 1,
    online: 1,
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
  DEVICE_REGISTRY.set(device.deviceCode, { ...device, ...identity, deviceIp: input.deviceIp || device.deviceIp });
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

export function buildDevicePagePayload(query = {}) {
  const page = Math.max(1, Number(query.pageNo ?? query.page ?? 1) || 1);
  const size = Math.max(1, Number(query.pageSize ?? query.page) || 20);
  const keyword = String(query.keyword ?? '').trim();
  let list = [...DEVICE_REGISTRY.values()];
  if (keyword) list = list.filter((d) => d.deviceName.includes(keyword) || d.deviceIp.includes(keyword));
  const start = (page - 1) * size;
  const slice = list.slice(start, start + size);
  return {
    list: slice,
    results: slice,
    deviceList: slice,
    items: slice,
    pageNo: page,
    pageSize: size,
    total: list.length,
    totalCount: list.length,
    pageCount: Math.max(1, Math.ceil(list.length / size)),
    onlineCount: list.filter((d) => d.online).length
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
    deviceIp: d.deviceIp,
    devicePort: String(d.devicePort ?? ''),
    protocolType: d.protocolType,
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
    deviceIp: d.deviceIp,
    devicePort: String(d.devicePort ?? ''),
    protocolType: d.protocolType,
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

export function buildDiscoverJoinBatchPayload(body = {}) {
  const items = Array.isArray(body.devices) ? body.devices
    : Array.isArray(body.list) ? body.list
      : Array.isArray(body.items) ? body.items : [body];
  const created = [];
  for (const raw of items) {
    if (!raw || typeof raw !== 'object') continue;
    const input = normalizeDeviceInput(raw);
    if (!input.deviceIp) continue;
    const identity = { source: 'discovery', manufacturer: raw.manufacturer, model: raw.model, firmwareVersion: raw.firmwareVersion, serialNumber: raw.serialNumber };
    const device = findDeviceByIpPort(input.deviceIp, input.devicePort) || createDeviceRecord(input, identity);
    created.push(device);
  }
  return {
    results: created,
    list: created,
    deviceList: created,
    items: created,
    total: created.length,
    success: true,
    failList: []
  };
}

export function buildDeviceAddBatchPayload(body = {}) {
  return buildDiscoverJoinBatchPayload(body);
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
  for (const code of codes) { if (DEVICE_REGISTRY.delete(String(code))) removed += 1; }
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
  for (const d of DEVICE_REGISTRY.values()) {
    const key = String(d.deviceCategory || '1');
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const list = catalog.map((g) => ({
    deviceCategory: g.deviceCategory,
    deviceCategoryName: g.deviceCategoryName,
    deviceCount: counts.get(String(g.deviceCategory)) || 0,
    onlineCount: counts.get(String(g.deviceCategory)) || 0,
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
