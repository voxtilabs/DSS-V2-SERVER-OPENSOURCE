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
import { DEFAULT_ORG_CODE, deviceOrgCode, orgName, getOrg, listOrgs } from './e041-orgs.js';

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
// E-185: las credenciales del equipo NO pueden vivir en devices.json (se
// borran ahi por diseno), pero tampoco pueden perderse: sin ellas el server no
// puede loguearse al DVR despues de un reinicio. Archivo separado, 0600.
export const DEVICE_CRED_STORE_PATH = path.join(__dirname, '..', 'data', 'device-credentials.json');

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
        // E-191: 'ARS-' era un prefijo interno y el cliente lo mostraba como
        // Device ID (ARS-202611122200). El DSS real muestra el Register ID
        // pelado, que es el valor escrito en el equipo: se migra al cargar.
        if (rec && String(rec.source || '') === 'auto-register') {
          // El prefijo pudo quedar en el codigo, en el id o en ambos segun la
          // version que escribio la fila: se limpia en los tres.
          for (const k of ['deviceCode', 'deviceId', 'id']) {
            if (typeof rec[k] === 'string' && rec[k].startsWith('ARS-')) rec[k] = rec[k].slice(4);
          }
        }
        DEVICE_REGISTRY.set(rec.deviceCode, rec);
      }
      if (arr.length) deviceSeq = arr.length;
      console.log(`[E026-STORE] Loaded ${arr.length} devices from ${DEVICE_STORE_PATH}`);
      loadDeviceCredentials();
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
    saveDeviceCredentials();
  } catch (err) {
    console.error('[E026-STORE] Failed to persist devices:', err.message);
  }
}

export function saveDeviceCredentials() {
  try {
    ensureDataDir();
    const creds = {};
    for (const d of DEVICE_REGISTRY.values()) {
      if (!d || !d.deviceCode) continue;
      if (d.username || d.password) {
        creds[d.deviceCode] = { username: String(d.username || ''), password: String(d.password || '') };
      }
    }
    fs.writeFileSync(DEVICE_CRED_STORE_PATH, JSON.stringify(creds, null, 2), { mode: 0o600 });
    try { fs.chmodSync(DEVICE_CRED_STORE_PATH, 0o600); } catch { /* plataforma sin chmod */ }
  } catch (err) {
    console.error('[E-185][CREDS] persist failed:', err.message);
  }
}

export function loadDeviceCredentials() {
  try {
    const raw = fs.readFileSync(DEVICE_CRED_STORE_PATH, 'utf8');
    const creds = JSON.parse(raw);
    let n = 0;
    for (const [code, c] of Object.entries(creds || {})) {
      // E-191: acepta la clave con y sin el viejo prefijo ARS-.
      const rec = DEVICE_REGISTRY.get(code)
        || DEVICE_REGISTRY.get(code.replace(/^ARS-/, ''))
        || DEVICE_REGISTRY.get('ARS-' + code);
      if (!rec) continue;
      if (c && c.username) rec.username = c.username;
      if (c && c.password) rec.password = c.password;
      n++;
    }
    if (n) console.log(`[E-185][CREDS] restored ${n} device credential(s)`);
  } catch { /* sin credenciales guardadas todavia */ }
}

// E-191: resolucion tolerante del codigo de un equipo auto-registrado, para que
// las filas viejas (codigo con prefijo ARS-) y las nuevas (Register ID pelado)
// se encuentren sin importar cual de las dos formas llegue.
export function findDeviceByRegisterId(id) {
  const key = String(id || '').trim();
  if (!key) return null;
  return DEVICE_REGISTRY.get(key)
    || DEVICE_REGISTRY.get('ARS-' + key)
    || DEVICE_REGISTRY.get(key.replace(/^ARS-/, ''))
    || null;
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

  // E-144: a loopback deviceIp can never carry a real camera stream. Some
  // registration funnels (LAN-scan join / P2P fallback) materialized records
  // with deviceIp=127.0.0.1 (observed: "EBA1" D7001SHX9002 @127.0.0.1:1) and
  // the 60 s provisioning loop then configured a dahua-convention pull to
  // 127.0.0.1:554 forever (MediaMTX: "connection refused", path notReady ->
  // client "RTSP SETUP timed out"). Reject the bogus source instead of
  // configuring a pull that can never work, and vacate the dead path so the
  // client gets an immediate 400 instead of a hanging SETUP.
  const isLoopback = (h) => /^(127\.|localhost$|::1$|0\.0\.0\.0$)/.test(String(h).toLowerCase());
  const uriHost = (() => { try { return new URL(rtspUri).hostname; } catch { return ''; } })();
  // E-144: provisioning runs in a setImmediate closure; the device may have
  // been deleted meanwhile (delete/batch removes it from the registry while
  // the background ensureDeviceStream still holds the old object). Never
  // resurrect a deleted device: persist only when the registry still owns it.
  if (DEVICE_REGISTRY.get(device.deviceCode) !== device) {
    console.log('[E034-STREAM] skip provisioning for removed device', String(device.deviceCode));
    return device;
  }
  if (isLoopback(ip) || isLoopback(uriHost)) {
    const pathName = device.mediamtxPath || mediaMtxPathForDevice(device);
    device.rtspUri = '';
    device.streamSource = 'rejected-loopback';
    device.streamConfigured = false;
    persistDevice(device);
    setImmediate(() => { removeMediaMTXPath(pathName); });
    console.log('[E034-STREAM] REJECT bogus loopback source', JSON.stringify({
      deviceCode: device.deviceCode, deviceIp: ip, devicePort: port
    }));
    return device;
  }

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
    success: true,
    // E-142 (rea-flows-v3 §5): native BRMS.Device.AddDevice response also walks
    // failedDevices:[{errorMsg,deviceIp}] — keep it as a real empty array.
    failedDevices: []
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

// E-174: real payload for the client's "Add Type: Auto Register" list. Every
// device that reached us over TCP 9500 and has not been authorized yet is
// exposed here (research/E-162 §2.5, §4-P0.3). All fields are STRINGS: the
// C++/Qt matchers compare with === against string constants.
export function buildDeviceUnauthorizedPagePayload() {
  const rows = [...DEVICE_REGISTRY.values()]
    .filter((d) => d.source === 'auto-register' && String(d.authorized) !== '1')
    .map((d) => ({
      id: String(d.deviceCode),
      deviceCode: String(d.deviceCode),
      deviceId: String(d.deviceCode),
      deviceName: String(d.deviceName || ''),
      deviceIp: String(d.deviceIp || ''),
      devicePort: String(d.devicePort || ''),
      protocolType: String(d.protocolType || '1'),
      protocolName: String(d.protocolName || 'Dahua'),
      deviceType: String(d.deviceType || '2'),
      deviceCategory: String(d.deviceCategory || '1'),
      manufacturer: String(d.manufacturer || 'Dahua'),
      model: String(d.model || ''),
      serialNumber: String(d.serialNumber || d.deviceCode || ''),
      channelNum: String(d.channelNum || '1'),
      online: String(d.online ?? '1'),
      status: String(d.status ?? '1'),
      onlineStatus: String(d.onlineStatus ?? '1'),
      initStatus: '1',
      addType: 'auto-register',
      source: 'auto-register',
      authorized: '0',
      registerFromIp: String(d.registerFromIp || d.deviceIp || ''),
      lastSeenAt: String(d.lastSeenAt || d.updatedAt || Date.now()),
      orgCode: String(d.orgCode || '001')
    }));
  return {
    pageNo: '1',
    pageSize: '20',
    totalCount: String(rows.length),
    total: String(rows.length),
    totalCountStr: String(rows.length),
    pageData: rows,
    results: rows,
    list: rows,
    items: rows,
    success: true
  };
}

export function authorizeArsDevices(codes = []) {
  const authorized = [];
  for (const code of codes) {
    const key = String(code);
    const rec = DEVICE_REGISTRY.get(key) || DEVICE_REGISTRY.get(key.replace(/^ARS-/, 'ARS-'));
    if (!rec) continue;
    rec.authorized = '1';
    rec.authorizedAt = Date.now();
    authorized.push(rec);
  }
  if (authorized.length) saveDevicesToDisk();
  return authorized;
}

export function listArsSessions(rows = []) { return rows; }

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

// E-144: notify hook injected by index.js (this data module must not import
// the MQ hub directly); falls back to a no-op so unit tests stay quiet.
let DEVICE_NOTIFIER = { deviceEvent: () => {} };
export function setDeviceNotifier(n) { DEVICE_NOTIFIER = n || { deviceEvent: () => {} }; }
export function getDeviceNotifier() { return DEVICE_NOTIFIER; }
export function buildDevicePasswordChangeBatchPayload() { return { success: true, results: [], list: [], failList: [] }; }
export function buildDeviceTimezoneUpdateBatchPayload() { return { success: true, results: [], list: [], failList: [] }; }

// E-144: device modify (Device Management edit). Accepts the common DSS
// shapes: { deviceCodes:[code], device:{...fields} } and
// { list:[{ deviceCode, ...fields }] }. Editable fields: deviceName,
// deviceIp, devicePort, userName, loginPass/password, protocolType,
// deviceCategory, deviceType, orgCode, serverCode. When the stream-relevant
// identity (deviceIp / devicePort / userName / credentials) changes, the
// cached RTSP source is invalidated so ensureDeviceStream re-discovers the
// real stream (ONVIF or Dahua convention) and re-provisions the MediaMTX
// path inside the RUNNING process (an external store edit is overwritten by
// the 60 s provisioning loop - observed 2026-11-12 on D7001SHX9002).
export function buildDeviceModifyBatchPayload(body = {}) {
  const rows = [];
  if (Array.isArray(body.list) && body.list.length) {
    for (const row of body.list) {
      if (row && (row.deviceCode || row.deviceId)) rows.push({ ...row, deviceCode: String(row.deviceCode || row.deviceId) });
    }
  } else {
    const dev = body.device || body;
    const code = String(dev.deviceCode || dev.deviceId || (Array.isArray(body.deviceCodes) ? body.deviceCodes[0] : '') || '');
    if (code) rows.push({ ...dev, deviceCode: code });
  }

  const results = [];
  let modified = 0;
  for (const row of rows) {
    const device = DEVICE_REGISTRY.get(row.deviceCode);
    if (!device) {
      results.push({ deviceCode: row.deviceCode, success: false, errorCode: 1001, errorMsg: 'Device not found' });
      continue;
    }
    const STREAM_ID_FIELDS = ['deviceIp', 'devicePort', 'userName', 'loginPass', 'password'];
    let streamDirty = false;
    for (const f of ['deviceName', 'deviceIp', 'devicePort', 'userName', 'loginPass', 'password', 'protocolType', 'deviceCategory', 'deviceType', 'orgCode', 'serverCode']) {
      if (row[f] !== undefined && row[f] !== null && row[f] !== '') {
        if (device[f] !== row[f]) {
          device[f] = row[f];
          if (STREAM_ID_FIELDS.includes(f)) streamDirty = true;
        }
      }
    }
    if (row.devicePort !== undefined) {
      const p = Number(row.devicePort);
      if (Number.isFinite(p) && p > 0) device.devicePort = p;
    }
    if (streamDirty) {
      // force re-discovery of the stream source on the next provisioning tick
      device.rtspUri = '';
      device.streamSource = '';
      device.streamConfigured = false;
    }
    persistDevice(device);
    modified += 1;
    results.push({ deviceCode: device.deviceCode, success: true });
    setImmediate(async () => {
      try {
        const fresh = DEVICE_REGISTRY.get(device.deviceCode) || device;
        await ensureDeviceStream(fresh);
        DEVICE_NOTIFIER.deviceEvent('DEVICE_STATUS', fresh);
      } catch (err) {
        console.log('[E025-MODIFY] stream re-provision failed:', err.message);
      }
    });
  }
  return { success: true, modified, results, list: results, total: modified, failList: results.filter((r) => !r.success) };
}

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

// E-099: E-095 lesson applied to ROLES. Live evidence 2026-11-06 21:12 UTC:
// the User Config dialog requested role/list (200) and the client crashed
// before issuing user/page - the previous payload served status/level/
// default/editable/deletable/userCount as NUMBERS and the client compares
// flags with strict === against STRING "1"/"0". Every boolean/enum flag is
// now a STRING plus statusName; rows are a superset (parser ignores unknown
// keys, RE-SCHEMA-DPSDK).
export function buildRolePagePayload() {
  // E-102 native contract (DPSDK.dll FUN_1806c6280, role/page pageData[]):
  // items bind allowEdit/id/roleType/roleName/memo - ALL strings (tipo 2).
  // E-122: the Administrator role carries the FULL grant automatically -
  // every registered deviceCode, every channelId, the whole menu/function
  // catalog and every org - so the Role Details dialog opens with all
  // Device Permissions pre-checked and the camera is clickable/selected.
  const allDevices = [...DEVICE_REGISTRY.values()];
  const allDeviceCodes = allDevices.map((d) => d.deviceCode);
  const allChannelIds = allChannels().map((c) => c.channelId || c.channelCode);
  const allOrgCodes = listOrgsSafe().map((o) => o.code);
  // menuCatalogForRole lives in e037 (which imports this module) - resolved at
  // call time via dynamic binding, never at module-eval time.
  const allMenuCodes = safeMenuCodes();
  const allFunctionCodes = DSS_FUNCTIONS_AVAILABLE.map((f) => f.functionCode);
  const list = [
    { roleId: '1', id: '1', roleCode: 'admin', roleName: 'Administrator', description: 'Built-in administrator',
      memo: 'Built-in administrator', roleType: '1', allowEdit: '0',
      userCount: '1', status: '1', statusName: 'Enable', level: '1', roleLevel: '1',
      default: '1', editable: '0', deletable: '0', checked: '1', permission: '1', operate: '1',
      hasAuthority: '1', orgCode: '001', createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00',
      // E-122: automatic full grant
      deviceCodes: allDeviceCodes, channelIds: allChannelIds, orgCodes: allOrgCodes,
      menuCodes: allMenuCodes, functionCodes: allFunctionCodes,
      deviceList: allDeviceCodes, channelList: allChannelIds },
    { roleId: '2', id: '2', roleCode: 'operator', roleName: 'Operator', description: 'Built-in operator',
      memo: 'Built-in operator', roleType: '2', allowEdit: '1',
      userCount: '1', status: '1', statusName: 'Enable', level: '2', roleLevel: '2',
      default: '0', editable: '1', deletable: '1', checked: '1', permission: '1', operate: '1',
      hasAuthority: '1', orgCode: 'VIGILAB', createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00',
      deviceCodes: allDeviceCodes, channelIds: allChannelIds, orgCodes: ['VIGILAB'],
      menuCodes: allMenuCodes, functionCodes: allFunctionCodes }
  ];
  return {
    list, results: list, items: list, roleList: list, roles: list, pageData: list, // E-103: pageData alias (native contract)
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '20', pageCount: '1'
  };
}

// late-bound helpers (avoid circular imports at module load)
function listOrgsSafe() { try { return listOrgs(); } catch { return [{ code: '001' }, { code: 'VIGILAB' }]; } }
function safeMenuCodes() {
  // e037-native-tree.js imports this module, so we cannot import it at
  // top-level safely; the full catalog codes are static (E-035/E-037 RE),
  // listed here to keep buildRolePagePayload dependency-free.
  return ['001', '002', '003', '004', '010', '002001', '002002', '002005004', '002013', '004001', '004003', '004004', '004005', '004007', '004008', '010001', '010002', '003005', '002006', '002007', '002008', '002009', '004004004'];
}

// E-099 helper: stringify every numeric value of a row (enum/boolean flags
// must be STRING per the E-095 strict-=== lesson). Applied to the function /
// subsystem / alert-type catalogs that the User Config dialog also parses.
export function strEnum(row) {
  const o = {};
  for (const [k, v] of Object.entries(row)) o[k] = typeof v === 'number' ? String(v) : v;
  return o;
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
  const rows = DSS_FUNCTIONS_AVAILABLE.map(strEnum); // E-099: flags as strings
  return { results: rows, list: rows, items: rows, functionList: rows, total: String(rows.length), totalCount: String(rows.length) };
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
  const rows = DSS_SUBSYSTEMS_AVAILABLE.map(strEnum); // E-099: flags as strings
  return {
    results: rows,
    list: rows,
    items: rows,
    subsystemList: rows,
    subsystemRegisterWarnings: [],
    total: String(rows.length),
    totalCount: String(rows.length)
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
    roleIds: ['1'], roleId: '1', roleNames: ['Administrator'], roleName: 'Administrator',
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
    remark: 'Default user group', memo: 'Default user group', // E-112: client reads "memo" (GetUserGroupList error[-1] without it)
    userCount: String(USER_STORE.length),
    sort: '1', roleId: '1', level: '1', roleLevel: '1', status: '1', // E-099: strings
    modifyTime: '2026-01-01 00:00:00'
  }
];

// E-105: EXACT native contract of GET /brms/api/v1.1/user/page.
// Evidence (DPSDK.dll, response descriptor FUN_1806c8d20 / DAT_180f77d50):
//   data.pageData[] -> { username, online, name, enableMPT, id, status,
//                        userType, roles:[ {roleName, roleId} ] }
//   data.totalCount  -> STRING, consumed with atoi() by
//                        DPSDK::CRestLogical::GetUserManagerUsers (FUN_1802a01c0)
// Every leaf of the row descriptor has native kind=2 (STRING); the ONLY
// arrays allowed in the whole payload are data.pageData and
// data.pageData[].roles. A JSON array used as a leaf value (the E-100 payload
// served roleIds:["1"] / roleNames:["Super Administrator"]) is the prime
// AppHangB1 suspect: the native matcher does a STRICT type check and a
// mismatching node leaves the field NULL/0, so the logical row the UI
// renders is structurally incomplete (roles empty, name empty).
// The SPA consumer (index-BQObycDy.js, userGroupView) only reads
// data.pageData[].id and data.pageData[].username, both native keys, so the
// strict payload does not break the web UI.
function serializeUserPageRow(u) {
  const ids = Array.isArray(u.roleIds) ? u.roleIds : (u.roleId != null ? [u.roleId] : []);
  const names = Array.isArray(u.roleNames) ? u.roleNames : (u.roleName != null ? [u.roleName] : []);
  return {
    id: String(u.id ?? ''),
    username: String(u.username ?? ''),
    name: String(u.realName || u.employeeName || u.username || ''), // native draws "name"
    online: String(u.online ?? '0'),
    enableMPT: String(u.enableMPT ?? '0'),
    status: String(u.status ?? '1'),
    userType: String(u.userType ?? '0'),
    roles: ids.map((rid, i) => ({
      roleId: String(rid),
      roleName: String(names[i] ?? u.roleName ?? '')
    }))
  };
}

// E-101/E-105: the user DETAIL endpoint (v1.1/user/:id) has its own native
// descriptor (0xd00-byte native row, DPSDK_GetUser) and is also consumed by
// the SPA, so it keeps a superset - but NO JSON array leaf values: role id /
// role name lists are CSV STRINGS ("1,2") as real Dahua REST does.
function serializeUserRow(u) {
  const base = serializeUserPageRow(u);
  // E-123: the User Details > Permissions dialog reads the user's current
  // grants from the detail row - deviceCodes/channelCodes/orgCodes as CSV
  // STRINGS (real Dahua REST semantics, no array leaves per E-105). Admin
  // gets every registered device/channel/org automatically.
  const allDeviceCodes = [...DEVICE_REGISTRY.values()].map((d) => d.deviceCode).join(',');
  const allChannelIds = allChannels().map((c) => c.channelId || c.channelCode).join(',');
  const allOrgCodes = (() => { try { return listOrgs().map((o) => o.code).join(','); } catch { return '001,VIGILAB'; } })();
  const isAdmin = String(u.adminFlag ?? u.isAdmin ?? '') === '1' || String(u.userType) === '1';
  return {
    ...base,
    userId: String(u.userId ?? u.id ?? ''),
    loginName: String(u.loginName ?? u.username ?? ''),
    realName: String(u.realName ?? base.name),
    employeeName: String(u.employeeName ?? u.realName ?? base.name),
    userTypeName: String(u.userTypeName ?? ''),
    adminFlag: String(u.adminFlag ?? '0'),
    hasAuthority: '1',
    authority: '1',
    statusName: String(u.statusName ?? ''),
    enable: String(u.enable ?? '1'),
    locked: String(u.locked ?? u.lock ?? '0'),
    lock: String(u.lock ?? u.locked ?? '0'),
    roleIds: Array.isArray(u.roleIds) ? u.roleIds.join(',') : String(u.roleIds ?? ''),
    roleNames: Array.isArray(u.roleNames) ? u.roleNames.join(',') : String(u.roleNames ?? ''),
    roleId: String(u.roleId ?? (Array.isArray(u.roleIds) ? u.roleIds[0] ?? '' : u.roleIds ?? '')),
    roleName: String(u.roleName ?? (Array.isArray(u.roleNames) ? u.roleNames[0] ?? '' : u.roleNames ?? '')),
    groupId: String(u.groupId ?? ''),
    groupName: String(u.groupName ?? ''),
    orgCode: String(u.orgCode ?? ''),
    orgCodes: isAdmin ? allOrgCodes : String(u.orgCode ?? ''),
    domainId: String(u.domainId ?? '0'),
    deviceCodes: isAdmin ? allDeviceCodes : '',
    channelIds: isAdmin ? allChannelIds : '',
    email: String(u.email ?? ''),
    telephone: String(u.telephone ?? ''),
    mobile: String(u.mobile ?? ''),
    createTime: String(u.createTime ?? ''),
    modifyTime: String(u.modifyTime ?? ''),
    remark: String(u.remark ?? u.remarks ?? ''),
    deletable: String(u.deletable ?? '1')
  };
}

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
  const pageData = rows.slice(start, start + pageSize).map(serializeUserPageRow);
  // E-105: strict native envelope of v1.1/user/page.
  //   data.pageData[]  = the rows of the requested page
  //   data.totalCount  = TOTAL number of matching users (STRING).
  // PROVEN (UserLogical.dll):
  //   * FUN_18005fa00 (DPSDK callback) -> FUN_180070530 writes
  //     *(u32*)(out+8) = native.totalCount (atoi of this STRING) into the
  //     logical container COUNT field, and that field is copied verbatim to
  //     the notify payload (+0x30) -> PluginFactory
  //     DSNumberPageCtrl::SetTotalCount(param_2+0x30) => it is the PAGER
  //     total, NOT the number of rendered rows.
  //   * the number of rendered rows comes from the vector itself:
  //     FUN_180047d20 computes (end-begin)/0x88 and PluginFactory
  //     FUN_180ac33a0 loops (end-begin)/0x88 - the UI loop is bounded by
  //     pageData.length, so totalCount may (and must) exceed it when the
  //     user store is bigger than pageSize.
  // No list/results/items/userList aliases and no total/page/pageSize/
  // pageCount duplicates: they are not part of the native descriptor and
  // only enlarge the body the native binder has to walk.
  return {
    pageData,
    totalCount: String(totalCount)
  };
}

export function buildUserDetailPayload(userId) {
  const row = USER_STORE.find((u) => String(userId) === u.id || String(userId) === u.userId);
  return row ? serializeUserRow(row) : null; // E-105: native keys + CSV aliases, no array leaves
}

export function buildUserGroupListPayload(query = {}) {
  const kw = String(query?.keyword ?? '').trim().toLowerCase();
  // E-102 native contract (FUN_1806f6a10, group-by-role-level/list):
  // results[] { groupName, groupId, users[] { userId, username } } - strings.
  const list = USER_GROUP_STORE.filter((g) => !kw || g.groupName.toLowerCase().includes(kw)).map((g) => ({
    ...g,
    // E-133 (REA ses_e4217e907, APIModule 0x28e70): every group row must carry
    // eventTypes[]{eventType,eventTypeName,sort} or IsKeyValid -> 3101 toast.
    eventTypes: [
      { eventType: '1', eventTypeName: 'Alarm', sort: '1' },
      { eventType: '2', eventTypeName: 'Event', sort: '2' },
      { eventType: '3', eventTypeName: 'System', sort: '3' }
    ],
    users: USER_STORE.filter((u) => u.groupId === g.groupId)
      .map((u) => ({ userId: u.userId, id: u.id, username: u.username, userName: u.username, name: u.realName }))
  }));
  return {
    list, results: list, items: list, userGroupList: list, groupList: list, pageData: list,
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '100', pageCount: '1'
  };
}

export function buildLdapConfigPayload() {
  // E-104: NATIVE contract (DPSDK.dll FUN_18064d140 - no wrapper key, reads
  // data directly): username/port/autoSynTime/dn/enable/enableAutoSyn/ssl/
  // server, ALL STRING (port via atoi). enable/enableAutoSyn/ssl are
  // compared with the literal "1" (FUN_18076f010 vs "1" @0xc7cb2c). SPA
  // (index-BiUvY3rV.js@0xad65) reads the same keys with string "1"/"0".
  return {
    // native keys (no underscore spelling - case-sensitive bind)
    username: '', port: '389', autoSynTime: '00:00:00', dn: '',
    enable: '0', enableAutoSyn: '0', ssl: '0', server: '',
    // SPA/legacy aliases kept as superset
    enableLdap: '0', status: '0',
    ip: '', address: '', useSsl: '0', useSSL: '0', encryptType: '0',
    baseDn: '', baseDN: '', userName: '', userDn: '',
    password: '', usernameAttribute: 'uid', remark: ''
  };
}

export function buildUserEmailListPayload(query = {}) {
  const kw = String(query?.keyword ?? '').trim().toLowerCase();
  const hits = USER_STORE.filter((u) => u.email && (!kw || u.email.toLowerCase().includes(kw) || u.username.toLowerCase().includes(kw)));
  const list = hits.map((u) => ({ id: u.id, userId: u.id, username: u.username, email: u.email }));
  // E-100: SPA consumers read data.pageData for user/email/page (report-send
  // dialog index-C1zRFxk1.js @85138) - without it V.value stays undefined and
  // the render throws (white screen). pageData + string counters.
  return {
    list, results: list, items: list, emailList: list, pageData: list,
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '10000', pageCount: '1'
  };
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
  // E-099: a resource id can be an org code (001/VIGILAB), a device code
  // (D0238JDG3016) or a channel code (D0238JDG3016$1$0$0). Resolve the owning
  // org so VIGILAB assets grant the operator role too.
  const dev = DEVICE_REGISTRY.get(rid) || [...DEVICE_REGISTRY.values()].find((d) => String(rid).startsWith(d.deviceCode));
  const resOrg = body?.orgCode || body?.orgName || (dev ? deviceOrgCodeOf(dev) : '') || rid;
  const isOrgResource = rid === '' || rid === '001' || resOrg === 'VIGILAB' || resOrg === '001';
  const roles = buildRolePagePayload().list || [];
  const list = roles.map((r) => {
    // cascade: admin (roleId 1) is granted everywhere; operator on 001/VIGILAB
    // assets (orgs, devices and channels of those orgs)
    const checked = String(r.roleId) === '1' || (isOrgResource && String(r.roleId) === '2');
    return {
      // E-102 native contract (FUN_1806d99f0): results[] items bind
      // id/roleName/memo (strings). checked/permission only exist in the
      // TREE contract, kept here as harmless superset.
      id: String(r.roleId), roleId: String(r.roleId), roleCode: r.roleCode,
      roleName: r.roleName, memo: r.memo || r.description || '',
      checked: checked ? '1' : '0',           // E-099: STRING flags (E-095 lesson)
      permission: checked ? '1' : '0',
      operate: checked ? '1' : '0',
      resourceId: rid, inputChecked: checked ? '1' : '0',
      orgCode: resOrg, status: r.status, statusName: r.statusName,
      level: r.level, roleLevel: r.roleLevel,
      userCount: r.userCount, editable: r.editable, deletable: r.deletable,
      default: r.default, createTime: r.createTime
    };
  });
  // E-104: NATIVE contract (DPSDK.dll FUN_18028f220, descriptor built inline
  // @0x28f220): data.results is an ARRAY OF STRINGS (roleIds, each -> char
  // [0x40]). Serving objects there makes the native parser (type=2 vs JSON
  // object node 6) extract ZERO elements -> empty permission dialog. The
  // role OBJECTS live in list/roleList/items (SPA/legacy consumers).
  const roleIds = list.map((r) => String(r.roleId));
  return {
    list, results: roleIds, roleIds, items: list, roleList: list, roles: list,
    checkedRoles: roleIds,
    total: String(list.length), totalCount: String(list.length), resourceId: rid
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
      // E-122: selection flags so the Role Details > Device Permissions tree
      // renders every camera as an ENABLED, CLICKABLE checkbox (the DPSDK
      // tree parser binds checked/hasAuthority/disabled as strings).
      checked: '0', hasAuthority: '1', disabled: '0', selectable: '1',
      isParent: channels.length ? '1' : '0', hasChild: channels.length ? '1' : '0',
      id: d.deviceCode, name: d.deviceName, parentCode: deviceOrgCodeOf(d),
      channels: channels.map((c) => ({
        channelId: c.channelId || c.channelCode, channelCode: c.channelCode,
        channelName: c.channelName || d.deviceName, channelSeq: c.channelSeq ?? 0,
        deviceCode: d.deviceCode, orgCode: deviceOrgCodeOf(d), status: '1',
        checked: '0', hasAuthority: '1', disabled: '0', selectable: '1',
        isParent: '0', hasChild: '0',
        id: c.channelId || c.channelCode, name: c.channelName || d.deviceName,
        parentCode: d.deviceCode
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

// ===== E-099: LIVE VIEW PRIVILEGE GATE (asset permission per channel) =======
//
// DPSDK.dll string pool:
//   CheckChannelFunction -> v1.1/account/function/channel/check   (@0xc9ca80)
//   GetChannelFunctions  -> v1.1/account/function/channel/check/batch (@0xc7f0c0)
//   CheckDeviceFunction  -> v1.1/account/function/device/check    (@0xc9c978)
//   response keys: "functionCodes" (@0xcc9440, BRMSAccountCheckChannelFunctions)
// The client asks WHICH FunctionType codes the logged account may use on a
// channel BEFORE opening Live View: liveView=8, playback=9, download=10,
// ptzOperate=13, alarm... (DSS_FUNCTION_CATALOG, e037-native-tree.js).
// Default grant (admin cascade, E-098): EVERY function on EVERY registered
// channel of the operator's orgs - so D0238JDG3016$1$0$0 in VIGILAB opens
// Live View / Playback / PTZ / Alarm immediately.
export const DSS_CHANNEL_FUNCTION_GRANTS = ['1', '2', '3', '5', '6', '8', '9', '10', '11', '13', '15', '17', '21', '23', '24', '25', '27'];

const FN_NAMES = {
  '1': 'record', '2': 'ptzOperateAndConfig', '3': 'talk', '5': 'recordLock', '6': 'recordTips',
  '8': 'liveView', '9': 'playback', '10': 'download', '11': 'privacyMasking', '13': 'ptzOperate',
  '15': 'syncTime', '17': 'livePreview', '21': 'deviceWeb', '23': 'broadcast', '24': 'playAudio',
  '25': 'controlVolume', '27': 'panoramicSplicing'
};

export function channelFunctionRows() {
  // E-099: every flag STRING (E-095 strict === lesson)
  return DSS_CHANNEL_FUNCTION_GRANTS.map((fc) => ({
    functionCode: fc, functionId: fc, functionName: FN_NAMES[fc] || fc,
    enable: '1', available: '1', hasRight: '1', checked: '1', status: '1', type: '1'
  }));
}

export function buildChannelFunctionCheckPayload(input = {}) {
  const raw = input.channelCodes || input.channelCodeList || input.channelIds
    || (input.channelCode ? [input.channelCode] : null)
    || (Array.isArray(input.channels) ? input.channels.map((c) => (typeof c === 'string' ? c : c.channelCode || c.channelId)) : null)
    || (Array.isArray(input.list) ? input.list.map((c) => (typeof c === 'string' ? c : c.channelCode || c.channelId)) : null);
  const codes = (raw || []).map(String).filter(Boolean);
  const all = allChannels();
  const matched = codes.length ? all.filter((c) => codes.includes(String(c.channelCode)) || codes.includes(String(c.channelId))) : all;
  const list = (matched.length ? matched : all).map((c) => {
    const functions = channelFunctionRows();
    return {
      channelCode: c.channelCode, channelId: c.channelId || c.channelCode, deviceCode: c.deviceCode,
      orgCode: c.orgCode || deviceOrgCodeOf(DEVICE_REGISTRY.get(c.deviceCode) || {}),
      functionCodes: [...DSS_CHANNEL_FUNCTION_GRANTS], functions, list: functions, results: functions,
      checkResult: '1', available: '1', hasRight: '1', hasFunction: '1', enable: '1', status: '1'
    };
  });
  const single = list[0] || { functionCodes: [...DSS_CHANNEL_FUNCTION_GRANTS], functions: channelFunctionRows() };
  return {
    ...single,
    list, results: list, items: list, channelList: list, channelFunctionList: list,
    total: String(list.length), totalCount: String(list.length)
  };
}

export function buildDeviceFunctionCheckPayload(input = {}) {
  const codes = (input.deviceCodes || (input.deviceCode ? [input.deviceCode] : null) || []).map(String).filter(Boolean);
  const all = [...DEVICE_REGISTRY.values()];
  const matched = codes.length ? all.filter((d) => codes.includes(String(d.deviceCode))) : all;
  const list = (matched.length ? matched : all).map((d) => ({
    deviceCode: d.deviceCode, deviceId: d.deviceId || d.deviceCode, orgCode: deviceOrgCodeOf(d),
    functionCodes: [...DSS_CHANNEL_FUNCTION_GRANTS], functions: channelFunctionRows(),
    checkResult: '1', available: '1', hasRight: '1', enable: '1', status: '1'
  }));
  const single = list[0] || {};
  return { ...single, list, results: list, items: list, deviceList: list, total: String(list.length), totalCount: String(list.length) };
}


export function buildAlertTypeListPayload() {
  // E-112: the client's PacketGetAlertTypes (CommonFunc.cpp:149 key check)
  // requires alertTypeId (+ alertTypeIdName) - observed as "Invalid key:
  // [alertTypeId]" in the client log 2026-11-07 04:44:56.
  const rows = OMMS_ALERT_TYPES.map(strEnum).map((a) => ({
    ...a,
    alertTypeId: a.alertType, alertTypeName: a.alertTypeName || a.alertName,
    alertTypeIdName: a.alertTypeName || a.alertName,
    name: a.alertName, type: a.alertType
  }));
  return {
    results: rows,
    list: rows,
    items: rows,
    alertTypeList: rows,
    dictionaryList: rows,
    total: String(rows.length),
    totalCount: String(rows.length)
  };
}

// ---------------------------------------------------------------------------
// 7) Auto-register (ARS): native devices registered on TCP 9500 become real
//    devices in the tree/page/statistics responses.
// ---------------------------------------------------------------------------
function isPrivateIp(ip) {
  const v = String(ip || '').replace(/^::ffff:/, '');
  if (!v || !/^\d+\.\d+\.\d+\.\d+$/.test(v)) return false;
  const [a, b] = v.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127 || a === 169;
}

export function registerArsDevice(deviceInfo) {
  // E-191: el codigo del equipo es el Register ID pelado, igual que en el DSS
  // real (antes se prefijaba con ARS-, que el cliente mostraba como Device ID).
  const code = String(deviceInfo.deviceId || '').replace(/^ARS-/, '');
  // E-184: a NAT'd device reports its LAN address, which this server cannot
  // reach. When the register came from a public source address, that address is
  // the one the operator will port-forward, so it wins over a private literal.
  const reported = String(deviceInfo.ip || '');
  const source = String(deviceInfo.registerFromIp || '').replace(/^::ffff:/, '');
  const reachableIp = (isPrivateIp(reported) && source && !isPrivateIp(source)) ? source : (reported || source);

  // E-184: the operator may have created this row from the client's "Auto
  // Register" dialog BEFORE the device dialed in (that row has an empty IP and
  // the organization/authorization they chose). Re-registering must COMPLETE
  // that row, never replace it - createDeviceRecord() always inserts a fresh
  // record and persistDevice() overwrites by code, which used to wipe both.
  const existing = DEVICE_REGISTRY.get(code);
  if (existing) {
    existing.deviceIp = reachableIp || existing.deviceIp || '';
    existing.devicePort = Number(deviceInfo.port) || Number(existing.devicePort) || 37777;
    existing.protocolType = existing.protocolType || '1';
    existing.deviceCategory = existing.deviceCategory || '1';
    const typeIn = String(deviceInfo.deviceType || '');
    if (typeIn && typeIn !== '1') existing.deviceType = typeIn;
    if (deviceInfo.deviceName && (!existing.deviceName || existing.deviceName === code)) existing.deviceName = deviceInfo.deviceName;
    const chans = Number(deviceInfo.channelCount) || 0;
    if (chans > 0) {
      existing.channelNum = chans;
      existing.encoderChannelCount = chans;
      existing.alarmInNum = chans;
      existing.alarmOutNum = chans;
      // E-186: el conteo confirmado por el equipo reemplaza al placeholder '1'
      // que el operador deja en el dialogo de alta.
      existing.channelCountSource = 'device';
      if (existing.model === '' && deviceInfo.model) existing.model = String(deviceInfo.model);
    }
    if (deviceInfo.username) existing.username = deviceInfo.username;
    if (deviceInfo.password) existing.password = deviceInfo.password;
    existing.manufacturer = existing.manufacturer || 'Dahua';
    // E-189: el serial real del equipo queda registrado aunque la fila se
    // identifique por el Device ID que definio el operador.
    if (deviceInfo.serialNo) existing.serialNumber = String(deviceInfo.serialNo);
    existing.registerFromIp = source || existing.registerFromIp || '';
    existing.lastSeenAt = Date.now();
    existing.online = '1';
    existing.status = '1';
    existing.onlineStatus = '1';
    existing.deviceStatus = 'online';
    existing.statusName = 'Online';
    existing.isOnline = 1;
    existing.isOnLine = 1;
    existing.source = existing.source || 'auto-register';
    existing.updateTime = new Date().toISOString();
    persistDevice(existing);
    return existing;
  }

  const input = normalizeDeviceInput({
    deviceIp: reachableIp,
    devicePort: deviceInfo.port || 37777,
    protocolType: '1',
    deviceCategory: '1',
    deviceType: String(deviceInfo.deviceType || '2'),
    deviceName: deviceInfo.deviceName || `Auto-Reg ${deviceInfo.deviceId}`,
    serverCode: 'video#local',
    channelCount: Number(deviceInfo.channelCount) > 0 ? Number(deviceInfo.channelCount) : 1,
    manufacturer: 'Dahua',
    deviceCode: code
  });
  const record = createDeviceRecord(input, { source: 'auto-register' });
  // E-185: the credentials entered in the client's "Auto Register" dialog are
  // the ones the platform will use to log into the device once it dials in.
  // normalizeDeviceInput() drops them, so they must be attached here - without
  // them the row had no user/password and every later login to the device
  // would start from an empty account.
  if (deviceInfo.username) record.username = String(deviceInfo.username);
  if (deviceInfo.password) record.password = String(deviceInfo.password);
  // E-186: '1' por defecto es un placeholder hasta que el equipo reporte su
  // ChannelNum real en el REGISTER.
  record.channelCountSource = Number(deviceInfo.channelCount) > 0 ? 'device' : 'placeholder';
  if (deviceInfo.serialNo) record.serialNumber = String(deviceInfo.serialNo);
  // E-174: pending authorization until the operator adds it in "Auto Register".
  // E-177: only for a NEW record - a DVR that re-registers after a reboot must
  // not lose the authorization the operator already granted.
  if (record.authorized === undefined) record.authorized = '0';
  record.registerFromIp = source || reachableIp || '';
  record.lastSeenAt = Date.now();
  if (reachableIp) {
    record.online = '1';
    record.status = '1';
    record.onlineStatus = '1';
    record.deviceStatus = 'online';
    record.statusName = 'Online';
    record.isOnline = 1;
    record.isOnLine = 1;
  }
  persistDevice(record);
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
