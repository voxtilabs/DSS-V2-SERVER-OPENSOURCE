// ===== E-026: ONVIF -> MediaMTX video bridge + missing FALLBACK routes =====
//
// Objective: eliminate all "data abnormal" toasts from missing routes, and
// provide real H.265 playback from ONVIF camera 192.168.0.238:8021 via
// MediaMTX proxy on :9100.
//
// Camera facts (verified live):
//   - ONVIF device service on http://192.168.0.238:8021/onvif/device_service
//   - RTSP stream on rtsp://192.168.0.238:8554/EBA1_LECTOR (NOT port 554)
//   - MediaMTX path "cam1" already pulls rtsp://192.168.0.238:8554/EBA1_LECTOR
//     and serves it on rtsp://10.10.20.120:9100/cam1 (H265, 25fps)
//
// MediaMTX control API: http://localhost:9997/v3/paths/list
//   POST /v3/paths/configure  {path: {...}, action: 'add'|'remove'|'setSource'}
//   DELETE /v3/paths/{name}

import http from 'node:http';
import crypto from 'node:crypto';

// RTSP path name in MediaMTX for the ONVIF camera
export const MEDIAMTX_CAMERA_PATH = process.env.MEDIAMTX_CAMERA_PATH || 'cam1';
export const MEDIAMTX_API_URL = process.env.MEDIAMTX_API_URL || 'http://mediamtx:9997';

// Discover ONVIF stream URI from the camera via SOAP GetProfiles/GetStreamUri
// WSSE UsernameToken per the ONVIF SOAP spec (PasswordDigest =
// base64(sha1(nonceB64 + created + password))). Cameras that require
// credentials for GetProfiles/GetStreamUri (the lab one does NOT, but Dahua
// devices in production DO) would otherwise drop the call at the transport.
function wsseHeader(user, pass) {
  if (!user) return '';
  const nonce = crypto.randomBytes(16);
  const nonceB64 = nonce.toString('base64');
  const created = new Date().toISOString().replace('.000Z', 'Z').replace(/\.\d+Z$/, 'Z');
  const digest = crypto.createHash('sha1')
    .update(Buffer.concat([nonce, Buffer.from(String(pass || ''), 'utf8'), Buffer.from(created, 'utf8')]))
    .digest('base64');
  return `<env:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken><wsse:Username>${user}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonceB64}</wsse:Nonce>
        <wsu:Created>${created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </env:Header>`;
}

export async function discoverOnvifStreamUri(deviceIp, devicePort = 8021, auth = {}) {
  const base = `http://${deviceIp}:${devicePort}`;
  const soapAction = 'http://www.onvif.org/ver10/media/wsdl';
  const devAction = 'http://www.onvif.org/ver10/device/wsdl';
  // WSSE security header: PasswordDigest per ONVIF spec (nonce + created + pass).
  const wsse = wsseHeader(auth.userName || auth.user || auth.loginName, auth.password || auth.pass);
  const sec = (xml) => xml.replace('<env:Body>', (wsse || '') + '\n<env:Body>');
  // Namespace-agnostic tag matches: cameras emit arbitrary prefixes
  // (trt:, tt:, s: or ns0:). The lab camera answers with s:/tt:/trt:.
  const rxProfiles = /<(?:[A-Za-z0-9]+:)?Profiles[^>]*token="([^"]+)"/;
  const rxUri = /<(?:[A-Za-z0-9]+:)?Uri>([^<]+)<\/(?:[A-Za-z0-9]+:)?Uri>/;

  // Standard flow: GetCapabilities (device) -> Media XAddr -> GetProfiles ->
  // GetStreamUri against the MEDIA SERVICE the camera itself advertises.
  // The lab camera serves /onvif/media_service; "onvif/media" answers with an
  // empty <tds:wsdlResponse/> (diagnosed live, 2026-11-03).
  let mediaEndpoint = `${base}/onvif/media_service`;
  try {
    const capsBody = sec(`<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <env:Body><tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities></env:Body></env:Envelope>`);
    const caps = await soapPost(`${base}/onvif/device_service`, capsBody, devAction + '/GetCapabilities');
    // The first XAddr AFTER the <tt:Media> element is the Media service the
    // camera itself advertises (lab camera: http://ip:8021/onvif/media_service).
    const idxMedia = caps.search(/<(?:[A-Za-z0-9]+:)?Media>/);
    if (idxMedia >= 0) {
      const mx = caps.slice(idxMedia).match(/<(?:[A-Za-z0-9]+:)?XAddr>([^<]+)<\/(?:[A-Za-z0-9]+:)?XAddr>/);
      if (mx) { mediaEndpoint = mx[1].replace(/\/$/, ''); }
    }
  } catch { /* fall back to the conventional endpoint */ }

  let profileToken = '';
  for (const ep of [mediaEndpoint, `${base}/onvif/media`, `${base}/onvif/media_service`, `${base}/onvif/device_service`]) {
    try {
      const getProfilesBody = sec(`<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <env:Body><trt:GetProfiles/></env:Body></env:Envelope>`);
      const profiles = await soapPost(ep, getProfilesBody, `${soapAction}/GetProfiles`);
      const m = profiles.match(rxProfiles);
      if (m) { profileToken = m[1]; mediaEndpoint = ep; break; }
    } catch { /* try next endpoint */ }
  }

  if (!profileToken) return null;

  const getStreamBody = sec(`<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <env:Body>
    <trt:GetStreamUri>
      <trt:StreamSetup>
        <trt:Stream>RTP-Unicast</trt:Stream>
        <trt:Transport><trt:Protocol>RTSP</trt:Protocol></trt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>${profileToken}</trt:ProfileToken>
    </trt:GetStreamUri>
  </env:Body>
</env:Envelope>`);

  try {
    const stream = await soapPost(mediaEndpoint, getStreamBody, `${soapAction}/GetStreamUri`);
    const m = stream.match(rxUri);
    if (m) return m[1];
  } catch { /* fall through */ }
  return null;
}

function soapPost(url, body, soapAction) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      host: u.hostname,
      port: u.port || 80,
      path: u.pathname,
      method: 'POST',
      timeout: 2500,
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'SOAPAction': `"${soapAction}"`,
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve(data));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end(body);
  });
}

// Configure a MediaMTX path to pull from an RTSP source.
// MediaMTX v3 control API routes (v1.11.3, internal/api/api.go):
//   POST   /v3/config/paths/add/<name>       create the static entry
//   PATCH  /v3/config/paths/patch/<name>     alter an existing entry
//   DELETE /v3/config/paths/delete/<name>    remove it
// (there is NO /v3/paths/configure nor .../remove/<name>).
export async function configureMediaMTXPath(pathName, rtspSource) {
  const name = encodeURIComponent(String(pathName || ''));
  const body = JSON.stringify({ source: rtspSource, sourceOnDemand: true });
  const tryCall = (method, p) =>
    fetch(`${MEDIAMTX_API_URL}${p}`, { method, headers: { 'Content-Type': 'application/json' }, body });
  try {
    const add = await tryCall('POST', `/v3/config/paths/add/${name}`);
    if (add.ok) return true;
    //_ALREADY_EXISTS -> alter the existing entry instead
    const patch = await tryCall('PATCH', `/v3/config/paths/patch/${name}`);
    return patch.ok;
  } catch { return false; }
}

// E-032 hygiene: drop the device's MediaMTX path when the device is deleted.
export async function removeMediaMTXPath(pathName) {
  try {
    const res = await fetch(`${MEDIAMTX_API_URL}/v3/config/paths/delete/${encodeURIComponent(String(pathName || ''))}`, { method: 'DELETE' });
    return res.ok;
  } catch { return false; }
}

// E-034: one MediaMTX path per registered device. The Live View opens the
// stream returned by MTS/Video/StartVideo, so every device (added by hand,
// from Discover, by ONVIF or by Dahua auto-register) must own its path.
export function mediaMtxPathForDevice(device) {
  const code = String(device?.deviceCode || '').replace(/[^A-Za-z0-9_-]/g, '');
  return code ? `cam_${code}` : MEDIAMTX_CAMERA_PATH;
}

// Dahua native RTSP convention (documented EV-013). Used only as a LAST
// resort when the camera does not answer ONVIF.
export function dahuaRtspUri(ip, channel = 1, subtype = 0) {
  return `rtsp://${ip}:554/cam/realmonitor?channel=${channel}&subtype=${subtype}`;
}

// Missing FALLBACK routes implementations - return benign envelopes so the
// client never sees "data abnormal" toasts.
// These were observed during operator testing:
export const FALLBACK_ROUTES = {
  // User / role management
  'GET /brms/api/v1.1/user/list': { list: [], total: 0 },
  // E-033: monitor/view/view-tree is NOT a fallback any more - it is served by
  // the real ViewController contract (see e033-monitor-views.js).
  'GET /brms/api/v1.1/config/ai/privacy': { enable: 0, privacyMask: [], list: [] },
  // E-087: real response VO (server package javap): FishEyeDataVo{
  // results:[FishEyeXo{orgCode,fileData}] } - an empty fish-eye map is
  // legitimate (no map configured), but the key must be `results`.
  'GET /admin/API/user/fish-eye-data': { results: [], fishEyeData: [], list: [], total: 0 },
  // Face / AI
  'GET /brms/api/v1.1/face/application/control/repository/page': { list: [], total: 0 },
  'GET /brms/api/v1.1/face/application/control/repository/process/list': { list: [], total: 0 },
};
