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

// RTSP path name in MediaMTX for the ONVIF camera
export const MEDIAMTX_CAMERA_PATH = process.env.MEDIAMTX_CAMERA_PATH || 'cam1';
export const MEDIAMTX_API_URL = process.env.MEDIAMTX_API_URL || 'http://mediamtx:9997';

// Discover ONVIF stream URI from the camera via SOAP GetProfiles/GetStreamUri
export async function discoverOnvifStreamUri(deviceIp, devicePort = 8021) {
  const base = `http://${deviceIp}:${devicePort}`;
  const soapAction = 'http://www.onvif.org/ver10/media/wsdl';
  const getProfilesBody = `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <env:Body><trt:GetProfiles/></env:Body></env:Envelope>`;

  let profileToken = '';
  try {
    const profiles = await soapPost(`${base}/onvif/media`, getProfilesBody, soapAction);
    const m = profiles.match(/<trt:Profiles[^>]*token="([^"]+)"/);
    if (m) profileToken = m[1];
  } catch (e) {
    // Try the device_service endpoint as fallback
    try {
      const profiles = await soapPost(`${base}/onvif/device_service`, getProfilesBody, soapAction);
      const m = profiles.match(/<trt:Profiles[^>]*token="([^"]+)"/);
      if (m) profileToken = m[1];
    } catch { /* ignore */ }
  }

  if (!profileToken) return null;

  const getStreamBody = `<?xml version="1.0" encoding="UTF-8"?>
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
</env:Envelope>`;

  try {
    const stream = await soapPost(`${base}/onvif/media`, getStreamBody, soapAction);
    const m = stream.match(/<tt:Uri>([^<]+)<\/tt:Uri>/);
    if (m) return m[1];
  } catch {
    try {
      const stream = await soapPost(`${base}/onvif/device_service`, getStreamBody, soapAction);
      const m = stream.match(/<tt:Uri>([^<]+)<\/tt:Uri>/);
      if (m) return m[1];
    } catch { /* ignore */ }
  }

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
      timeout: 1500,
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

// Configure a MediaMTX path to pull from an RTSP source
export async function configureMediaMTXPath(pathName, rtspSource) {
  const body = JSON.stringify({
    path: { name: pathName, source: rtspSource, sourceOnDemand: true },
    action: 'setSource'
  });
  try {
    const res = await fetch(`${MEDIAMTX_API_URL}/v3/paths/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body
    });
    return res.ok;
  } catch { return false; }
}

// Missing FALLBACK routes implementations - return benign envelopes so the
// client never sees "data abnormal" toasts.
// These were observed during operator testing:
export const FALLBACK_ROUTES = {
  // User / role management
  'GET /brms/api/v1.1/user/list': { list: [], total: 0 },
  'GET /brms/api/v1.1/monitor/view/view-tree': { viewTree: [], list: [], total: 0 },
  'GET /brms/api/v1.1/config/ai/privacy': { enable: 0, privacyMask: [], list: [] },
  'GET /admin/API/user/fish-eye-data': { fishEyeData: [], list: [], total: 0 },
  // Face / AI
  'GET /brms/api/v1.1/face/application/control/repository/page': { list: [], total: 0 },
  'GET /brms/api/v1.1/face/application/control/repository/process/list': { list: [], total: 0 },
};
