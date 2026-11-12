// Query the lab camera's ONVIF profiles for the real encoder resolution.
const https = require('https');
const http = require('http');

const base = process.env.CAM || 'http://192.168.0.238:8021';
const body = `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <env:Body><trt:GetProfiles/></env:Body></env:Envelope>`;

function post(url, data) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'POST', rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/soap+xml; charset=utf-8', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => {
      let b = '';
      res.on('data', (d) => b += d);
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

(async () => {
  for (const ep of ['/onvif/media_service', '/onvif/media', '/onvif/device_service']) {
    try {
      const r = await post(base + ep, body);
      const res = [...r.body.matchAll(/<(?:tt:)?Resolution[^>]*>\s*<(?:tt:)?Width>(\d+)<\/(?:tt:)?Width>\s*<(?:tt:)?Height>(\d+)<\/(?:tt:)?Height>/g)].map((m) => m[1] + 'x' + m[2]);
      const enc = [...r.body.matchAll(/<tt:Encoding>([^<]+)<\/tt:Encoding>/g)].map((m) => m[1]);
      console.log(ep, '| status', r.status, '| resolutions', JSON.stringify(res), '| encodings', JSON.stringify(enc));
      if (res.length) return;
    } catch (e) { console.log(ep, 'ERR', e.message); }
  }
})();
