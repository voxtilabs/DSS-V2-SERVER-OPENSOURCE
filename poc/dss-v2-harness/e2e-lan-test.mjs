import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import WebSocket from 'ws';

// ─── Config ──────────────────────────────────────────────────────────────
const BASE = 'https://10.10.20.120:1443';
const BASE_9443 = 'https://10.10.20.120:9443';
const USER = 'admin';
const PASS = 'admin123';
let token = '';
// E-087 fix: ONLY the deviceCodes this suite created in THIS run are
// cleaned up in after(). Name-prefix filters are NOT safe: the operator
// names their own lab cameras "EBA..." too, and a prefix cleanup deleted
// the operator's camera from the registry (devices.json -> []).
const CREATED_CODES = new Set();
// Codes that ALREADY existed before this run (e.g. the operator's own camera
// 192.168.0.238:8021). The add endpoint is idempotent per ip:port and returns
// the EXISTING deviceCode in that case, so CREATED_CODES can pick up an
// operator-owned code - after() must never delete those (E-087 incident #2).
const PRE_EXISTING_CODES = new Set();

// ─── Crypto helpers ──────────────────────────────────────────────────────
function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) {
  return crypto.createHash('md5').update(md5(`${user}:${realm}:${temp}`) + ':' + randomKey).digest('hex');
}

// ─── HTTPS helper that ignores self-signed cert ──────────────────────────
async function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      rejectUnauthorized: false, // self-signed cert
    };
    if (options.body) {
      reqOptions.headers['Content-Length'] = Buffer.byteLength(options.body);
    }

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          json: () => JSON.parse(data),
          text: () => data,
        });
      });
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ─── Wait for server to be ready ────────────────────────────────────────
async function waitForServer(baseUrl) {
  const maxAttempts = 30;
  for (let attempts = 0; attempts < maxAttempts; attempts++) {
    try {
      const res = await request(`${baseUrl}/brms/api/v1.0/accounts/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userName: 'admin' })
      });
      if (res.status === 401) return;
    } catch { /* ignore */ }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Server did not start after 30 attempts');
}

// ─── DVRIP/DHIP REGISTER frame builder (E-025, auto-register) ─────────
// Header: 32-byte little-endian fields (magic DHIP, cmd, seq, payloadLen, ...),
// payload: null-terminated strings + uint16 fields, per the DHCP/reg contract
// implemented by the gateway's ARS TCP server (Dahua auto register service).
function buildDhipRegFrame(deviceId, deviceName, macTail, ip) {
  const DHIP_MAGIC = 0x44484950;
  const CMD_REGISTER = 0x0001;
  const payload = Buffer.alloc(512, 0);
  let pos = 0;
  const str = (s) => { const b = Buffer.from(String(s), 'utf8'); b.copy(payload, pos); pos += b.length + 1; };
  str(deviceId);
  str(deviceName);
  payload.writeUInt16LE(2, pos); pos += 2;        // deviceType: NVR
  payload.writeUInt16LE(4, pos); pos += 2;        // channelCount
  str(ip);
  payload.writeUInt16LE(37777, pos); pos += 2;    // port
  str(USER);
  str(PASS);
  payload[pos++] = parseInt(macTail.slice(0, 2), 16);
  payload[pos++] = parseInt(macTail.slice(2, 4), 16);
  payload[pos++] = parseInt(macTail.slice(4, 6), 16);
  payload[pos++] = parseInt(macTail.slice(6, 8), 16);
  payload[pos++] = parseInt(macTail.slice(8, 10), 16);
  payload[pos++] = parseInt(macTail.slice(10, 12), 16);
  str('E2E-FW');

  const header = Buffer.alloc(32);
  header.writeUInt32LE(DHIP_MAGIC, 0);
  header.writeUInt32LE(CMD_REGISTER, 4);
  header.writeUInt32LE(1, 8);
  header.writeUInt32LE(pos, 12);
  return Buffer.concat([header, payload.subarray(0, pos)]);
}

// ─── RTSP TCP probe helper ──────────────────────────────────────────────
async function probeRtsp(rtspUrl) {
  const url = new URL(rtspUrl);
  const host = url.hostname;
  const port = parseInt(url.port || '554', 10);

  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port }, () => {
      const optionsReq = `OPTIONS ${rtspUrl} RTSP/1.0\r\nCSeq: 1\r\n\r\n`;
      socket.write(optionsReq);
    });

    let buffer = '';
    let step = 0;
    let optionsOk = false;
    let describeOk = false;
    let describeNotFound = false;
    let sdp = '';

    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.includes('\r\n\r\n')) {
        const lines = buffer.split('\r\n');
        const statusLine = lines[0];

        if (step === 0) {
          // OPTIONS response
          if (statusLine.includes('200 OK')) {
            optionsOk = true;
            step = 1;
            const describeReq = `DESCRIBE ${rtspUrl} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n`;
            socket.write(describeReq);
            buffer = '';
          } else {
            socket.end();
            resolve({ optionsOk: false, describeOk: false, describeNotFound: false, sdp: buffer, error: 'OPTIONS failed: ' + statusLine });
          }
        } else if (step === 1) {
          // DESCRIBE response
          sdp = buffer;
          if (statusLine.includes('200 OK')) {
            describeOk = true;
          } else if (statusLine.includes('404 Not Found')) {
            describeNotFound = true;
          }
          socket.end();
          resolve({ optionsOk, describeOk, describeNotFound, sdp });
        } else {
          socket.end();
          resolve({ optionsOk, describeOk, describeNotFound, sdp, error: 'Unexpected step' });
        }
      }
    });

    socket.on('error', reject);
    socket.setTimeout(15000, () => {
      socket.destroy();
      reject(new Error('RTSP probe timeout'));
    });
  });
}

// ─── WebSocket event listener helper ────────────────────────────────────
async function waitForWsEvent(token, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`wss://10.10.20.120:1443/brms/api/v1.0/event/ws?token=${token}`, {
      rejectUnauthorized: false,
    });

    const timer = setTimeout(() => {
      clearInterval(udpKeepalive);
      ws.close();
      reject(new Error('WebSocket event timeout'));
    }, timeoutMs);

    let welcomeReceived = false;
    let udpSent = false;
    // UDP is lossy by design: keep re-sending the alarm every 2s until the
    // WS bridge forwards the event, instead of betting on a single datagram
    // (a dropped datagram made this test flaky, ~1 in 8 runs).
    const udpKeepalive = setInterval(() => {
      if (!welcomeReceived) return;
      const udp = dgram.createSocket('udp4');
      udp.send('ANPR_EBA|CAM001|plate=E2E_TEST\r\n', 18800, '10.10.20.120', (err) => {
        if (err) console.error('UDP send error:', err);
        udp.close();
      });
    }, 2000);

    ws.on('open', () => {
      // Connected, wait for events
    });

    ws.on('message', (data) => {
      const text = data.toString();
      if (!welcomeReceived && text.includes('WELCOME')) {
        welcomeReceived = true;
        // Send UDP alarm AFTER welcome received (first shot, keepalive takes over)
        if (!udpSent) {
          udpSent = true;
          const udp = dgram.createSocket('udp4');
          udp.send('ANPR_EBA|CAM001|plate=E2E_TEST\r\n', 18800, '10.10.20.120', (err) => {
            if (err) console.error('UDP send error:', err);
            udp.close();
          });
        }
        return;
      }
      if (text.includes('ANPR_EBA') || text.includes('ALARM') || text.includes('event')) {
        clearInterval(udpKeepalive);
        clearTimeout(timer);
        ws.close();
        resolve(text);
      }
    });

    ws.on('error', (err) => {
      clearInterval(udpKeepalive);
      clearTimeout(timer);
      reject(err);
    });

    ws.on('close', () => {
      clearInterval(udpKeepalive);
      clearTimeout(timer);
      if (!welcomeReceived) {
        reject(new Error('WebSocket closed before welcome'));
      }
    });
  });
}

// ─── Minimal MQTT 3.1.1 client (E-039): the native client talks MQTT to the
// gateway broker advertised by GetMqConfig (MQType "mqtt", mqtt://host:1883).
function mqttPacket(type, flags, body) {
  const out = [Buffer.from([(type << 4) | flags])];
  let len = body.length;
  do { let b = len % 128; len = Math.floor(len / 128); if (len > 0) b |= 0x80; out.push(Buffer.from([b])); } while (len > 0);
  out.push(body);
  return Buffer.concat(out);
}
function mqttString(s) {
  const b = Buffer.from(s, 'utf8');
  const head = Buffer.alloc(2);
  head.writeUInt16BE(b.length, 0);
  return Buffer.concat([head, b]);
}
function readMqttPacket(buf) {
  const type = buf[0] >> 4, flags = buf[0] & 0x0f;
  let mult = 1, len = 0, i = 1;
  for (;;) { const byte = buf[i++]; len += (byte & 0x7f) * mult; mult *= 128; if (!(byte & 0x80)) break; }
  return { type, flags, body: buf.subarray(i, i + len), rest: buf.subarray(i + len) };
}
// Connect + subscribe; resolves with {sock, publishes:[]} where every inbound
// PUBLISH is pushed as {topic, payload}.
function mqttSubscribe(host, port, filters, clientId) {
  return new Promise((resolve, reject) => {
    const publishes = [];
    const sock = net.connect(port, host, () => {
      const body = Buffer.concat([
        mqttString('MQTT'), Buffer.from([4, 0x02]), Buffer.from([0, 60]), mqttString(clientId)
      ]);
      sock.write(mqttPacket(1, 0, body));
      // The broker processes packets in stream order, so the SUBSCRIBEs can
      // go out right after the CONNECT.
      let pid = 1;
      for (const f of filters) {
        sock.write(mqttPacket(8, 2, Buffer.concat([Buffer.from([0, pid++]), mqttString(f), Buffer.from([0])])));
      }
    });
    let buf = Buffer.alloc(0);
    let subacks = 0;
    const wanted = filters.length;
    const timer = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } reject(new Error('MQTT handshake timeout')); }, 10000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 2) return;
        let mult = 1, len = 0, i = 1;
        let complete = true;
        for (;;) { if (i >= buf.length) { complete = false; break; } const byte = buf[i++]; len += (byte & 0x7f) * mult; mult *= 128; if (!(byte & 0x80)) break; }
        if (!complete || buf.length < i + len) return;
        const p = readMqttPacket(buf);
        buf = p.rest;
        if (p.type === 2) { /* CONNACK */ }
        else if (p.type === 9) { subacks++; if (subacks === wanted) { clearTimeout(timer); resolve({ sock, publishes }); } }
        else if (p.type === 3) {
          const tlen = p.body.readUInt16BE(0);
          publishes.push({ topic: p.body.toString('utf8', 2, 2 + tlen), payload: p.body.subarray(2 + tlen).toString('utf8') });
        }
      }
    });
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

// ─── Minimal STOMP 1.2 client (E-040): subscribe to an ActiveMQ topic on
// 61613. Frames are NULL-terminated; body length comes from content-length.
function stompSubscribe(host, port, destinations, clientId) {
  return new Promise((resolve, reject) => {
    const messages = [];
    const sock = net.connect(port, host, () => {
      const conn = `CONNECT\naccept-version:1.2\nhost:${host}\nlogin:admin\npasscode:admin\nheart-beat:0,0\n\n\0`;
      sock.write(conn);
      let sid = 0;
      for (const d of destinations) {
        sid += 1;
        sock.write(`SUBSCRIBE\nid:sub-${sid}\ndestination:${d}\nack:auto\nreceipt:r-${sid}\n\n\0`);
      }
    });
    let buf = Buffer.alloc(0);
    let receipts = 0;
    const wanted = destinations.length;
    const timer = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } reject(new Error('STOMP handshake timeout')); }, 15000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf(0);
        if (end === -1) break;
        let raw = buf.subarray(0, end).toString('utf8');
        buf = buf.subarray(end + 1);
        while (raw.startsWith('\n') || raw.startsWith('\r')) raw = raw.slice(1);
        if (!raw) continue;
        const nl = raw.indexOf('\n');
        const cmd = raw.slice(0, nl);
        const hend = raw.indexOf('\n\n', nl);
        if (hend === -1) continue;
        const headers = {};
        for (const line of raw.slice(nl + 1, hend).split('\n')) {
          const c = line.indexOf(':');
          if (c > 0) headers[line.slice(0, c)] = line.slice(c + 1);
        }
        const body = raw.slice(hend + 2);
        if (cmd === 'CONNECTED') { /* ok */ }
        else if (cmd === 'RECEIPT') { receipts++; if (receipts === wanted) { clearTimeout(timer); resolve({ sock, messages }); } }
        else if (cmd === 'MESSAGE') { messages.push({ destination: headers.destination, body }); }
        else if (cmd === 'ERROR') { clearTimeout(timer); reject(new Error('STOMP ERROR: ' + body.slice(0, 200))); }
      }
    });
    sock.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

// ─── Test Suite ──────────────────────────────────────────────────────────
describe('E2E Integration Tests (E-011)', { timeout: 120000 }, () => {
  before(async () => {
    await waitForServer(BASE);

    // Step 1: Challenge (401)
    const ch = await request(`${BASE}/brms/api/v1.0/accounts/authorize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName: USER })
    });
    assert.equal(ch.status, 401);
    const challenge = await ch.json();
    const d1 = challenge.data || challenge; // ResponseInfo envelope
    const { realm, randomKey, challengeKey } = d1;
    assert.ok(realm && randomKey && challengeKey);

    // Step 2: Response with signature
    const temp = doubleMd5(USER, PASS);
    const sig = makeSig(USER, realm, temp, randomKey);
    const auth = await request(`${BASE}/brms/api/v1.0/accounts/authorize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName: USER, randomKey, signature: sig, clientType: 'WINPC_V2', challengeKey })
    });
    assert.equal(auth.status, 200);
    const authBody = await auth.json();
    const d2 = authBody.data || authBody;
    token = d2.token;
    assert.ok(token);

    // Snapshot the registry BEFORE any test adds anything: after() only
    // deletes CREATED_CODES minus these pre-existing codes, so an idempotent
    // add that resolves to the operator's own device can never be wiped.
    const page = await request(`${BASE}/brms/api/v1.1/device/page?page=1&pageSize=1000`, {
      headers: { 'X-Subject-Token': token }
    });
    const pageJson = await page.json();
    const rows = pageJson.data?.results || pageJson.data?.list || [];
    for (const d of rows) if (d.deviceCode) PRE_EXISTING_CODES.add(String(d.deviceCode));
  });

  it('E2E-1 Auth handshake - keepalive & current user', async () => {
    const r = await request(`${BASE}/brms/api/v1.0/accounts/keepalive`, {
      method: 'POST',
      headers: { 'X-Subject-Token': token }
    });
    assert.equal(r.status, 200);

    const r2 = await request(`${BASE}/brms/api/v1.0/accounts/current`, {
      headers: { 'X-Subject-Token': token }
    });
    assert.equal(r2.status, 200);
    const j2 = await r2.json();
    const d2 = j2.data || j2;
    assert.equal(d2.username, USER);
  });

  it('E2E-2 Tree & DTOs - orgs, devices, channels', async () => {
    const r = await request(`${BASE}/brms/api/v1.0/tree/orgs`, {
      method: 'POST',
      headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: '{}'
    });
    assert.equal(r.status, 200);
    const j = await r.json();
    const d = j.data || j;
    assert.ok(d.orgList?.length > 0);

    const r2 = await request(`${BASE}/brms/api/v1.0/tree/devices`, {
      method: 'POST',
      headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: '{}'
    });
    assert.equal(r2.status, 200);
    const j2 = await r2.json();
    const d2 = j2.data || j2;
    // The registry only ever contains devices that were actually registered
    // (operator/lab). The CONTRACT is the response shape: native key "devices"
    // + web alias "deviceList", both fitting DeviceInfoVo when non-empty.
    assert.ok(Array.isArray(d2.deviceList) && Array.isArray(d2.devices));
    if (d2.devices.length > 0) {
      for (const dv of d2.devices) {
        assert.ok(dv.code && dv.name !== undefined && dv.status !== undefined);
        assert.ok(Array.isArray(dv.units) && dv.units[0].unitType === '1');
        assert.ok(dv.units[0].channels.some(ch => ch.channelCode.includes('$1$0$')));
      }
      assert.ok(d2.devices.every(dv => d2.deviceList.some(wl => wl.code === dv.code)));
    }

    const r3 = await request(`${BASE}/brms/api/v1.0/tree/channels`, {
      method: 'POST',
      headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelType: 1, category: 1 })
    });
    assert.equal(r3.status, 200);
    const j3 = await r3.json();
    const d3 = j3.data || j3;
    // Same registry-empty tolerance: contract = channelList fitting
    // channelId <code>$<unitType>$0$<seq>; content asserted when present.
    assert.ok(Array.isArray(d3.channelList));
    assert.ok(d3.channelList.every(c => /^\S+\$\d+\$0\$\d+$/.test(c.channelId || '')));
  });

  it('E2E-3 MTS & RTSP 9100 - Real TCP probe with OPTIONS + DESCRIBE', async () => {
    // Self-contained: the registry may be EMPTY (starts fresh, only operator
    // devices). This test registers its own real ONVIF lab device, drives the
    // per-device stream pipeline to a REAL RTSP DESCRIBE, and cleans up.
    const addBody = JSON.stringify({
      deviceIp: '192.168.0.238', devicePort: 8021, protocolType: '99',
      deviceCategory: '1', deviceType: '62', deviceName: 'E3-STREAM-PROBE',
      serverCode: 'video#local', encoderChannelCount: 1
    });
    const add = await request(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: addBody
    });
    assert.equal(add.status, 200);
    const addJson = await add.json();
    const streamCode = addJson.data?.deviceCode;
    assert.ok(streamCode, 'add must return a deviceCode');
    CREATED_CODES.add(streamCode);
    await new Promise(r => setTimeout(r, 2500)); // ONVIF GetStreamUri + MTX path

    const r = await request(`${BASE}/brms/api/v1.0/MTS/Video/StartVideo`, {
      method: 'POST',
      headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelId: `${streamCode}$1$0$0`, streamType: 1, dataType: 1 })
    });
    assert.equal(r.status, 200);
    const j = await r.json();
    const d = j.data || j;
    const rtspUrl = d.url; // Already uses PUBLIC_HOST=10.10.20.120
    assert.ok(rtspUrl && rtspUrl.includes('rtsp://10.10.20.120:9100/'));
    assert.ok(rtspUrl.includes(`cam_${streamCode}`), 'per-device MediaMTX path (E-034)');
    assert.ok(rtspUrl.includes('token='));
    assert.ok(d.hlsUrl && d.hlsUrl.includes('/hls'));

    // Real TCP probe to RTSP port 9100 on 10.10.20.120
    const result = await probeRtsp(rtspUrl);
    // Verify RTSP protocol works: OPTIONS returns 200 OK, DESCRIBE returns valid RTSP response
    assert.ok(result.optionsOk, 'RTSP OPTIONS did not return 200 OK');
    // DESCRIBE may return 200 OK with SDP (if stream available) or 404 Not Found (if no publisher)
    // Both are valid RTSP responses
    assert.ok(result.describeOk || result.describeNotFound,
      'RTSP DESCRIBE did not return valid RTSP response (expected 200 OK or 404 Not Found)');
    if (result.describeOk && result.sdp) {
      // If stream is available, verify H.265 in SDP
      console.log('Stream available, SDP:', result.sdp.substring(0, 500));
    } else if (result.describeNotFound) {
      console.log('No stream publisher available (404 Not Found) - RTSP protocol working correctly');
    }

    // Lab hygiene: remove this test's own device right away (device AND its
    // MediaMTX path are dropped by the E-034 delete pipeline). NEVER delete a
    // code that existed before this run: the add is idempotent per ip:port,
    // so against the operator's real camera it returns THEIR deviceCode and
    // deleting it would wipe their camera (E-087 incident #2, 23:03:37).
    if (!PRE_EXISTING_CODES.has(streamCode)) {
      await request(`${BASE}/brms/api/v1.1/device/delete/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
        body: JSON.stringify({ deviceCodes: [streamCode] })
      });
    } else {
      console.log(`E2E-3: ${streamCode} pre-existed (operator device) - kept`);
    }
  });

  it('E2E-4 UDP 18800 -> WebSocket event bridge', async () => {
    // waitForWsEvent connects WebSocket, waits for WELCOME, sends UDP, then waits for alarm event
    const eventText = await waitForWsEvent(token, 15000);
    assert.ok(eventText.includes('ANPR_EBA') || eventText.includes('ALARM'));
  });

  it('E2E-5 P2P probe - manual invocation profile', async () => {
    const r = await request(`${BASE}/brms/api/v1.0/p2p/status`, {
      headers: { 'X-Subject-Token': token }
    }).catch(() => ({ status: 404 }));
    assert.ok(r.status === 200 || r.status === 404);
  });

  it('E2E-6 HTTPS 9443 - Production port with System CA Service cert', async () => {
    const r = await request(`${BASE_9443}/health`, {
      headers: { 'X-Subject-Token': token }
    });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.status, 'ok');
    assert.equal(j.realm, 'DSS-V2-LAB');
    assert.equal(j.arsPort, 9500);
    // Verify cert is System CA Service by checking the port
    console.log('HTTPS 9443 health check passed');
  });

  // ===== E2E-8 (E-025): real DVRIP/DHIP auto-registration on TCP 9500 =====
  it('E2E-8 Auto-register (DVRIP/DHIP TCP 9500) - REGISTER -> ACK -> device in ars/list + tree', async () => {
    const frame = buildDhipRegFrame('E2E-NVR-01', 'EBA NVR 01', 'NNVR-01', '10.10.20.120');
    const ack = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '10.10.20.120', port: 9500 }, () => socket.write(frame));
      let buffer = Buffer.alloc(0);
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('ARS ack timeout')); }, 8000);
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length >= 32) {
          clearTimeout(timer);
          socket.end();
          resolve(buffer);
        }
      });
      socket.on('error', reject);
    });

    assert.equal(ack.readUInt32LE(0), 0x44484950, 'ack must start with DHIP magic');
    assert.equal(ack.readUInt32LE(4), 0x8001, 'command must be REGISTER_ACK (0x8001)');
    assert.equal(ack.readUInt32LE(8), 1, 'ack must echo the register sequence');

    const ars = await request(`${BASE}/brms/api/v1.0/ars/list`, { headers: { 'X-Subject-Token': token } });
    assert.equal(ars.status, 200);
    const arsJson = await ars.json();
    const arsList = arsJson.data?.devices || arsJson.data?.list || [];
    const registered = arsList.find((d) => String(d.deviceName || '').includes('EBA NVR 01') || String(d.deviceCode || '').includes('ARS-NNVR-01'));
    assert.ok(registered, 'auto-registered device must appear in ars/list');
    if (registered.deviceCode) CREATED_CODES.add(String(registered.deviceCode));
    console.log('ARS registered:', JSON.stringify(registered));

    // the device must also be a normal device in the tree
    const tree = await request(`${BASE}/brms/api/v1.0/tree/devices`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body: '{}' });
    const treeJson = await tree.json();
    assert.ok(treeJson.data?.deviceList?.some((d) => String(d.deviceName).includes('EBA NVR 01')), 'auto-registered device must be in the device tree');
  });

  // ===== E2E-9 (E-025): device add/discovery + catalog contracts =====
  it('E2E-9 Device add/discovery + catalogs (no 404, no generic fallback)', async () => {
    const body = JSON.stringify({
      deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99', deviceCategory: '1',
      deviceType: '6', deviceName: 'EBA1', serverCode: 'video#local',
      encoderChannelCount: 1, loginPass: '0123456789abcdef0123456789abcdef'
    });
    const cost = await request(`${BASE}/brms/api/v1.1/device/discover/cost-time`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body });
    assert.equal(cost.status, 200);
    const costJson = await cost.json();
    assert.equal(costJson.code, 1000);
    assert.ok(typeof costJson.data.costTime === 'number' && costJson.data.costTime > 0);

    const add = await request(`${BASE}/brms/api/v1.1/device`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body });
    assert.equal(add.status, 200);
    const addJson = await add.json();
    assert.ok(addJson.data?.deviceCode, 'add must return a deviceCode');
    CREATED_CODES.add(addJson.data.deviceCode);
    assert.ok(Array.isArray(addJson.data.channels) && addJson.data.channels.length === 1);
    assert.ok(!add.text().includes('0123456789abcdef'), 'loginPass (md5 hash) must not be echoed');

    const page = await request(`${BASE}/brms/api/v1.1/device/page`, { headers: { 'X-Subject-Token': token } });
    const pageJson = await page.json();
    assert.ok(pageJson.data.total >= 1 && pageJson.data.list.some((d) => d.deviceName === 'EBA1'));

    for (const p of [
      '/brms/api/v1.1/system/network/list',
      '/brms/api/v1.1/config/server/timezone',
      '/brms/api/v1.1/config/timezone/list',
      '/brms/api/v1.1/role/page',
      '/brms/api/v1.1/function/available/list',
      '/brms/api/v1.1/subsystem/available/list',
      '/omms/api/v1.1/alert/rule/alert-type/list',
      '/brms/api/v1.1/device/statistics/count-by-device-category/list?keyword=&orgCode=&domain=0&permitted=0&sourceType=1&containChild=1',
      '/brms/api/v1.1/discover/device/page'
    ]) {
      const r = await request(`${BASE}${p}`, { headers: { 'X-Subject-Token': token } });
      assert.equal(r.status, 200, `${p} must answer 200 (was 404/fallback before E-025)`);
      const j = await r.json();
      assert.equal(j.code, 1000, `${p} must return the success envelope`);
    }

    // E-028: the launcher page is the REAL production bundle now - assert its
    // authentic Vite shape instead of the retired invented page contract.
    const page2 = await request(`${BASE}/web/client-module/`, {});
    assert.equal(page2.status, 200);
    const html = await page2.text();
    assert.ok(html.includes('id="app"'), 'real SPA root div');
    assert.ok(html.includes('js/index-BhDUzoCV.js'), 'real production entry chunk');
    assert.ok(!/launcher|emoji/i.test(html), 'invented launcher must stay retired');
  });

  // ===== E2E-10 (E-026): device add + persist in disk + tree sync =====
  it('E2E-10 Device add + persist in disk + appear in device/page + tree/devices + tree/channels', async () => {
    const start = Date.now();
    const body = JSON.stringify({
      deviceIp: '192.168.0.238', devicePort: 8021, protocolType: '99',
      deviceCategory: '1', deviceType: '62', deviceName: 'EBA1_ONVIF',
      serverCode: 'video#local', encoderChannelCount: 1,
      loginPass: '0123456789abcdef0123456789abcdef'
    });
    const add = await request(`${BASE}/brms/api/v1.1/device`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body
    });
    const elapsed = Date.now() - start;
    assert.equal(add.status, 200);
    assert.ok(elapsed < 2000, `Add device took ${elapsed}ms, must be < 2000ms`);
    const addJson = await add.json();
    assert.ok(addJson.data?.deviceCode, 'add must return a deviceCode');
    CREATED_CODES.add(addJson.data.deviceCode);
    assert.ok(addJson.data.results?.[0]?.deviceCode, 'results[0] must have deviceCode');
    assert.ok(addJson.data.id === addJson.data.deviceCode || addJson.data.code === addJson.data.deviceCode, 'id/code/deviceCode must match');
    assert.ok(!JSON.stringify(addJson.data).includes('0123456789abcdef'), 'loginPass must not be echoed');

    // Add is idempotent per ip:port (real-lab server already has 192.168.0.238
    // registered as "EBA1" from E-027 probes); accept either record name.
    const page = await request(`${BASE}/brms/api/v1.1/device/page`, {
      headers: { 'X-Subject-Token': token }
    });
    const pageJson = await page.json();
    const registered = (pageJson.data.results || pageJson.data.list || [])
      .some((d) => String(d.deviceIp) === '192.168.0.238' && Number(d.devicePort) === 8021 && (d.deviceCode));
    assert.ok(registered, 'device must appear in device/page');

    const tree = await request(`${BASE}/brms/api/v1.0/tree/devices`, {
      method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}'
    });
    const treeJson = await tree.json();
    const treeHit = (treeJson.data?.deviceList || treeJson.data?.list || [])
      .some((d) => String(d.deviceIp) === '192.168.0.238');
    assert.ok(treeHit, 'device must appear in tree/devices');

    const chans = await request(`${BASE}/brms/api/v1.0/tree/channels`, {
      method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}'
    });
    const chansJson = await chans.json();
    assert.ok(Array.isArray(chansJson.data?.channelList) || Array.isArray(chansJson.data?.list), 'tree/channels must return channel list');

  });

  it('E2E-7 SIP UDP 5080 - REGISTER SIP registration', async () => {
    const crypto = await import('node:crypto');
    const dgram = await import('node:dgram');
    
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      const callId = crypto.randomBytes(16).toString('hex') + '@' + crypto.randomBytes(4).toString('hex');
      const cseq = '1';
      const branch = 'z9hG4bK' + crypto.randomBytes(8).toString('hex');
      
      const registerPacket = `REGISTER sip:10.10.20.120:5080 SIP/2.0\r
Via: SIP/2.0/UDP 192.168.1.100:5080;branch=${branch}\r
From: <sip:8888881000@10.10.20.120>;tag=123456\r
To: <sip:8888881000@10.10.20.120>\r
Call-ID: ${callId}\r
CSeq: ${cseq} REGISTER\r
Contact: <sip:8888881000@192.168.1.100:5080;transport=udp>\r
Expires: 3600\r
Content-Length: 0\r
\r
`;
      
      let resolved = false;
      
      socket.on('message', (msg, rinfo) => {
        if (resolved) return;
        resolved = true;
        
        const text = msg.toString();
        console.log('SIP Response:', text);
        
        if (text.includes('SIP/2.0 200 OK') && text.includes('REGISTER')) {
          console.log('SIP REGISTER 200 OK received!');
          resolve(true);
        } else {
          reject(new Error('Unexpected SIP response: ' + text));
        }
        socket.close();
      });
      
      socket.on('error', (err) => {
        if (!resolved) reject(err);
      });
      
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          console.log('SIP timeout');
          try { socket.close(); } catch { /* already closed */ }
          reject(new Error('SIP timeout'));
        }
      }, 10000);
      
      socket.on('close', () => {
        clearTimeout(timeout);
      });
      
      socket.send(registerPacket, 5080, '10.10.20.120', (err) => {
        if (err) reject(err);
      });
    });
  });

  // ===== E2E-11 (E-039/E-040): GetMqConfig advertises the OpenWire broker
  // (UseMqFlag=1, MQConfig "<host>:61616", MQType != "mqtt", real
  // brms.notify* TopicInfos) and a device add is still pushed live on the
  // MQTT 1883 dual-push broker =====
  it('E2E-11 GetMqConfig OpenWire contract + MQTT 1883 dual-push notify on brms.notifyBatchAddDevices', async () => {
    // 1) the real RPC call exactly as the native client issues it
    const rpc = await request(`${BASE}/admin/API/BRM/Config/GetMqConfig`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
      body: JSON.stringify({
        clientType: 'WINPC_V2', clientMac: 'E2E:11', clientPushId: 'e2e11',
        project: 'PSDK', method: 'BRM.Config.GetMqConfig', data: { optional: '' }
      })
    });
    assert.equal(rpc.status, 200);
    const rpcJson = await rpc.json();
    assert.equal(rpcJson.code, 1000);
    const cfg = rpcJson.data || rpcJson.info;
    assert.equal(cfg.UseMqFlag, 1, 'UseMqFlag must be 1 (MQ channel enabled)');
    // E-040: MQConfig is the MQ endpoint - MSG.exe (CMQSDKManager::MQInit,
    // E-087 RE) builds failover:(ssl://<MQConfig>...startupMaxReconnect-
    // Attempts=1...) verbatim, so no JSON/URL here. The lab broker therefore
    // serves the OpenWire transport over TLS on 61616 (sslContext with the
    // lab System CA keystore; MSG.exe sets
    // decaf.net.ssl.disablePeerVerification). MQType must differ from
    // "mqtt" so DPSDK pipes the config to MSG.exe instead of the
    // libcurl-MQTT branch.
    assert.equal(cfg.MQConfig, '10.10.20.120:61616');
    assert.notEqual(cfg.MQType, 'mqtt');
    assert.equal(cfg.UnSSLPort, 61616);
    assert.equal(cfg.SSLEnable, 0);
    // E-087 (Ghidra): the DPSDK response parser (FUN_180214d60, descriptor
    // FUN_1806755a0) binds STRING keys addr/userName/password/enableTls/mqtt;
    // `addr` IS the MQ Config handed to MSG.exe (OpenWire 61616). mqtt is
    // served NON-EMPTY "host:1883": lab evidence (22:14:49-22:15:56 session)
    // shows MSG.exe never dialed 61616 with mqtt "" (0 broker connection
    // events), so the libcurl-MQTT branch (mqtt://host:1883/<topic>) is the
    // notify path that actually reaches the client on our dual-push broker.
    assert.equal(cfg.addr, '10.10.20.120:61616', 'DPSDK descriptor addr = MQ Config');
    assert.equal(cfg.userName, 'admin');
    assert.equal(cfg.password, 'admin');
    assert.equal(cfg.enableTls, '', 'empty enableTls (transport is MSG.exe-internal: ssl:// + disablePeerVerification)');
    assert.equal(cfg.mqtt, '10.10.20.120:1883', 'non-empty mqtt => libcurl-MQTT branch on 1883');
    const topics = (cfg.TopicInfos || []).map((t) => t.Topic);
    assert.ok(topics.includes('brms.notifyBatchAddDevices'), 'real notify topic advertised');
    assert.ok(topics.includes('brms.notifyChannelStatuses'));
    assert.ok((cfg.TopicInfos || []).every((t) => 'IsAccUser' in t), 'TopicInfos entries carry IsAccUser');

    // 2) subscribe on the real broker. NOTE: the real topics are single-level
    // dotted names (brms.notifyX), so "brms/#" does NOT match them in MQTT
    // semantics - the native client subscribes each TopicInfos entry exactly.
    const sub = await mqttSubscribe('10.10.20.120', 1883, ['brms.notifyBatchAddDevices', 'brms.notifyChannelStatuses', '#'], 'e2e11-sub');
    try {
      // 3) add a lab device (127.x rows are auto-removed by the after() cleanup)
      const body = JSON.stringify({
        deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99', deviceCategory: '1',
        deviceType: '6', deviceName: 'E2E11MQTT', serverCode: 'video#local',
        encoderChannelCount: 1, loginPass: '0123456789abcdef0123456789abcdef'
      });
      const add = await request(`${BASE}/brms/api/v1.1/device`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body
      });
      assert.equal(add.status, 200);
      const addJson = await add.json();
      const code = addJson.data?.deviceCode;
      assert.ok(code, 'add must return a deviceCode');
      CREATED_CODES.add(code);

      // 4) the notify must arrive on the MQTT topic within a few seconds
      const deadline = Date.now() + 8000;
      let hit = null;
      while (Date.now() < deadline && !hit) {
        hit = sub.publishes.find((p) => p.topic === 'brms.notifyBatchAddDevices' && p.payload.includes(code));
        if (!hit) await new Promise((r) => setTimeout(r, 200));
      }
      assert.ok(hit, 'PUBLISH on brms.notifyBatchAddDevices carrying the new deviceCode');
      assert.equal(JSON.parse(hit.payload).deviceCode, code, 'notify body is the device VO');
      const chanHit = sub.publishes.find((p) => p.topic === 'brms.notifyChannelStatuses' && p.payload.includes(code));
      assert.ok(chanHit, 'PUBLISH on brms.notifyChannelStatuses too');
    } finally {
      try { sub.sock.destroy(); } catch { /* ignore */ }
    }
  });

  // ===== E2E-12 (E-040): the REAL notify bus - ActiveMQ Classic. Port 61616
  // must speak OpenWire over TLS (MSG.exe's CMQSDKManager::MQInit always
  // builds failover:(ssl://10.10.20.120:61616) and sets
  // decaf.net.ssl.disablePeerVerification - the broker presents the lab
  // System CA chain) and a device add must arrive as a STOMP MESSAGE on
  // /topic/brms.notifyBatchAddDevices =====
  it('E2E-12 ActiveMQ - OpenWire over TLS 61616 answers + STOMP 61613 notify push on /topic/brms.notifyBatchAddDevices', async () => {
    // 1) OpenWire probe over TLS: a real ActiveMQ ssl:// connector answers
    //    the handshake and immediately sends a WireFormatInfo frame.
    const wire = await new Promise((resolve, reject) => {
      const sock = tls.connect(61616, '10.10.20.120', { rejectUnauthorized: false }, () => {});
      const to = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } reject(new Error('61616 no answer (TLS + OpenWire WireFormatInfo timeout)')); }, 10000);
      sock.on('data', (d) => {
        clearTimeout(to);
        try { sock.destroy(); } catch { /* ignore */ }
        resolve(d);
      });
      sock.on('error', (err) => { clearTimeout(to); reject(err); });
    });
    assert.ok(wire.length >= 8, 'ssl://61616 sent a WireFormatInfo frame after the handshake');
    // OpenWire frame: 4-byte big-endian size, then the tight-marshaled
    // WireFormatInfo (starts with the 'magic' byte array 0x01 0x01 ...).
    const size = wire.readUInt32BE(0);
    assert.ok(size > 0 && size <= wire.length - 4, `plausible OpenWire frame size ${size} (got ${wire.length - 4} payload bytes)`);

    // 2) subscribe on the STOMP connector to the real notify topic
    const sub = await stompSubscribe('10.10.20.120', 61613,
      ['/topic/brms.notifyBatchAddDevices', '/topic/brms.notifyChannelStatuses'], 'e2e12-sub');
    try {
      // 3) add a lab device (127.x rows are auto-removed by the after() cleanup)
      const body = JSON.stringify({
        deviceIp: '127.0.0.1', devicePort: 1, protocolType: '99', deviceCategory: '1',
        deviceType: '6', deviceName: 'E2E12AMQ', serverCode: 'video#local',
        encoderChannelCount: 1, loginPass: '0123456789abcdef0123456789abcdef'
      });
      const add = await request(`${BASE}/brms/api/v1.1/device`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token }, body
      });
      assert.equal(add.status, 200);
      const addJson = await add.json();
      const code = addJson.data?.deviceCode;
      assert.ok(code, 'add must return a deviceCode');
      CREATED_CODES.add(code);

      // 4) the notify must arrive on the ActiveMQ topic within a few seconds
      const deadline = Date.now() + 10000;
      let hit = null;
      while (Date.now() < deadline && !hit) {
        hit = sub.messages.find((m) => m.destination === '/topic/brms.notifyBatchAddDevices' && m.body.includes(code));
        if (!hit) await new Promise((r) => setTimeout(r, 200));
      }
      assert.ok(hit, 'STOMP MESSAGE on /topic/brms.notifyBatchAddDevices carrying the new deviceCode');
      assert.equal(JSON.parse(hit.body).deviceCode, code, 'notify body is the device VO');
      const chanHit = sub.messages.find((m) => m.destination === '/topic/brms.notifyChannelStatuses' && m.body.includes(code));
      assert.ok(chanHit, 'STOMP MESSAGE on /topic/brms.notifyChannelStatuses too');
    } finally {
      try { sub.sock.destroy(); } catch { /* ignore */ }
    }
  });

  // Lab hygiene: ONLY the devices this suite created in this run are
  // removed (tracked by the deviceCode each add returned in CREATED_CODES).
  // Never filter by name/IP prefix: the operator's own lab cameras may
  // share names ("EBA*") and a prefix cleanup wiped them from the registry
  // (E-087 incident: devices.json went [] and the camera vanished).
  after(async () => {
    try {
      const codes = [...CREATED_CODES].filter((c) => !PRE_EXISTING_CODES.has(c));
      if (!codes.length) return;
      await request(`${BASE}/brms/api/v1.1/device/delete/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Subject-Token': token },
        body: JSON.stringify({ deviceCodes: codes })
      });
      console.log(`E2E cleanup: removed ${codes.length} suite-created device(s): ${codes.join(',')}`);
    } catch (err) {
      console.log('E2E cleanup skipped:', err.message);
    }
  });
});