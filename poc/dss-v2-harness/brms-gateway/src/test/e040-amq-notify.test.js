// E-040: STOMP 1.2 publisher to ActiveMQ + E-041 persistent org store.
// Pure module tests (fake STOMP server on ephemeral ports, no fixed ports,
// no spawned gateway -> no clash with brms.test.js). The org-store seed write
// (data/orgs.json) is idempotent content, same as the gateway startup seed.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createStompPublisher } from '../e040-amq-notify.js';
import {
  listOrgs,
  getOrg,
  deviceOrgCode,
  DEFAULT_ORG_CODE,
  ROOT_ORG
} from '../e041-orgs.js';
import { buildNativeOrgTreePayload } from '../e037-native-tree.js';
// In-memory registry only (no persistDevice -> no devices.json write race).
import { DEVICE_REGISTRY } from '../e025-devices.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Minimal fake STOMP 1.2 broker: parses NULL-terminated frames, answers
// CONNECTED to CONNECT, records every frame.
function startFakeStomp() {
  const frames = [];
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf(0);
        if (end === -1) break;
        const raw = buf.subarray(0, end).toString('utf8');
        buf = buf.subarray(end + 1);
        const nl = raw.indexOf('\n');
        if (nl === -1) continue;
        const cmd = raw.slice(0, nl);
        const hend = raw.indexOf('\n\n', nl);
        if (hend === -1) continue;
        const headers = {};
        for (const line of raw.slice(nl + 1, hend).split('\n')) {
          const c = line.indexOf(':');
          if (c > 0) headers[line.slice(0, c)] = line.slice(c + 1);
        }
        frames.push({ cmd, headers, body: raw.slice(hend + 2) });
        if (cmd === 'CONNECT') {
          sock.write(Buffer.from('CONNECTED\nversion:1.2\nsession:fake-1\n\n\0', 'utf8'));
        }
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, frames, port: server.address().port }));
  });
}

async function reservePort() {
  const s = net.createServer();
  return new Promise((resolve) => {
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

describe('E-040 STOMP publisher (ActiveMQ notify bus)', { timeout: 20000 }, () => {
  it('CONNECT -> CONNECTED, publish -> SEND frame with destination + JSON body + content-length', async () => {
    const fake = await startFakeStomp();
    const pub = createStompPublisher({ host: '127.0.0.1', port: fake.port, login: 'admin', passcode: 'admin', reconnectMs: 100 });
    pub.start();
    try {
      const deadline = Date.now() + 5000;
      while (!pub.isConnected() && Date.now() < deadline) await sleep(50);
      assert.ok(pub.isConnected(), 'publisher must reach CONNECTED');
      const body = JSON.stringify({ deviceCode: 'AMQTEST01', deviceName: 'lab' });
      assert.equal(pub.publish('/topic/brms.notifyBatchAddDevices', body), true);
      await sleep(150);
      const connect = fake.frames.find((f) => f.cmd === 'CONNECT');
      assert.ok(connect, 'CONNECT frame sent');
      assert.equal(connect.headers['accept-version'], '1.2');
      assert.equal(connect.headers.login, 'admin');
      const send = fake.frames.find((f) => f.cmd === 'SEND');
      assert.ok(send, 'SEND frame sent after CONNECTED');
      assert.equal(send.headers.destination, '/topic/brms.notifyBatchAddDevices');
      assert.equal(send.headers['content-type'], 'application/json');
      assert.equal(Number(send.headers['content-length']), Buffer.byteLength(body));
      assert.equal(send.body, body);
    } finally {
      pub.close();
      fake.server.close();
    }
  });

  it('queues while the broker is down and flushes on reconnect', async () => {
    const port = await reservePort(); // nothing listens here yet
    const pub = createStompPublisher({ host: '127.0.0.1', port, reconnectMs: 100 });
    pub.start();
    await sleep(200);
    assert.equal(pub.isConnected(), false);
    const body = JSON.stringify({ deviceCode: 'AMQQUEUE1' });
    assert.equal(pub.publish('/topic/brms.notifyChannelStatuses', body), false, 'queued, not sent');
    assert.equal(pub.queued(), 1);
    // bring the broker up on that port -> reconnect -> flush
    const frames = [];
    const server = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        for (;;) {
          const end = buf.indexOf(0);
          if (end === -1) break;
          const raw = buf.subarray(0, end).toString('utf8');
          buf = buf.subarray(end + 1);
          const nl = raw.indexOf('\n');
          if (nl > 0 && raw.slice(0, nl) === 'CONNECT') {
            frames.push('CONNECT');
            sock.write(Buffer.from('CONNECTED\nversion:1.2\n\n\0', 'utf8'));
          } else if (nl > 0 && raw.slice(0, nl) === 'SEND') {
            frames.push(raw);
          }
        }
      });
      sock.on('error', () => {});
    });
    await new Promise((res) => server.listen(port, '127.0.0.1', res));
    try {
      const deadline = Date.now() + 6000;
      while (Date.now() < deadline && !frames.some((f) => f.startsWith('SEND'))) await sleep(100);
      assert.ok(pub.isConnected(), 'reconnected after broker came up');
      assert.equal(pub.queued(), 0, 'queue flushed');
      const send = frames.find((f) => f.startsWith('SEND'));
      assert.ok(send.includes('destination:/topic/brms.notifyChannelStatuses'), 'SEND carries the topic destination');
      assert.ok(send.includes(body), 'SEND carries the queued body');
    } finally {
      pub.close();
      server.close();
    }
  });
});

describe('E-041 persistent org store (VIGILAB)', () => {
  it('seeds root 001 + VIGILAB and never returns an empty org list', () => {
    const orgs = listOrgs();
    assert.ok(orgs.some((o) => o.code === ROOT_ORG.code), 'root org 001 present');
    assert.ok(orgs.some((o) => o.code === DEFAULT_ORG_CODE && o.name === 'VIGILAB'), 'VIGILAB present');
    assert.equal(getOrg('VIGILAB').parentCode, '001');
  });

  it('deviceOrgCode falls back to VIGILAB on empty orgCode (attempt-2 bug)', () => {
    assert.equal(deviceOrgCode({ orgCode: '' }), 'VIGILAB');
    assert.equal(deviceOrgCode({}), 'VIGILAB');
    assert.equal(deviceOrgCode({ orgCode: '001' }), '001');
  });

  it('native org tree lists one OrgNodeVo per persisted org, devices under their org', () => {
    const code = 'E041TREE01';
    DEVICE_REGISTRY.set(code, {
      deviceCode: code, deviceId: code, deviceName: 'E041 lab', deviceIp: '127.0.0.9', devicePort: 9999,
      deviceType: '1', deviceCategory: '1', protocolType: '99', orgCode: '', channelNum: 1, online: true
    });
    try {
      const payload = buildNativeOrgTreePayload();
      const codes = payload.departments.map((d) => d.code);
      assert.ok(codes.includes('001') && codes.includes('VIGILAB'), `departments carry orgs: ${codes}`);
      const vig = payload.departments.find((d) => d.code === 'VIGILAB');
      assert.ok(vig.device.some((x) => x.id === code), 'device with empty orgCode lands under VIGILAB');
      assert.ok(vig.channel.some((c) => c.id === `${code}$1$0$0`), 'channel ids under VIGILAB too');
      const root = payload.departments.find((d) => d.code === '001');
      assert.ok(root, 'root node still present');
      // E-087: the DPSDK org-tree parser (FUN_180718860) builds the hierarchy
      // by parentCode; isParent/deparmentsCount must mark '001' expandable so
      // VIGILAB is reachable in the native tree.
      assert.equal(root.deparmentsCount, '1', "root '001' reports its VIGILAB child");
      assert.ok(root.isParent, "root '001' is expandable");
      assert.ok(root.hasChild, "root '001' carries hasChild (DPSDK tree parser key)");
      assert.equal(vig.deparmentsCount, '0', 'VIGILAB is a leaf');
      assert.ok(!vig.isParent, 'VIGILAB not expandable');
      assert.ok(!vig.hasChild, 'VIGILAB hasChild=false');
    } finally {
      DEVICE_REGISTRY.delete(code); // in-memory only, no disk write
    }
  });
});
