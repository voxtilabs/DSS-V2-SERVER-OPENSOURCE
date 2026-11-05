// E-039: MQTT notify broker + device-change hub + tree `id` fix.
// Pure module tests (no spawned server, no fixed ports -> no clashes with
// brms.test.js, which spawns the gateway on 11443). IMPORTANT: this file
// must NOT write data/devices.json - node --test runs files in parallel
// processes and a disk write here races the server spawned by brms.test.js.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {
  createMqttBroker,
  createNotifyHub,
  buildMqConfigPayload,
  buildClientNotifyEnvelope,
  buildClientNotifyEnvelopes,
  clientMqTopics,
  MQ_TOPICS,
  TOPIC_BATCH_ADD_DEVICES,
  TOPIC_CHANNEL_STATUSES
} from '../e039-mq-notify.js';
import { buildGradeDeviceTreePayload } from '../e029-spa-contracts.js';
// DEVICE_REGISTRY is mutated in memory only; persistDevice() would call
// saveDevicesToDisk() and race the parallel brms.test.js server.
import { DEVICE_REGISTRY } from '../e025-devices.js';

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
// Read one MQTT packet from a buffer; returns {type, flags, body, rest}.
function readPacket(buf) {
  const type = buf[0] >> 4, flags = buf[0] & 0x0f;
  let mult = 1, len = 0, i = 1;
  for (;;) { const byte = buf[i++]; len += (byte & 0x7f) * mult; mult *= 128; if (!(byte & 0x80)) break; }
  return { type, flags, body: buf.subarray(i, i + len), rest: buf.subarray(i + len) };
}

// Connect + CONNECT/CONNACK handshake. The CONNACK is consumed here so the
// returned `take()` only yields packets that arrive AFTER the handshake.
function connectClient(port, clientId) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      const body = Buffer.concat([
        mqttString('MQTT'), Buffer.from([4, 0x02]), Buffer.from([0, 60]), mqttString(clientId)
      ]);
      sock.write(mqttPacket(1, 0, body));
    });
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4 && buf[0] === 0x20) {
        const connack = readPacket(buf);
        assert.equal(connack.type, 2, 'CONNACK expected');
        buf = connack.rest;
        resolve({ sock, take: () => { const p = readPacket(buf); buf = p.rest; return p; }, pending: () => buf.length });
      }
    });
    sock.on('error', reject);
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('E-039 MQTT notify broker', { timeout: 20000 }, () => {
  let broker;
  let port;
  before(async () => {
    broker = createMqttBroker();
    const addr = await broker.listen(0, '127.0.0.1'); // ephemeral port, one listen per broker
    port = addr.port;
  });
  after(() => { if (broker) broker.close(); });

  it('CONNECT->CONNACK, SUBSCRIBE->SUBACK, PUBLISH delivered with topic+body, PINGREQ->PINGRESP', async () => {
    const client = await connectClient(port, 'test-sub');
    // SUBSCRIBE to the real notify topic
    const pid = 0x0007;
    const subBody = Buffer.concat([Buffer.from([0, pid]), mqttString(TOPIC_BATCH_ADD_DEVICES), Buffer.from([0])]);
    client.sock.write(mqttPacket(8, 2, subBody));
    await sleep(100);
    const suback = client.take();
    assert.equal(suback.type, 9, 'SUBACK expected');
    assert.deepEqual([...suback.body.subarray(2)], [0]);
    // broker publishes a device event
    const payload = JSON.stringify({ deviceCode: 'TESTMQ01', deviceName: 'lab' });
    const delivered = broker.publish(TOPIC_BATCH_ADD_DEVICES, payload);
    assert.ok(delivered >= 1, 'at least one subscriber must receive it');
    await sleep(100);
    const pub = client.take();
    assert.equal(pub.type, 3, 'PUBLISH expected');
    const tlen = pub.body.readUInt16BE(0);
    assert.equal(pub.body.toString('utf8', 2, 2 + tlen), TOPIC_BATCH_ADD_DEVICES);
    assert.equal(pub.body.toString('utf8', 2 + tlen), payload);
    // PINGREQ -> PINGRESP
    client.sock.write(mqttPacket(12, 0, Buffer.alloc(0)));
    await sleep(100);
    const ping = client.take();
    assert.equal(ping.type, 13, 'PINGRESP expected');
    client.sock.destroy();
  });

  it('wildcard + matches one level and # matches across levels', async () => {
    const c = await connectClient(port, 'wild');
    c.sock.write(mqttPacket(8, 2, Buffer.concat([Buffer.from([0, 9]), mqttString('brms/+/x'), Buffer.from([0])])));
    c.sock.write(mqttPacket(8, 2, Buffer.concat([Buffer.from([0, 10]), mqttString('brms/#'), Buffer.from([0])])));
    await sleep(100);
    c.take(); c.take(); // two SUBACKs
    broker.publish('brms/notify/x', 'a');   // matches both filters -> one frame per socket
    broker.publish('brms/a/b/c', 'b');       // matches only brms/#
    broker.publish('other/topic', 'c');      // matches neither -> not delivered
    await sleep(100);
    const p1 = c.take(), p2 = c.take();
    assert.equal(p1.type, 3);
    assert.equal(p2.type, 3);
    const t1 = p1.body.readUInt16BE(0);
    const t2 = p2.body.readUInt16BE(0);
    assert.equal(p1.body.toString('utf8', 2, 2 + t1), 'brms/notify/x');
    assert.equal(p2.body.toString('utf8', 2, 2 + t2), 'brms/a/b/c');
    assert.equal(c.pending(), 0, 'exactly two PUBLISH frames expected');
    c.sock.destroy();
  });
});

describe('E-039/E-040 GetMqConfig payload (real TopicInfos, OpenWire MQConfig)', () => {
  it('serves UseMqFlag=1, MQType != mqtt, PLAIN host:61616 MQConfig and every real brms.notify* topic', () => {
    // E-040: MSG.exe builds failover:(tcp://<MQConfig>) with the string
    // verbatim, so MQConfig must be plain "host:port" (OpenWire 61616), and
    // MQType must NOT be "mqtt" (that selects the libcurl-MQTT branch in
    // DPSDK.dll; anything else pipes the config to MSG.exe -> OpenWire).
    const cfg = buildMqConfigPayload({ publicHost: '10.10.20.120', amqPort: 61616, enabled: true });
    assert.equal(cfg.UseMqFlag, 1);
    assert.notEqual(cfg.MQType, 'mqtt');
    assert.equal(cfg.MQConfig, '10.10.20.120:61616', 'MQConfig is plain host:port, not JSON/URL');
    assert.equal(cfg.UnSSLPort, 61616);
    assert.equal(cfg.SSLEnable, 0, 'tcp:// not ssl:// (SSLEnable flag in MQInit)');
    // E-087 (Ghidra): DPSDK GetMQConfig (FUN_180214d60) binds STRING keys
    // password/addr/mqtt/enableTls/userName (descriptor FUN_1806755a0) -
    // `addr` IS the MQ Config the client hands to MSG.exe. mqtt non-empty
    // ("host:1883") selects the libcurl-MQTT branch: the client subscribes
    // directly on our 1883 broker (lab: MSG.exe never dialed 61616, so the
    // pipe path left the client without notifies -> "Operation timed out").
    assert.equal(cfg.addr, '10.10.20.120:61616', 'DPSDK descriptor key addr = MQ Config');
    assert.equal(cfg.userName, 'admin');
    assert.equal(cfg.password, 'admin');
    assert.equal(cfg.enableTls, '', 'empty enableTls (transport is MSG.exe-internal: ssl:// + disablePeerVerification)');
    assert.equal(cfg.mqtt, '10.10.20.120:1883', 'non-empty mqtt => libcurl-MQTT branch on the dual-push broker');
    const topics = cfg.TopicInfos.map((t) => t.Topic);
    for (const t of MQ_TOPICS) assert.ok(topics.includes(t), `missing ${t}`);
    assert.ok(topics.includes(TOPIC_BATCH_ADD_DEVICES));
    assert.ok(topics.includes(TOPIC_CHANNEL_STATUSES));
    assert.ok(cfg.TopicInfos.every((t) => Object.prototype.hasOwnProperty.call(t, 'IsAccUser')));
  });

  it('MQ_ENABLE=0 path returns UseMqFlag 0', () => {
    const cfg = buildMqConfigPayload({ publicHost: 'h', amqPort: 61616, enabled: false });
    assert.equal(cfg.UseMqFlag, 0);
  });
});

describe('E-039/E-040 notify hub fans out to WS + MQTT + ActiveMQ topics', () => {
  it('deviceEvent sends dual-shape WS frames and publishes to MQTT and STOMP topics', () => {
    const sent = [];
    const fakeWs = { readyState: 1, send: (m) => sent.push(JSON.parse(m)) };
    const published = [];
    const amqPublished = [];
    const hub = createNotifyHub({
      wsClients: new Set([fakeWs]),
      mqttPublish: (t, b) => published.push([t, b]),
      amqPublish: (t, b) => amqPublished.push([t, b])
    });
    hub.deviceEvent('DEVICE_ADDED', { deviceCode: 'HUB01', deviceName: 'hub lab' });
    assert.equal(sent.length, 2, 'flat + envelope WS frames');
    assert.equal(sent[0].type, 'DEVICE_ADDED');
    assert.equal(sent[0].deviceCode, 'HUB01');
    assert.equal(sent[1].eventType, 'DEVICE_ADDED');
    assert.equal(sent[1].data.deviceCode, 'HUB01');
    assert.deepEqual(published.map((p) => p[0]), [TOPIC_BATCH_ADD_DEVICES, TOPIC_CHANNEL_STATUSES]);
    assert.ok(JSON.parse(published[0][1]).deviceCode === 'HUB01');
    // E-040: same two topics on the ActiveMQ bus (destination carries /topic/)
    assert.deepEqual(amqPublished.slice(0, 2).map((p) => p[0]), [TOPIC_BATCH_ADD_DEVICES, TOPIC_CHANNEL_STATUSES]);
    assert.ok(JSON.parse(amqPublished[0][1]).deviceCode === 'HUB01');
    // E-088: the native client (MSG.exe) listens on the mq.*.msg.topic pool,
    // NOT on brms.notify* (ConsumerCount=0 there, live Jolokia evidence) - the
    // method envelope must also go to every mq.* topic (bare + UserId).
    const mqPubs = amqPublished.slice(2);
    // E-092: 3 method envelopes x every mq.* topic (bare + UserId suffix)
    assert.equal(mqPubs.length, 3 * clientMqTopics('1').length);
    const topics = mqPubs.map((p) => p[0]);
    const firstWave = mqPubs.slice(0, clientMqTopics('1').length);
    for (const t of firstWave) assert.ok(topics.includes(t[0]));
    const byMethod = new Map();
    for (const [, b] of mqPubs) {
      const env = JSON.parse(b);
      // E-091: ParseMQMsg (FUN_1800306b0) requires root keys "method" AND
      // "info"; handlers receive root["info"] (dispatcher FUN_180030ed0).
      assert.ok(env.info && typeof env.info === 'object', 'root.info object required by ParseMQMsg gate');
      assert.ok(!('params' in env), 'params is never read on the MQ path');
      if (!byMethod.has(env.method)) byMethod.set(env.method, env);
    }
    // tree push: vms.LogicOrgChannel op=1 with CHANNEL codes (<code>$1$0$<seq>)
    const loc = byMethod.get('vms.LogicOrgChannel');
    assert.ok(loc, 'vms.LogicOrgChannel envelope present');
    assert.equal(loc.info.operation, 1);
    assert.deepEqual(loc.info.addChannels, ['HUB01$1$0$0']);
    // device node: vms.addDev with full VO
    const addDev = byMethod.get('vms.addDev');
    assert.ok(addDev, 'vms.addDev envelope present');
    assert.equal(addDev.info.code, 'HUB01');
    assert.equal(addDev.info.channels[0].channelId, 'HUB01$1$0$0');
    // result ACK: brms.batchAddDevices info={session,successfulCount,failedCount}
    const ack = byMethod.get('brms.batchAddDevices');
    assert.ok(ack, 'brms.batchAddDevices ACK present');
    assert.equal(ack.info.successfulCount, 1);
    assert.equal(ack.info.failedCount, 0);
    assert.ok('session' in ack.info);
  });

  it('E-092 envelope: DEVICE_DELETED maps to vms.LogicOrgChannel op=3 + vms.deleteDev', () => {
    const envs = buildClientNotifyEnvelopes('DEVICE_DELETED', { deviceCode: 'X1', orgCode: 'VIGILAB', channelNum: 2 }).map((s) => JSON.parse(s));
    const loc = envs.find((e) => e.method === 'vms.LogicOrgChannel');
    assert.equal(loc.info.operation, 3);
    assert.deepEqual(loc.info.deleteChannels, ['X1$1$0$0', 'X1$1$0$1']);
    assert.equal(loc.info.deleteOrgCode, 'VIGILAB');
    const del = envs.find((e) => e.method === 'vms.deleteDev');
    assert.equal(del.info.devices[0].deviceCode, 'X1');
    assert.equal(del.info.devices[0].orgCode, 'VIGILAB');
  });
});

describe('E-039 grade-device-tree rows carry id (fix for devices:[null])', () => {
  const code = 'E039TEST01';
  after(() => { DEVICE_REGISTRY.delete(code); }); // in-memory only, no disk write

  it('device/channel/org nodes expose id equal to their code', () => {
    DEVICE_REGISTRY.set(code, {
      deviceCode: code, deviceId: code, deviceName: 'E039 lab', deviceIp: '127.0.0.9', devicePort: 9999,
      deviceType: '1', deviceCategory: '1', protocolType: '99', orgCode: '001', channelNum: 1, online: true
    });
    const payload = buildGradeDeviceTreePayload({ orgCode: '001', treeType: '2', domain: '1' });
    const dev = payload.devices.find((d) => d.deviceCode === code);
    assert.ok(dev, 'lab device present');
    assert.equal(dev.id, code, 'device row must carry id (live bug: devices:[null])');
    assert.ok(dev.channels.length >= 1);
    assert.equal(dev.channels[0].id, dev.channels[0].channelId, 'channel row must carry id');
    const all = buildGradeDeviceTreePayload({ orgCode: '999' });
    const root = all.organizations.find((o) => o.orgCode === '001');
    assert.ok(root, 'root org listed when querying another org');
    assert.equal(root.id, '001', 'org row must carry id');
  });
});
