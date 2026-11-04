// ===== E-039: device-change push channel (real contract, zero invention) =====
//
// Evidence (string pools, not guesses):
// - Client DPSDK.dll 0xc40450 window: GetMqConfig response keys are
//   TopicInfos (entries parsed with keys "Topic" + "IsAccUser"), MQConfig,
//   MQUser, MQPwd, UserId, GroupId, SSLEnable, UnSSLPort, CertificatePath,
//   ProtocolVersion, UseMqFlag, MQType, MQMessage, httpsMode.
// - PROLogic.dll 0x62f7b0 window: MQType values "stomp" | "amqp" | "mqtt",
//   with MQConfig inner keys "addr", "enableTls", "wss".
// - Topic names (identical pools in client DPSDK.dll 0xc71390-0xc745f0 and
//   server PROLogic.dll 0x709d60-0x70d0f8), e.g. brms.notifyBatchAddDevices is
//   the device-add notification topic; brms.notifyChannelStatuses the
//   channel-status one.
// - Client uses curl MQTT ("meta:proto:mqtt:conn", "No MQTT topic found.
//   Forgot to URL encode it?") => MQConfig addr is an mqtt:// URL and MQTT
//   3.1.1 is the implementable wire protocol (no ActiveMQ broker needed).
//
// This module implements a minimal MQTT 3.1.1 broker (CONNECT/SUBSCRIBE/
// PUBLISH/PINGREQ/DISCONNECT, QoS 0/1, + and # wildcards) plus a notify hub
// that fans device mutations out to the WS event stream AND the MQ topics.

import net from 'node:net';

export const MQ_TOPICS = [
  'brms.notifyAlarms',
  'brms.notifyBatchAddDevices',
  'brms.notifyChannelStatuses',
  'brms.notifyChannelCapabilities',
  'brms.notifyDeviceSipStatus',
  'brms.notifyDeviceSleepRequest',
  'brms.notifyFaceInfos',
  'brms.notifyHumanInfos',
  'brms.notifyNonVehicleInfos',
  'brms.notifyVehicleInfos',
  'brms.notifyPasswordOverDate',
  'brms.notifyLicenseInvalid',
  'brms.notifyAcsEvents',
  'brms.notifyLiftEvents',
  'brms.notifyOutsideDatabaseErrorInfo',
  'brms.device.notifyDiscoverAndUpdateDeviceResult',
  'brms.device.batchDiscoverDevices',
  'brms.batchAddDevices'
];
export const TOPIC_BATCH_ADD_DEVICES = 'brms.notifyBatchAddDevices';
export const TOPIC_CHANNEL_STATUSES = 'brms.notifyChannelStatuses';

// GetMqConfig data payload. TopicInfos entries use the real parser keys
// ("Topic", "IsAccUser"); dual-key strategy like the rest of the RPC layer.
//
// E-040 (production evidence): the real notify bus of the native client is
// ActiveMQ OpenWire on 61616, NOT MQTT:
// - pcap prod: client -> server:61616 TLS+OpenWire, zero traffic on 1883.
// - MSG.exe MQInit builds failover:(ssl://%s)?... (E-087 RE: ssl format at
//   0x1f6458, tcp fallback exists but the lab never saw tcp; MQConfig is
//   consumed VERBATIM => must be plain "host:port") with
//   decaf.net.ssl.disablePeerVerification => broker serves OpenWire over TLS.
// E-087 (Ghidra RE, DPSDK.dll confirmed): Dpsdk::CRestLogicalImplPro::
// GetMQConfig (FUN_180214d60) parses the response with the descriptor of
// FUN_1806755a0 (DAT_180f76610) - five STRING keys at offsets 0/8/0x10/0x18/
// 0x20 = "password", "addr", "mqtt", "enableTls", "userName". The "MQ Config"
// printed by "GetMQConfig PSDKAPI_REQUEST is success, MQ Config is %s..." is
// the `addr` field. The pipe->MSG.exe (OpenWire) path is taken when `mqtt`
// is EMPTY; the libcurl-MQTT branch only on a non-empty mqtt value.
// So BOTH key families are served: the legacy parser keys (MQConfig/MQType/
// UseMqFlag/MQUser/MQPwd/SSLEnable/UnSSLPort/ProtocolVersion/TopicInfos) AND
// the actual descriptor keys addr/userName/password/enableTls/mqtt.
export function buildMqConfigPayload({ publicHost, amqPort = 61616, enabled }) {
  const mqAddr = `${publicHost}:${amqPort}`;
  return {
    method: 'BRM.Config.GetMqConfig',
    SessionId: '',
    UseMqFlag: enabled ? 1 : 0,
    MQConfig: mqAddr,
    MQType: 'stomp',
    // DPSDK real descriptor keys (FUN_1806755a0): addr IS the MQ Config the
    // client hands to MSG.exe; mqtt "" => pipe path (OpenWire 61616).
    // E-087 lab+RE: MSG.exe (CMQSDKManager::MQInit) picks the transport
    // internally - even with enableTls "" it built failover:(ssl://%s)
    // (decaf.net.ssl.disablePeerVerification set), so the broker must serve
    // the OpenWire transport over TLS on 61616; this field stays EMPTY
    // (tried "0"/"1" - no effect on the transport choice).
    addr: mqAddr,
    userName: 'admin',
    password: 'admin',
    enableTls: '',
    mqtt: '',
    // lab broker credentials (ActiveMQ image defaults, lab-only - the same
    // class of lab credentials already used by the gateway/e2e admin login)
    MQUser: 'admin',
    MQPwd: 'admin',
    UserId: '1',
    GroupId: '',
    SSLEnable: 0,
    UnSSLPort: amqPort,
    CertificatePath: '',
    ProtocolVersion: 'MQTT',
    httpsMode: 0,
    TopicInfos: MQ_TOPICS.map((t) => ({ Topic: t, IsAccUser: 0 }))
  };
}

// --- MQTT 3.1.1 wire helpers -------------------------------------------------
function encodeRemainingLength(len) {
  const out = [];
  do { let b = len % 128; len = Math.floor(len / 128); if (len > 0) b |= 0x80; out.push(b); } while (len > 0);
  return Buffer.from(out);
}
function packet(type, flags, body) {
  return Buffer.concat([Buffer.from([(type << 4) | flags]), encodeRemainingLength(body.length), body]);
}
function readString(buf, off) {
  const len = buf.readUInt16BE(off);
  return [buf.toString('utf8', off + 2, off + 2 + len), off + 2 + len];
}
function topicMatches(filter, topic) {
  const f = filter.split('/'), t = topic.split('/');
  for (let i = 0; i < f.length; i++) {
    if (f[i] === '#') return true;
    if (i >= t.length) return false;
    if (f[i] !== '+' && f[i] !== t[i]) return false;
  }
  return f.length === t.length;
}

// Minimal broker. Returns { server, publish, clients, close }.
export function createMqttBroker() {
  const clients = new Map(); // socket -> { subscriptions: Set<string> }
  const server = net.createServer((socket) => {
    const state = { subscriptions: new Set(), buffer: Buffer.alloc(0), connected: false };
    clients.set(socket, state);
    socket.on('data', (chunk) => {
      state.buffer = Buffer.concat([state.buffer, chunk]);
      for (;;) {
        const b = state.buffer;
        if (b.length < 2) return;
        const type = b[0] >> 4, flags = b[0] & 0x0f;
        // remaining length varint
        let mult = 1, len = 0, i = 1;
        for (;;) { if (i >= b.length) return; const byte = b[i++]; len += (byte & 0x7f) * mult; mult *= 128; if (!(byte & 0x80)) break; }
        const total = i + len;
        if (b.length < total) return;
        const body = b.subarray(i, total);
        state.buffer = b.subarray(total);
        try { handlePacket(socket, state, type, flags, body); } catch (err) { console.log('[MQTT] packet error:', err.message); }
      }
    });
    const drop = () => { clients.delete(socket); socket.destroy(); };
    socket.on('close', drop);
    socket.on('error', drop);
  });

  function handlePacket(socket, state, type, flags, body) {
    switch (type) {
      case 1: { // CONNECT
        let off = 0;
        let proto; [proto, off] = readString(body, off);
        const level = body[off++]; const cflags = body[off++];
        const keepalive = body.readUInt16BE(off); off += 2;
        let clientId; [clientId, off] = readString(body, off);
        if (cflags & 0x04) { let w; [w, off] = readString(body, off); [w, off] = readString(body, off); } // will topic+payload
        if (cflags & 0x80) { let s; [s, off] = readString(body, off); } // username
        if (cflags & 0x40) { let s; [s, off] = readString(body, off); } // password
        state.connected = true; state.clientId = clientId || 'anon';
        state.keepalive = keepalive;
        socket.write(packet(2, 0, Buffer.from([0x00, 0x00]))); // CONNACK accepted
        console.log(`[MQTT] CONNECT client=${state.clientId} proto=${proto} v${level} keepalive=${keepalive}`);
        break;
      }
      case 8: { // SUBSCRIBE
        const pid = body.readUInt16BE(0);
        let off = 2; const granted = [];
        while (off < body.length) {
          let filter; [filter, off] = readString(body, off);
          const qos = body[off++] & 0x03;
          state.subscriptions.add(filter);
          granted.push(Math.min(qos, 1));
          console.log(`[MQTT] SUBSCRIBE client=${state.clientId} filter=${filter} qos=${qos}`);
        }
        socket.write(packet(9, 0, Buffer.concat([Buffer.from([pid >> 8, pid & 0xff]), Buffer.from(granted)])));
        break;
      }
      case 10: { // UNSUBSCRIBE
        const pid = body.readUInt16BE(0);
        let off = 2;
        while (off < body.length) { let f; [f, off] = readString(body, off); state.subscriptions.delete(f); }
        socket.write(packet(11, 0, Buffer.from([pid >> 8, pid & 0xff])));
        break;
      }
      case 3: { // PUBLISH from client
        let off = 0; let topic; [topic, off] = readString(body, off);
        const qos = (flags >> 1) & 0x03;
        let pid = 0;
        if (qos > 0) { pid = body.readUInt16BE(off); off += 2; }
        const payload = body.subarray(off);
        if (qos === 1) socket.write(packet(4, 0, Buffer.from([pid >> 8, pid & 0xff]))); // PUBACK
        publish(topic, payload, socket);
        break;
      }
      case 12: socket.write(packet(13, 0, Buffer.alloc(0))); break; // PINGREQ -> PINGRESP
      case 14: socket.destroy(); break; // DISCONNECT
      default: break;
    }
  }

  function publish(topic, payload, fromSocket = null) {
    const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
    // PUBLISH body (qos0, no packet id) = len(topic) + topic + payload
    const full = Buffer.concat([Buffer.from([0, 0]), Buffer.from(topic, 'utf8'), data]);
    full.writeUInt16BE(Buffer.byteLength(topic, 'utf8'), 0);
    let delivered = 0;
    for (const [sock, st] of clients) {
      if (sock === fromSocket) continue;
      if (![...st.subscriptions].some((f) => topicMatches(f, topic))) continue;
      try { sock.write(packet(3, 0, full)); delivered++; } catch { /* gone */ }
    }
    console.log(`[MQTT] PUBLISH ${topic} ${data.length}B -> ${delivered} subscriber(s)`);
    return delivered;
  }

  return {
    server,
    clients,
    publish,
    listen(port, host = '0.0.0.0') {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => resolve(server.address()));
      });
    },
    close() { for (const s of clients.keys()) s.destroy(); server.close(); }
  };
}

// --- notify hub: WS event stream + MQTT topics -------------------------------
// WS message keeps BOTH shapes seen in the wild: the flat DEVICE_ADDED frame
// (E-025) and the {type, data, timestamp} event envelope (EV-029 §event).
export function createNotifyHub({ wsClients, mqttPublish, amqPublish }) {
  function deviceEvent(type, device) {
    if (!device) return;
    const d = typeof device === 'object' ? device : { deviceCode: String(device) };
    const timestamp = new Date().toISOString();
    const body = JSON.stringify(d);
    // MQTT: the real notify topics carry the device VO as the message body
    // (kept as dual push - E-039 broker on 1883 stays up).
    if (mqttPublish) {
      mqttPublish(TOPIC_BATCH_ADD_DEVICES, body);
      mqttPublish(TOPIC_CHANNEL_STATUSES, body);
    }
    // E-040: the REAL client bus - ActiveMQ topic via STOMP publisher.
    if (amqPublish) {
      try {
        amqPublish(TOPIC_BATCH_ADD_DEVICES, body);
        amqPublish(TOPIC_CHANNEL_STATUSES, body);
      } catch (err) { console.log('[E040-NOTIFY] amq publish failed:', err.message); }
    }
    // WS: dual-shape frame.
    if (wsClients) {
      const flat = JSON.stringify({
        type, deviceCode: d.deviceCode, deviceId: d.deviceId || d.deviceCode,
        deviceName: d.deviceName, deviceIp: d.deviceIp, devicePort: d.devicePort,
        protocolType: d.protocolType, deviceCategory: d.deviceCategory,
        deviceType: d.deviceType, channelNum: d.channelNum, online: d.online, timestamp: Date.now()
      });
      const envelopeMsg = JSON.stringify({ type, eventType: type, data: d, timestamp });
      for (const ws of wsClients) {
        if (ws.readyState !== 1) continue;
        try { ws.send(flat); ws.send(envelopeMsg); } catch (err) { console.log('[E039-NOTIFY] ws send failed:', err.message); }
      }
    }
    console.log(`[E039-NOTIFY] ${type} ${d.deviceCode || ''}`);
  }
  return { deviceEvent };
}
