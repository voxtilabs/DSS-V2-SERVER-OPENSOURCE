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
export const TOPIC_ALARMS = 'brms.notifyAlarms';
export const TOPIC_VMS_ALARM_MSG = 'vms.alarm.msg';

// E-088 (lab evidence 2026-11-04 ~22:00 UTC, Jolokia on the live broker):
// MSG.exe connects OpenWire ssl://61616 and subscribes ONLY to its hardcoded
// mq.*.msg.topic pool (ConsumerCount=1 on mq.common.msg.topic,
// mq.vehicle.msg.topic, mq.alarm.msg.group.topic., mq.event.msg.topic.1,
// mq.alarm.msg.topic.1, mq.carsurvey.alarm.msg.topic.1; ConsumerCount=0 on
// every brms.notify* topic). Pool prefixes from MSG.exe (file 0x1f6250):
// per-user topics are "<prefix><UserId>" (observed ".1" = UserId '1' served
// by GetMqConfig), global ones are subscribed bare. So the notify envelope is
// ALSO published to these topics, or the native client never receives it
// ("Operation timed out" on CDevAdd, tree never refreshes).
export const CLIENT_MQ_TOPIC_PREFIXES = [
  'mq.alarm.msg.topic.',
  'mq.alarm.msg.group.topic.',
  'mq.event.msg.group.topic.',
  'mq.event.msg.topic.',
  'mq.common.msg.topic',
  'mq.carsurvey.alarm.msg.topic.',
  'mq.vehicle.msg.topic'
];

export function clientMqTopics(userId = '1') {
  const id = String(userId || '');
  const out = [];
  for (const p of CLIENT_MQ_TOPIC_PREFIXES) {
    out.push(p);
    if (id) out.push(`${p}${id}`);
  }
  return out;
}

// E-088/E-091: envelope the native client parses. RE evidence (DPSDK.dll,
// decomp-DPSDKdll.txt):
// - FUN_1800306b0 (Dpsdk::CDpsdkCore::ParseMQMsg) parses the MQ body and BAILS
//   unless the ROOT has BOTH keys "info" (DAT_180c76d40, confirmed string
//   "info" at VA 0x180c76d40) and "method" - then it reads root["method"] and
//   dispatches.
// - FUN_1800309c0 reads method from the root, takes root["info"] and passes
//   THAT object to the method handlers; FUN_180363e30 (the
//   brms.batchAddDevices param parser) reads operation (int),
//   addOrgCode/deleteOrgCode (string), addChannels/deleteChannels (array of
//   strings), and FUN_1803bdc60 additionally reads "timeCell" (int) and
//   "devices" from the same object.
// So the payload MUST live under root["info"]. Keys are ALSO sent flat at the
// root and under "params" (dual/triple-key strategy - other parsers were seen
// reading the flat shape).
// - addChannels/deleteChannels carry CHANNEL codes, not the device code: the
//   DSS channel id layout "<deviceCode>$<unitType=1>$0$<channelSeq>" is proven
//   (E-038: production web bundle + server UnitType). The tree is
//   channel-based, so a bare device code never matches a node.
export function dssChannelCodes(deviceCode, channelNum) {
  const n = Math.max(1, Number(channelNum) || 1);
  const out = [];
  for (let i = 1; i <= n; i++) out.push(`${deviceCode}$1$0$${i - 1}`);
  return out;
}

export function buildClientNotifyEnvelope(type, device) {
  // Kept for compatibility/tests: returns the JSON of the FIRST (primary)
  // envelope of buildClientNotifyEnvelopes().
  return buildClientNotifyEnvelopes(type, device)[0];
}

// E-092 (RE-SCHEMA-DPSDK.md, Ghidra runs dpsdk7-11 on DPSDK.dll):
// - MQ path (ParseMQMsg FUN_1800306b0) reads ONLY root "method" + "info";
//   "params"/flat keys are ignored on this path. Handlers receive root["info"].
// - brms.batchAddDevices is the batch-add RESULT ACK: info = {session:string,
//   successfulCount:int, failedCount:int} -> UI callback 0x5e. It carries NO
//   device list - sending addChannels under it does nothing.
// - The method that actually pushes a device+channels into the org tree is
//   vms.LogicOrgChannel: info = {operation:1..3, addOrgCode, addChannels:
//   ["<deviceCode>$1$0$<seq>"], deleteOrgCode, deleteChannels} (parser
//   FUN_180363e30; handler FUN_1800328b0). vms.addDev (handler FUN_180032ac0,
//   parser FUN_180364830/FUN_1803649a0, callback 0xd) takes a full device
//   object: orgCode + code/name/deviceIp/devicePort/serverCode/protocol/
//   manufacturer/type/category/model/sn/status + channels[]/{channelId,...}.
// - Delete side: vms.LogicOrgChannel op=3 {deleteOrgCode, deleteChannels} and
//   vms.deleteDev info={devices:[{deviceCode, orgCode, reason}]}.
// E-097 (no-refresh fix): the device-status push methods the native client
// subscribes to are in the DPSDK method table (@0xc71358/0xc71370):
//   vms.notifyDeviceStatus / vms.notifyDevChannelStatus (plus the flat
//   brms.notifyChannelStatuses). Typo warning: the DPSDK string pool spells the
//   deviceStatus variant "notifyDeviceStatus" exactly (not "notifyDeviceState").
//   The parser keys are NOT fully RE'd (no Ghidra decomp for its handler), so
//   info is a defensive superset: deviceCode/deviceId + status "1"/"0" STRING
//   (E-095: strict === against "1"), online, statusName and a channel array
//   covering both notifyDevChannelStatus shapes.
export function buildDeviceStatusNotifyEnvelopes(device, online = true) {
  const d = typeof device === 'object' ? device : { deviceCode: String(device) };
  const code = d.deviceCode || '';
  if (!code) return [];
  const status = online ? '1' : '0';
  const statusName = online ? 'Online' : 'Offline';
  const orgCode = d.orgCode || '';
  const channelNum = Number(d.channelNum || d.encoderChannelCount || d.channelCount) || 1;
  const channelCodes = dssChannelCodes(code, channelNum);
  const channelList = channelCodes.map((channelId) => ({
    channelId, channelCode: channelId, deviceCode: code, status, online: status,
    statusName, channelStatus: status
  }));
  const statusInfo = {
    deviceCode: code, deviceId: code, deviceName: d.deviceName || code,
    orgCode, status, online: status, statusName,
    deviceStatus: status, statusValue: status, time: new Date().toISOString(),
    channels: channelList
  };
  const env = (method, info) => JSON.stringify({ method, info });
  return [
    env('vms.notifyDeviceStatus', { ...statusInfo, info: statusInfo }),
    env('vms.notifyDevChannelStatus', { ...statusInfo, info: statusInfo })
  ];
}

export function buildClientNotifyEnvelopes(type, device) {
  const d = typeof device === 'object' ? device : { deviceCode: String(device) };
  const code = d.deviceCode || '';
  const deleting = type === 'DEVICE_DELETED';
  const orgCode = d.orgCode || '';
  const channelNum = Number(d.channelNum || d.encoderChannelCount || d.channelCount) || 1;
  const channelCodes = code ? dssChannelCodes(code, channelNum) : [];
  const channels = Array.isArray(d.channels) && d.channels.length
    ? d.channels
    : channelCodes.map((channelCode, idx) => ({
        channelCode, channelId: channelCode, channelSeq: idx, channelNo: idx + 1,
        channelName: idx === 0 ? (d.deviceName || code) : `${d.deviceName || code} CH${idx + 1}`,
        unitType: '1', deviceCode: code, deviceName: d.deviceName || '', orgCode
      }));
  const env = (method, info) => JSON.stringify({ method, info });
  if (deleting) {
    return [
      env('vms.LogicOrgChannel', {
        operation: 3, addOrgCode: '', addChannels: [],
        deleteOrgCode: orgCode, deleteChannels: channelCodes
      }),
      env('vms.deleteDev', {
        devices: [{ deviceCode: code, orgCode, reason: 0 }]
      })
    ];
  }
  const addDevInfo = {
    orgCode,
    code,
    name: d.deviceName || code,
    deviceIp: d.deviceIp || '',
    devicePort: Number(d.devicePort) || 0,
    serverCode: d.serverCode || 'video#local',
    protocol: d.protocolName || 'ONVIF',
    streamProtocol: d.protocolType || '99',
    manufacturer: d.manufacturer || '',
    type: String(d.deviceType || '1'),
    category: String(d.deviceCategory || '1'),
    model: d.model || '',
    deviceModelStr: d.model || '',
    sn: d.serialNumber || '',
    status: 1,
    loginType: 9,
    domainId: '0',
    channels,
    units: [{ unitType: '1', unitSeq: 0, channels }]
  };
  return [
    // 1) tree push: add the channels under the org (this is what makes the
    //    camera show up under VIGILAB in Dispositivos Agregados)
    env('vms.LogicOrgChannel', {
      operation: 1, addOrgCode: orgCode, addChannels: channelCodes,
      deleteOrgCode: '', deleteChannels: []
    }),
    // 2) full device node
    env('vms.addDev', addDevInfo),
    // 3) batch-add result ACK (clears the CDevAdd waiter instead of
    //    "Operation timed out")
    env('brms.batchAddDevices', { session: '', successfulCount: 1, failedCount: 0 })
  ];
}

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
// E-087 lab evidence (2026-11-04 22:14:49-22:15:56 session): with mqtt ""
// the notify never reached the client -> CDevAdd toasted "Operation timed
// out". NOTE (E-088, refutes the old reading): "0 connection events in the
// broker log" did NOT mean MSG.exe never dialed - ActiveMQ 6.2 does not
// INFO-log successful connections. Jolokia on the live broker showed
// CurrentConnectionsCount=2 and MSG.exe subscribed to the mq.*.msg.topic
// pool; the real gap was that we only published brms.notify* (ConsumerCount
// 0). So: mqtt stays "<host>:1883" (harmless dual path) and the notify
// envelope is now ALSO published to the mq.* topics (see below).
// addr/MQConfig stay 61616 (OpenWire ssl, MSG.exe).
// E-088: UserId served in GetMqConfig - MSG.exe appends it to the per-user
// mq.* topics (observed "mq.event.msg.topic.1" with UserId '1').
export const MQ_USER_ID = '1';

export function buildMqConfigPayload({ publicHost, amqPort = 61616, mqttPort = 1883, enabled }) {
  const mqAddr = `${publicHost}:${amqPort}`;
  const mqttAddr = `${publicHost}:${mqttPort}`;
  return {
    method: 'BRM.Config.GetMqConfig',
    SessionId: '',
    UseMqFlag: enabled ? 1 : 0,
    MQConfig: mqAddr,
    MQType: 'stomp',
    // DPSDK real descriptor keys (FUN_1806755a0): addr IS the MQ Config the
    // client hands to MSG.exe; mqtt non-empty => libcurl-MQTT branch
    // (mqtt://host:1883/<topic>) instead of the MSG.exe pipe.
    // E-087 lab+RE: MSG.exe (CMQSDKManager::MQInit) picks the transport
    // internally - even with enableTls "" it built failover:(ssl://%s)
    // (decaf.net.ssl.disablePeerVerification set), so the broker must serve
    // the OpenWire transport over TLS on 61616; this field stays EMPTY
    // (tried "0"/"1" - no effect on the transport choice).
    addr: mqAddr,
    userName: 'admin',
    password: 'admin',
    enableTls: '',
    mqtt: mqttAddr,
    // lab broker credentials (ActiveMQ image defaults, lab-only - the same
    // class of lab credentials already used by the gateway/e2e admin login)
    MQUser: 'admin',
    MQPwd: 'admin',
    UserId: MQ_USER_ID,
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
export function createNotifyHub({ wsClients, mqttPublish, amqPublish, mqUserId = '1' }) {
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
        // E-088: MSG.exe listens on the mq.*.msg.topic pool, NOT on
        // brms.notify* (ConsumerCount=0 there) - publish the method envelopes
        // there too or the native client never gets the notify.
        // E-092: one envelope per MQ method (vms.LogicOrgChannel tree push,
        // vms.addDev device node, brms.batchAddDevices result ACK) to every
        // mq.* topic (bare + UserId suffix).
        for (const envelope of buildClientNotifyEnvelopes(type, d)) {
          for (const t of clientMqTopics(mqUserId)) amqPublish(t, envelope);
        }
        // E-097: DEVICE_STATUS events additionally publish the native
        // vms.notifyDeviceStatus / vms.notifyDevChannelStatus methods so the
        // client updates the device row LIVE (no manual refresh). DEVICE_STATUS
        // is emitted by scheduleStreamProvisioning after every add funnel.
        if (type === 'DEVICE_STATUS') {
          for (const envelope of buildDeviceStatusNotifyEnvelopes(d, true)) {
            for (const t of clientMqTopics(mqUserId)) amqPublish(t, envelope);
          }
        }
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
        try {
          ws.send(flat); ws.send(envelopeMsg);
          // E-097: SPA eventBus frames for live status updates (the SPA
          // subscribes to vms.notifyDeviceStatus in monitoring views).
          if (type === 'DEVICE_STATUS') {
            ws.send(JSON.stringify({ type: 'vms.notifyDeviceStatus', method: 'vms.notifyDeviceStatus', data: d, info: d, timestamp }));
          }
        } catch (err) { console.log('[E039-NOTIFY] ws send failed:', err.message); }
      }
    }
    console.log(`[E039-NOTIFY] ${type} ${d.deviceCode || ''}`);
  }
  function alarmEvent(event) {
    if (!event) return;
    const body = buildAlarmEventEnvelope(event);
    const stamp = new Date().toISOString();
    if (mqttPublish) mqttPublish(TOPIC_ALARMS || 'brms.notifyAlarms', body);
    if (amqPublish) {
      try {
        amqPublish('brms.notifyAlarms', body);
        amqPublish('vms.alarm.msg', body);
        // the native pool MSG.exe really consumes
        for (const t of clientMqTopics(mqUserId)) {
          if (t.startsWith('mq.alarm.msg.topic.') || t.startsWith('mq.event.msg.topic.')) amqPublish(t, body);
        }
      } catch (err) { console.log('[E040-NOTIFY] alarm publish failed:', err.message); }
    }
    if (wsClients) {
      for (const ws of wsClients) {
        if (ws.readyState !== 1) continue;
        try {
          ws.send(body);
          ws.send(JSON.stringify({ type: 'vms.alarm.msg', method: 'vms.alarm.msg', data: event, timestamp: stamp }));
        } catch { /* socket gone */ }
      }
    }
    console.log('[E117-ALARM] event published:', event.eventId || event.description || '(no id)');
  }

  return { deviceEvent, alarmEvent };
}

// E-117: alarm event envelope for the Event Center. The native client listens
// on brms.notifyAlarms + the mq.alarm.msg.topic.* pool (E-088 evidence); the
// SPA subscribes on the WS eventBus. One alarm -> all three channels.
export function buildAlarmEventEnvelope(event) {
  const e = typeof event === 'object' && event !== null ? event : { eventId: String(event) };
  const ts = new Date().toISOString();
  return JSON.stringify({
    method: 'vms.alarm.msg',
    eventId: e.eventId, alarmId: e.eventId,
    alarmType: String(e.eventType ?? '1'), eventType: String(e.eventType ?? '1'),
    level: String(e.eventLevel ?? '1'), eventLevel: String(e.eventLevel ?? '1'),
    channelId: e.channelId || '', deviceCode: e.deviceCode || '', orgCode: e.orgCode || '',
    eventTime: e.eventTime || ts, timestamp: ts,
    description: e.description || '', status: '1', handleStatus: '0'
  });
}
