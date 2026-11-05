// ===== E-040: ActiveMQ Classic notify publisher (STOMP 1.2, zero deps) =====
//
// Evidence (production, this session):
// - pcap "CAPTURA FILTRADA DSS.pcapng": the real DSS Client 8.006
//   (192.168.100.18) opens TLS to the DSS server 200.54.10.50:**61616** and
//   speaks OpenWire inside it; there is NO traffic to 1883/8883/61613/5672.
//   The DSS server package ships the full ActiveMQ broker
//   (activemq-broker-6.2.0.jar, activemq-mqtt/amqp/stomp, MQConfiger.class),
//   so 61616 = ActiveMQ Classic OpenWire connector.
// - MSG.exe CMQSDKManager::MQInit (desensamblado manual): builds
//     failover:(ssl://%s)?startupMaxReconnectAttempts=1&wireFormat.maxInactivityDuration=0&connection.connectResponseTimeout=5000
//   or failover:(tcp://%s)?... with %s = strMQConfig VERBATIM (there is no
//   ":%d" format in the function), i.e. MQConfig must be a plain "host:port".
// - DPSDK.dll: the libcurl-MQTT branch is taken only when MQType === "mqtt"
//   (literal 0xcd5728); any other MQType forwards the config to MSG.exe over
//   the <tomsgpipe> named pipe -> OpenWire. So the gateway runs a REAL
//   ActiveMQ Classic (same version as the DSS package: 6.2.0) and publishes
//   the brms.notify* topics to it over STOMP 61613.
//
// This module is a minimal STOMP 1.2 client: CONNECT (with receipt), then
// SEND frames to /topic/<name>. Messages published while the broker is down
// are queued (bounded) and flushed on reconnect.

import net from 'node:net';

function stompFrame(command, headers, body) {
  const bodyBuf = body === undefined || body === null ? Buffer.alloc(0) : Buffer.from(String(body), 'utf8');
  const lines = [command];
  for (const [k, v] of Object.entries(headers || {})) lines.push(`${k}:${v}`);
  return Buffer.concat([Buffer.from(lines.join('\n') + '\n\n', 'utf8'), bodyBuf, Buffer.from([0])]);
}

export function createStompPublisher({
  host = '127.0.0.1',
  port = 61613,
  login = 'admin',
  passcode = 'admin',
  reconnectMs = 3000,
  maxQueue = 2000,
  clientId = 'brms-gateway'
} = {}) {
  let sock = null;
  let connected = false;
  let started = false;
  let closed = false;
  let timer = null;
  const queue = [];
  let connectAttempt = 0;

  function log(...args) { console.log('[E040-STOMP]', ...args); }

  function flush() {
    while (connected && queue.length) {
      const item = queue.shift();
      try { sock.write(item.frame); } catch (err) { log('write failed:', err.message); break; }
    }
  }

  function connect() {
    if (closed) return;
    connectAttempt += 1;
    try {
      sock = net.connect({ host, port });
    } catch (err) {
      log('connect error:', err.message);
      scheduleReconnect();
      return;
    }
    sock.setNoDelay(true);
    let buf = Buffer.alloc(0);
    let greeted = false;

    sock.on('connect', () => {
      sock.write(stompFrame('CONNECT', {
        'accept-version': '1.2',
        'host': host,
        'login': login,
        'passcode': passcode,
        'heart-beat': '0,0',
        'receipt': 'c' + connectAttempt
      }));
    });

    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // frames are NULL-terminated; heart-beats are bare LF
      for (;;) {
        const end = buf.indexOf(0);
        if (end === -1) break;
        let raw = buf.subarray(0, end);
        buf = buf.subarray(end + 1);
        while (raw.length && (raw[0] === 0x0a || raw[0] === 0x0d)) raw = raw.subarray(1);
        if (!raw.length) continue;
        const text = raw.toString('utf8');
        const nl = text.indexOf('\n');
        const cmd = text.slice(0, nl);
        if (cmd === 'CONNECTED') {
          if (!greeted) {
            greeted = true;
            connected = true;
            log(`connected to ${host}:${port} (stomp 1.2, attempt ${connectAttempt}), flushing ${queue.length} queued message(s)`);
            flush();
          }
        } else if (cmd === 'ERROR') {
          log(`broker ERROR frame: ${text.slice(nl + 1, nl + 300).replace(/\n/g, ' | ')}`);
        } else if (cmd === 'RECEIPT') {
          // connect receipt - nothing else to do
        } else {
          log(`unexpected frame ${cmd}`);
        }
      }
    });

    const drop = () => {
      if (!connected && greeted) return;
      connected = false;
      greeted = false;
      try { sock.destroy(); } catch { /* already gone */ }
      sock = null;
      if (started && !closed) scheduleReconnect();
    };
    sock.on('error', (err) => { log(`socket error: ${err.message}`); });
    sock.on('close', drop);
    sock.on('timeout', drop);
  }

  function scheduleReconnect() {
    if (timer || closed) return;
    timer = setTimeout(() => {
      timer = null;
      connect();
    }, reconnectMs);
  }

  // destination like "/topic/brms.notifyBatchAddDevices"
  function publish(destination, body) {
    const bodyBuf = Buffer.from(String(body), 'utf8');
    const frame = stompFrame('SEND', {
      destination,
      'content-type': 'application/json',
      // E-089: ActiveMQ Classic maps a STOMP SEND to BytesMessage whenever
      // content-length is present (LegacyFrameTranslator.convertFrame) and to
      // TextMessage only when it is absent - UNLESS amq-msg-type overrides.
      // MSG.exe (decaf OpenWire consumer) expects a TextMessage and silently
      // discards BytesMessage (browse evidence: only with amq-msg-type=text
      // the message shows a "Text" field). content-length stays for framing;
      // amq-msg-type wins over it (checked first in convertFrame).
      'amq-msg-type': 'text',
      'content-length': bodyBuf.length,
      'persistent': 'false'
    }, bodyBuf);
    if (connected && sock) {
      try { sock.write(frame); return true; } catch (err) { log('send failed:', err.message); }
    }
    if (queue.length < maxQueue) queue.push({ destination, frame });
    return false;
  }

  return {
    publish,
    isConnected: () => connected,
    queued: () => queue.length,
    start() {
      if (started) return;
      started = true;
      connect();
    },
    close() {
      closed = true;
      if (timer) { clearTimeout(timer); timer = null; }
      connected = false;
      if (sock) { try { sock.destroy(); } catch { /* ignore */ } sock = null; }
    }
  };
}
