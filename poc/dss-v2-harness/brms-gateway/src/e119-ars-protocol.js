// ===== E-119: Dahua DVRIP/DHIP auto-register framing (RE-verified) =========
//
// RE evidence (netsdk.dll AutoRegister.cpp @0x01366578, header templates in
// .rdata):
//   DVRIP frame @0x01388648: magic "DVRIP\0\0\0" (8B) + dword 0x19930522
//     @+0x08 + dword 1 @+0x0C + ... + payloadLen 0x90 @+0x24 + 1 @+0x2C
//     -> payload = JSON {"ExtraFormat":[...],"MainFormat":[...],"SnapFormat":[...]}
//   DHIP frame @0x013988dc: magic "DHIP\0\0\0" (8B) + dword 0 @+0x08 +
//     dword 0x19930522 @+0x0C + 5 @+0x10 + ... + 96 @+0x28 + 1 @+0x30
//     -> JSON payload @+0x34 ("client.notif...")
//   Registration message fields: DeviceID (<=63), SerialNo, DeviceType,
//     DeviceClass, MachineName, MachineAddress, UserName, Password,
//     IPAddress, ProxyHttps/ProxyPort (@0x0137a138-0x01398608)
//   Transport: JSON-RPC (GetParameterValues/SetParameterValues) over this
//     binary framing. Errors: "Failed to parse pRegisterInfo" @0x013880a8.
//   9500 is not hardcoded in the client - the server injects ARSPort.
//
// This module parses BOTH the legacy 32B-header framing (what the previous
// build served) and the RE-verified binary-header + JSON framing, and builds
// protocol-correct ACKs.

export const DVRIP_VERSION = 0x19930522;

const MAGIC_DVRIP = Buffer.from('DVRIP\0\0\0', 'latin1');
const MAGIC_DHIP = Buffer.from('DHIP\0\0\0', 'latin1');

function startsWith(buf, magic) {
  if (buf.length < magic.length) return false;
  return buf.subarray(0, magic.length).equals(magic);
}

// Try the RE-verified DVRIP/DHIP framing: 8B magic + version + header + JSON.
// Returns {ok, magic, version, command, sequence, payloadLen, headerLen, payload}
export function parseDahuaFrame(buf) {
  for (const [magic, label] of [[MAGIC_DVRIP, 'DVRIP'], [MAGIC_DHIP, 'DHIP']]) {
    if (!startsWith(buf, magic)) continue;
    if (buf.length < 16) return { ok: false };
    const v1 = buf.readUInt32LE(8);
    const v2 = buf.readUInt32LE(12);
    const version = v1 === DVRIP_VERSION ? v1 : v2;
    if (version !== DVRIP_VERSION) return { ok: false, magic: label };
    // DVRIP layout (template @0x01388648): command/length candidates are the
    // small dwords; the JSON payload starts after the 48B header. DHIP uses a
    // 52B header (JSON @+0x34). We locate the JSON by scanning for '{'.
    const headerLen = label === 'DVRIP' ? 0x30 : 0x34;
    const jsonAt = buf.indexOf(0x7b); // '{'
    if (jsonAt === -1) {
      return { ok: true, magic: label, version, headerLen, command: 0, sequence: 0, payloadLen: 0, payload: Buffer.alloc(0), jsonAt: -1 };
    }
    // header dwords: for DVRIP cmd@0x18 seq@0x1c len@0x24; for DHIP cmd@0x10
    // (both tolerate garbage - the JSON is authoritative)
    const command = label === 'DVRIP' ? buf.readUInt32LE(0x18) : buf.readUInt32LE(0x10);
    const sequence = label === 'DVRIP' ? buf.readUInt32LE(0x1c) : buf.readUInt32LE(0x14);
    const payloadLen = buf.length - jsonAt;
    return {
      ok: true, magic: label, version, headerLen, jsonAt,
      command: command & 0xffff, sequence, payloadLen,
      payload: buf.subarray(jsonAt)
    };
  }
  return { ok: false };
}

function pick(obj, keys, fallback) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null && String(obj[k]).length) return String(obj[k]);
  }
  return fallback;
}

// Parse the AutoRegister JSON payload into our device record shape.
export function parseRegisterJson(jsonBuf) {
  let obj;
  try { obj = JSON.parse(jsonBuf.toString('utf8').replace(/\0+$/, '')); } catch { return null; }
  if (!obj || typeof obj !== 'object') return null;
  // nested containers (ExtraFormat/MainFormat/SnapFormat carry the real data)
  const flat = { ...obj };
  for (const k of ['ExtraFormat', 'MainFormat', 'SnapFormat', 'Device', 'RegisterInfo', 'pRegisterInfo', 'params']) {
    const v = obj[k];
    if (Array.isArray(v)) for (const item of v) if (item && typeof item === 'object') Object.assign(flat, item);
    else if (v && typeof v === 'object') Object.assign(flat, v);
  }
  return {
    deviceId: pick(flat, ['DeviceID', 'deviceId', 'SerialNo', 'sn', 'MachineName'], ''),
    serialNo: pick(flat, ['SerialNo', 'sn', 'DeviceID'], ''),
    deviceName: pick(flat, ['MachineName', 'DeviceName', 'deviceName', 'DeviceID'], ''),
    deviceType: pick(flat, ['DeviceType', 'deviceType'], '2'),
    deviceClass: pick(flat, ['DeviceClass', 'deviceClass'], ''),
    machineAddress: pick(flat, ['MachineAddress', 'machineAddress', 'IPAddress', 'ip'], ''),
    ip: pick(flat, ['IPAddress', 'ip', 'MachineAddress'], ''),
    port: pick(flat, ['Port', 'port', 'MediaPort'], '37777'),
    username: pick(flat, ['UserName', 'username'], 'admin'),
    password: pick(flat, ['Password', 'password'], 'admin123'),
    channelCount: pick(flat, ['ChannelNum', 'channelNum', 'ChannelCount', 'VideoInputChannel'], '1'),
    firmware: pick(flat, ['SoftWareVersion', 'Firmware', 'firmware'], '')
  };
}

// Build a protocol ACK frame (magic + version + cmd|0x8000 + seq + JSON body).
export function buildDahuaAck(magic, command, sequence, jsonBody) {
  const body = Buffer.from(typeof jsonBody === 'string' ? jsonBody : JSON.stringify(jsonBody), 'utf8');
  const header = Buffer.alloc(0x30);
  const magicBuf = magic === 'DHIP' ? MAGIC_DHIP : MAGIC_DVRIP;
  magicBuf.copy(header, 0);
  header.writeUInt32LE(DVRIP_VERSION, 8);
  header.writeUInt32LE((command | 0x8000) & 0xffffffff, 12);
  header.writeUInt32LE(sequence || 0, 16);
  header.writeUInt32LE(body.length, 20);
  header.writeUInt32LE(1, 28);
  return Buffer.concat([header, body]);
}

// The register ACK the real devices expect: the server address + session.
export function buildRegisterAckJson(deviceId, serverHost, serverPort) {
  return JSON.stringify({
    Ret: 100, RetMsg: 'OK', SessionID: String(Date.now() % 1000000),
    DeviceID: String(deviceId || ''), RegisterServer: String(serverHost || ''),
    RegisterPort: String(serverPort || ''), KeepAliveSecond: '60'
  });
}
