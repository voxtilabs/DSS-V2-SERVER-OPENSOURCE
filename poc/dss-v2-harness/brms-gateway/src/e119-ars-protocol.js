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
// E-128: payloadLen now comes from the HEADER (DVRIP len@0x24, DHIP len@0x28),
// not from buf.length - jsonAt, so a fragmented frame reports its declared
// length and the caller can wait for the complete frame.
export const ARS_MAX_PAYLOAD = 1024 * 1024; // 1 MiB cap - anti-DoS (DevOps audit)
export const ARS_MAX_BUFFER = 4 * 1024 * 1024; // 4 MiB accumulated cap

export function parseDahuaFrame(buf) {
  for (const [magic, label] of [[MAGIC_DVRIP, 'DVRIP'], [MAGIC_DHIP, 'DHIP']]) {
    if (!startsWith(buf, magic)) continue;
    if (buf.length < 16) return { ok: false };
    const v1 = buf.readUInt32LE(8);
    const v2 = buf.readUInt32LE(12);
    const version = v1 === DVRIP_VERSION ? v1 : v2;
    if (version !== DVRIP_VERSION) return { ok: false, magic: label };
    // DVRIP layout (template @0x01388648): cmd@0x18 seq@0x1c len@0x24 flag@0x2c,
    // 48B header, JSON @+0x30. DHIP layout (template @0x013988dc): version@0x0c,
    // 52B header, JSON @+0x34, len@0x28 flag@0x30.
    const headerLen = label === 'DVRIP' ? 0x30 : 0x34;
    if (buf.length < headerLen) return { ok: false, magic: label, needMore: true };
    const command = label === 'DVRIP' ? buf.readUInt32LE(0x18) : buf.readUInt32LE(0x10);
    const sequence = label === 'DVRIP' ? buf.readUInt32LE(0x1c) : buf.readUInt32LE(0x14);
    const declaredLen = label === 'DVRIP' ? buf.readUInt32LE(0x24) : buf.readUInt32LE(0x28);
    const jsonAt = buf.indexOf(0x7b); // '{'
    if (jsonAt === -1) {
      return { ok: true, magic: label, version, headerLen, command: 0, sequence: 0, payloadLen: declaredLen, payload: Buffer.alloc(0), jsonAt: -1, needMore: true };
    }
    return {
      ok: true, magic: label, version, headerLen, jsonAt,
      command: command & 0xffff, sequence,
      payloadLen: declaredLen > 0 && declaredLen <= ARS_MAX_PAYLOAD ? declaredLen : (buf.length - jsonAt),
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

// Build a protocol ACK frame. E-128: offsets fixed to the RE header templates
// (DevOps audit found the old code wrote cmd@0x0C/seq@0x10/len@0x14, while
// netsdk template @0x01388648 reads cmd@0x18/seq@0x1C/len@0x24/flag@0x2C):
//   DVRIP ACK: 48B header - magic@0, version@8, cmd|0x8000@0x18, seq@0x1C,
//              len@0x24, flag 1@0x2C, JSON payload @0x30.
//   DHIP ACK:  52B header - magic@0, 0@8, version@0x0C, cmd|0x8000@0x10,
//              seq@0x14, len@0x28, flag 1@0x30, JSON payload @0x34.
export function buildDahuaAck(magic, command, sequence, jsonBody) {
  const body = Buffer.from(typeof jsonBody === 'string' ? jsonBody : JSON.stringify(jsonBody), 'utf8');
  const isDhip = magic === 'DHIP';
  const header = Buffer.alloc(isDhip ? 0x34 : 0x30);
  const magicBuf = isDhip ? MAGIC_DHIP : MAGIC_DVRIP;
  magicBuf.copy(header, 0);
  if (isDhip) {
    header.writeUInt32LE(0, 8);
    header.writeUInt32LE(DVRIP_VERSION, 0x0c);
    header.writeUInt32LE((command | 0x8000) & 0xffffffff, 0x10);
    header.writeUInt32LE(sequence || 0, 0x14);
    header.writeUInt32LE(body.length, 0x28);
    header.writeUInt32LE(1, 0x30);
  } else {
    header.writeUInt32LE(DVRIP_VERSION, 8);
    header.writeUInt32LE((command | 0x8000) & 0xffffffff, 0x18);
    header.writeUInt32LE(sequence || 0, 0x1c);
    header.writeUInt32LE(body.length, 0x24);
    header.writeUInt32LE(1, 0x2c);
  }
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
