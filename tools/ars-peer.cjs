#!/usr/bin/env node
// E-174: synthetic Dahua device that speaks the AutoRegister framing we
// reimplemented, so the ARS path can be verified without hardware:
//   DVRIP: magic "DVRIP\0\0\0" + 0x19930522 @8 + cmd@0x18 + seq@0x1C
//          + len@0x24 + flag @0x2C + JSON @0x38
//   DHIP : magic "DHIP\0\0\0"  + 0x19930522 @0x0C + cmd@0x10 + seq@0x14
//          + len@0x28 + flag @0x30 + JSON @0x34
// Usage: node ars-peer.cjs <host> <port> [DVRIP|DHIP] [deviceId]
const net = require('net');

const host = process.argv[2] || '127.0.0.1';
const port = Number(process.argv[3] || 9500);
const framing = (process.argv[4] || 'DVRIP').toUpperCase();
const deviceId = process.argv[5] || 'LABXVR0001';

function build(framing, cmd, seq, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const isDhip = framing === 'DHIP';
  const h = Buffer.alloc(isDhip ? 0x34 : 0x38);
  (isDhip ? Buffer.from('DHIP\0\0\0', 'latin1') : Buffer.from('DVRIP\0\0\0', 'latin1')).copy(h, 0);
  if (isDhip) {
    h.writeUInt32LE(0x19930522, 0x0c);
    h.writeUInt32LE(cmd, 0x10);
    h.writeUInt32LE(seq, 0x14);
    h.writeUInt32LE(body.length, 0x28);
    h.writeUInt32LE(1, 0x30);
  } else {
    h.writeUInt32LE(0x19930522, 8);
    h.writeUInt32LE(1, 0x0c);
    h.writeUInt32LE(cmd, 0x18);
    h.writeUInt32LE(seq, 0x1c);
    h.writeUInt32LE(body.length, 0x24);
    h.writeUInt32LE(1, 0x2c);
  }
  return Buffer.concat([h, body]);
}

const register = {
  DeviceID: deviceId,
  SerialNo: deviceId,
  MachineName: 'LAB-XVR-4CH',
  MachineAddress: '192.168.100.50',
  IPAddress: '192.168.100.50',
  Port: 37777,
  ChannelNum: 4,
  DeviceType: 2,
  DeviceClass: 'IPC',
  UserName: 'admin',
  Password: 'admin123',
  ExtraFormat: [null, null, null],
  MainFormat: [null, null, null],
  SnapFormat: [null, null, null]
};

const c = net.connect(port, host, () => {
  console.log(`[peer] connected ${host}:${port} framing=${framing} id=${deviceId}`);
  c.write(build(framing, 5, 1, register));
});

let got = 0;
c.on('data', (d) => {
  got++;
  const magic = d.subarray(0, 5).toString('latin1');
  const isDhip = magic.startsWith('DHIP');
  const cmd = isDhip ? d.readUInt32LE(0x10) : d.readUInt32LE(0x18);
  const seq = isDhip ? d.readUInt32LE(0x14) : d.readUInt32LE(0x1c);
  const jsonAt = isDhip ? 0x34 : 0x38;
  let body = '';
  try { body = d.subarray(jsonAt).toString('utf8').replace(/\0+$/, ''); } catch { }
  console.log(`[peer] <- ${d.length}B magic=${magic.trim()} cmd=0x${cmd.toString(16)} seq=${seq}`);
  console.log(`[peer]    ${body}`);
  if (got === 1) {
    setTimeout(() => c.write(build(framing, 0x0004, 2, { DeviceID: deviceId, method: 'global.keepAlive' })), 300);
    setTimeout(() => { c.end(); console.log('[peer] done'); }, 1200);
  }
});
c.on('error', (e) => console.log('[peer] error', e.message));
c.on('close', () => console.log('[peer] closed'));
setTimeout(() => { try { c.destroy(); } catch { } process.exit(0); }, 6000);
