// E-192 test peer: emula una camara Dahua que manda DHIP BIG-ENDIAN
// (magic BE 0x20000000, cmd 0x40 = REGISTER, payload JSON).
const net = require('node:net');

const host = process.argv[2] || '200.54.10.52';
const port = parseInt(process.argv[3] || '9500', 10);
const subId = process.argv[4] || 'CAM-TEST-BE-01';
const serial = process.argv[5] || 'CAMSN0001';

const payload = JSON.stringify({
  DeviceID: serial,
  SerialNo: serial,
  SubDeviceID: subId,
  MachineName: 'CAM-LAB-BE',
  IPAddress: '192.168.1.77',
  Port: 37777,
  ChannelNum: 1,
  DeviceType: 62,
  DeviceClass: 'IPC',
  UserName: 'admin',
  Password: 'cam123'
});

const h = Buffer.alloc(32);
h.writeUInt32BE(0x20000000, 0);   // magic BE
h.writeUInt32BE(0x40, 4);         // cmd 64 = REGISTER
h.writeUInt32BE(1, 8);            // seq
h.writeUInt32BE(Buffer.byteLength(payload), 12);

const c = net.connect(port, host, () => {
  console.log(`[be-peer] connected ${host}:${port} id=${subId}`);
  c.write(Buffer.concat([h, Buffer.from(payload)]));
});

c.on('data', (d) => {
  console.log('[be-peer] <-', d.length, 'B hex=' + d.toString('hex'));
  c.end();
});
c.on('close', () => process.exit(0));
setTimeout(() => { console.log('[be-peer] timeout'); process.exit(1); }, 8000);
