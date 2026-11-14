// E-193 test peer: emula la trama DHIP "plana" de una camara Dahua real
// (magic LE 0x780000b4, cmd 0x40, payload ASCII con el Device ID, 96B fijos).
const net = require('node:net');

const host = process.argv[2] || '200.54.10.52';
const port = parseInt(process.argv[3] || '9500', 10);
const deviceId = process.argv[4] || '202611122200';

const payload = Buffer.alloc(64);
Buffer.from(deviceId, 'latin1').copy(payload, 0);

const h = Buffer.alloc(32);
h.writeUInt32LE(0x780000b4, 0);
h.writeUInt32LE(0x40, 4);
h.writeUInt32LE(7, 8);
h.writeUInt32LE(0, 12);

const c = net.connect(port, host, () => {
  console.log(`[flat-peer] connected ${host}:${port} id=${deviceId}`);
  c.write(Buffer.concat([h, payload]));
});

c.on('data', (d) => {
  console.log('[flat-peer] <-', d.length, 'B hex=' + d.toString('hex').slice(0, 64));
});
setTimeout(() => { c.end(); process.exit(0); }, 4000);
