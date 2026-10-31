import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'node:crypto';

const app = Fastify({ logger: true });
await app.register(cors, { origin: true });

const REALM = 'DSS-V2-LAB';
const TOKENS = new Map(); // token -> { userName, expires }
const PENDING = new Map(); // userName -> { realm, randomKey, expires }

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genRandomKey() { return crypto.randomBytes(16).toString('hex'); }

app.post('/brms/api/v1.0/accounts/authorize', async (req, reply) => {
  const { userName, randomKey, signature, clientType, challengeKey } = req.body;
  // Challenge request: only userName
  if (userName && !randomKey && !signature) {
    const rk = genRandomKey();
    const key = 'pending-' + Date.now();
    PENDING.set(key, { realm: REALM, randomKey: rk, expires: Date.now() + 60000 });
    return reply.code(401).send({ realm: REALM, randomKey: rk, challengeKey: key });
  }
  // Verification request: userName + randomKey + signature + challengeKey
  const pending = PENDING.get(challengeKey);
  if (!pending || pending.randomKey !== randomKey) return reply.code(401).send({ error: 'invalid challenge' });
  const temp = doubleMd5(userName, 'admin123'); // fixed lab password
  const expected = makeSig(userName, REALM, temp, randomKey);
  if (signature !== expected) return reply.code(401).send({ error: 'bad signature' });
  const token = genToken();
  TOKENS.set(token, { userName, expires: Date.now() + 86400000 });
  PENDING.delete(userName);
  return { token, duration: 86400 };
});

function auth(req, reply, done) {
  const token = req.headers['x-subject-token'];
  if (!token || !TOKENS.has(token)) return reply.code(401).send({ error: 'unauthorized' });
  const t = TOKENS.get(token);
  if (Date.now() > t.expires) { TOKENS.delete(token); return reply.code(401).send({ error: 'expired' }); }
  req.user = t; done();
}

app.post('/brms/api/v1.0/accounts/keepalive', { preHandler: auth }, async () => ({ success: true }));
app.get('/brms/api/v1.0/accounts/current', { preHandler: auth }, async (req) => ({ userName: req.user.userName }));
app.post('/brms/api/v1.0/accounts/unauthorize', { preHandler: auth }, async (req) => { TOKENS.delete(req.headers['x-subject-token']); return { success: true }; });

// Tree endpoints
app.post('/brms/api/v1.0/tree/orgs', { preHandler: auth }, async () => ({ orgList: [{ orgId: '1', orgName: 'Root', parentId: '0' }] }));
app.post('/brms/api/v1.0/tree/devices', { preHandler: auth }, async () => ({ deviceList: [{ deviceCode: 'CAM001', deviceName: 'Test Cam', status: 1, deviceType: 2 }] }));
app.post('/brms/api/v1.0/tree/channels', { preHandler: auth }, async () => ({ channelList: [{ channelId: '1000171$1$0$0', channelName: 'Ch1', status: 1, channelType: 1 }] }));

// MTS Video
app.post('/brms/api/v1.0/MTS/Video/StartVideo', { preHandler: auth }, async (req) => {
  const { channelId, streamType, dataType } = req.body;
  return { rtspUrl: `rtsp://127.0.0.1:9100/${channelId}?token=MOCK-${genToken()}`, hlsUrl: `https://127.0.0.1:1443/brms/api/v1.1/video/live/channel/${channelId}/hls` };
});
app.post('/brms/api/v1.0/MTS/Video/StopVideo', { preHandler: auth }, async () => ({ success: true }));
app.post('/brms/api/v1.0/MTS/Video/KeepAlive', { preHandler: auth }, async () => ({ success: true }));

// SS Record
app.post('/brms/api/v1.0/SS/Record/QueryRecord', { preHandler: auth }, async () => ({ recordList: [] }));

// Events
app.post('/brms/api/v1.0/event/subscription', { preHandler: auth }, async () => ({ subscriptionId: 'sub-' + genToken().slice(0, 8) }));
app.post('/brms/api/v1.0/event/query', { preHandler: auth }, async () => ({ events: [] }));

// Vehicle / ANPR
app.post('/brms/api/v1.0/vehicle/anpr/records', { preHandler: auth }, async () => ({ records: [] }));
app.post('/brms/api/v1.0/vehicle/whitelist', { preHandler: auth }, async () => ({ success: true }));

// Access control
app.post('/brms/api/v1.0/access/door/control', { preHandler: auth }, async () => ({ success: true }));

// PTZ
app.post('/brms/api/v1.0/ptz/direction', { preHandler: auth }, async () => ({ success: true }));
app.post('/brms/api/v1.0/ptz/preset', { preHandler: auth }, async () => ({ success: true }));

const PORT = parseInt(process.env.PORT || '11443');
await app.listen({ port: PORT, host: '0.0.0.0' });
console.log(`BRMS Gateway listening on https://0.0.0.0:${PORT} (TLS disabled for lab)`);