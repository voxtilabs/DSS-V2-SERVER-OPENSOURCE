import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const BASE = 'http://127.0.0.1:11443';
const USER = 'admin';
const PASS = 'admin123';

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }

let token = '';
let serverProc = null;

function waitForServer() {
  return new Promise((resolve, reject) => {
    for (let i = 0; i < 15; i++) {
      setTimeout(async () => {
        try {
          await fetch(BASE + '/brms/api/v1.0/accounts/authorize', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER }) });
          resolve();
        } catch { if (i === 14) reject(new Error('Server did not start')); }
      }, i * 300);
    }
  });
}

describe('BRMS Gateway handshake (EV-029/030)', { timeout: 30000 }, () => {
  before(async () => {
    serverProc = spawn('node', ['src/index.js'], { cwd: 'C:/Users/bruno/Downloads/LOCURA DSS/poc/dss-v2-harness/brms-gateway', stdio: 'pipe' });
    await waitForServer();
    // challenge
    const ch = await fetch(`${BASE}/brms/api/v1.0/accounts/authorize`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER }) });
    assert.equal(ch.status, 401);
    const { realm, randomKey, challengeKey } = await ch.json();
    assert.ok(realm && randomKey && challengeKey);
    // response
    const temp = doubleMd5(USER, PASS);
    const sig = makeSig(USER, realm, temp, randomKey);
    const auth = await fetch(`${BASE}/brms/api/v1.0/accounts/authorize`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: USER, randomKey, signature: sig, clientType: 'WINPC_V2', challengeKey }) });
    assert.equal(auth.status, 200);
    const { token: t } = await auth.json();
    token = t;
    assert.ok(token);
  });

  it('keepalive works', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/accounts/keepalive`, { method: 'POST', headers: { 'X-Subject-Token': token } });
    assert.equal(r.status, 200);
  });

  it('current returns user', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/accounts/current`, { headers: { 'X-Subject-Token': token } });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.userName, USER);
  });

  it('tree/orgs returns valid org', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/orgs`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.orgList && j.orgList.length > 0);
  });

  it('tree/devices returns device', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/devices`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 200);
  });

  it('tree/channels returns channelId format', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/tree/channels`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelType: 1, category: 1 }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.channelList.some(c => c.channelId.includes('$')));
  });

  it('MTS StartVideo returns rtsp/hls urls', async () => {
    const r = await fetch(`${BASE}/brms/api/v1.0/MTS/Video/StartVideo`, { method: 'POST', headers: { 'X-Subject-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId: '1000171$1$0$0', streamType: 1, dataType: 1 }) });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.rtspUrl && j.rtspUrl.includes('rtsp://'));
    assert.ok(j.hlsUrl && j.hlsUrl.includes('/hls'));
  });

  after(async () => {
    await fetch(`${BASE}/brms/api/v1.0/accounts/unauthorize`, { method: 'POST', headers: { 'X-Subject-Token': token } });
    serverProc.kill();
  });
});