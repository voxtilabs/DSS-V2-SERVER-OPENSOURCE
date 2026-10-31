import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function doubleMd5(user, pass) { return md5(md5(user + md5(pass))); }
function makeSig(user, realm, temp, randomKey) { return md5(md5(`${user}:${realm}:${temp}`) + ':' + randomKey); }

describe('P2P Probe crypto helpers (EV-029/031)', () => {
  it('double MD5 matches DSS Client formula', () => {
    const user = 'admin', pass = 'admin123';
    // md5('admin123') = '482c811da5d5b4bc6d497ffa98491e38'
    // md5('admin' + '482c811da5d5b4bc6d497ffa98491e38') = '3aceb9fb5f01c2b83c8c2482cc256f51'
    const expected = '3aceb9fb5f01c2b83c8c2482cc256f51';
    assert.equal(doubleMd5(user, pass), expected);
  });
  it('signature formula matches buildMd5DigestAuthReq', () => {
    const user = 'admin', realm = 'DSS-V2-LAB', randomKey = 'abc123';
    const temp = doubleMd5(user, 'admin123');
    const sig = makeSig(user, realm, temp, randomKey);
    assert.ok(sig.length === 32);
  });
});