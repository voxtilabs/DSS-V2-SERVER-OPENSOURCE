// E-143a: the camera's internal IP (e.g. 192.168.0.238) must NEVER appear in
// any tree payload served to the DSS client. Tree emitters (e037 native tree,
// e029 SPA tree, e124 grade tree, e139 paged tree) must carry the gateway
// address (PUBLIC_DEVICE_IP) instead; the media path is server-provided.
// Pure module tests: DEVICE_REGISTRY is mutated in memory only, no disk
// writes, no spawned server (node --test runs files in parallel processes).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { maskDeviceIp, PUBLIC_DEVICE_IP } from '../e143-ip-mask.js';
import {
  buildNativeDeviceInfoVo,
  buildNativeChannelVo
} from '../e037-native-tree.js';
import { buildGradeDeviceTreePayload } from '../e029-spa-contracts.js';
import { buildFullGradeDeviceTreePayload } from '../e124-grade-tree.js';
import { pagedDeviceResult } from '../e139-paged-tree.js';
import { DEVICE_REGISTRY } from '../e025-devices.js';

const CAMERA_IP = '192.168.0.238';
const CODE = 'E143CAM';
function makeDevice() {
  return {
    deviceCode: CODE, deviceId: CODE, deviceName: 'E-143 leak test',
    deviceIp: CAMERA_IP, devicePort: 8021, protocolType: '99',
    deviceCategory: '1', deviceType: '2', orgCode: 'VIGILAB',
    online: 1, status: 1, channelNum: 2, model: 'IPC-HDW', manufacturer: 'Dahua'
  };
}
function assertNoCameraIp(payload, label) {
  const text = JSON.stringify(payload);
  assert.ok(text, `${label} serializes`);
  assert.ok(!text.includes(CAMERA_IP), `${label} must not leak the camera IP`);
  assert.ok(text.includes(PUBLIC_DEVICE_IP), `${label} carries the gateway IP`);
}

describe('E-143a tree IP masking', () => {
  before(() => { DEVICE_REGISTRY.set(CODE, makeDevice()); });
  after(() => { DEVICE_REGISTRY.delete(CODE); });

  it('maskDeviceIp maps the camera IP to the gateway and keeps empty empty', () => {
    assert.equal(maskDeviceIp({ deviceIp: CAMERA_IP }), PUBLIC_DEVICE_IP);
    assert.equal(maskDeviceIp({ deviceIp: '' }), '');
    assert.equal(maskDeviceIp({}), '');
  });

  it('native DeviceInfoVo (tree/devices) leaks no camera IP', () => {
    const vo = buildNativeDeviceInfoVo(makeDevice());
    assert.ok(vo.deviceIp, 'deviceIp stays truthy (client contract)');
    assert.equal(vo.deviceIp, PUBLIC_DEVICE_IP);
    assertNoCameraIp(vo, 'DeviceInfoVo');
    for (const unit of vo.units) {
      for (const ch of unit.channels) {
        assert.equal(ch.ipcIp, PUBLIC_DEVICE_IP, 'channel ipcIp masked');
        assert.ok(!JSON.stringify(ch).includes(CAMERA_IP), 'channel leaks no camera IP');
      }
    }
  });

  it('native ChannelVo masks ipcIp directly', () => {
    const ch = buildNativeChannelVo(makeDevice(), 0);
    assert.equal(ch.ipcIp, PUBLIC_DEVICE_IP);
    assertNoCameraIp(ch, 'ChannelVo');
  });

  it('SPA grade tree device node leaks no camera IP', () => {
    const payload = buildGradeDeviceTreePayload({ orgCode: 'VIGILAB' });
    assertNoCameraIp(payload, 'SPA grade tree');
  });

  it('full grade-device-tree (e124) leaks no camera IP', () => {
    const payload = buildFullGradeDeviceTreePayload({ orgCode: 'VIGILAB' });
    assertNoCameraIp(payload, 'full grade tree');
  });

  it('paged tree device row (e139) leaks no camera IP', () => {
    const row = pagedDeviceResult(makeDevice());
    assert.ok(row.deviceIp, 'paged deviceIp stays truthy');
    assert.equal(row.deviceIp, PUBLIC_DEVICE_IP);
    assertNoCameraIp(row, 'paged device row');
  });
});
