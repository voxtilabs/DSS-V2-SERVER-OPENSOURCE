// ===========================================================================
// E-139 - PAGED TREE contract FUN_18071dac0 (DPSDK.dll 0x18071dac0)
//
// REA ses_e3c071651ffeoKjtc23nzZtAEO (rea-grade-tree.md Q2.3): the SECOND tree
// schema - the one behind v1.0/tree/orgs | tree/devices | tree/channels and
// v1.1/tree/deviceOrg - is PAGED and uses DIFFERENT key names than the grade
// tree (FUN_1806d33a0):
//   root:      { totalCount (0x00), results[] (0x08, element 0xe0) }
//   results[]: sourceType(0x00) assistStream(0x08) capability(0x10) domainId(0x18)
//              isParent(0x38) sourceId(0x40) manufacturer(0x48) channelSeq(0x58)
//              decodeMode(0x60) channelRemoteType(0x68) deviceModel(0x78)
//              online(0x88) subType(0x90) nodeType(0x98) cameraType(0xa0)
//              channelType(0xa8) unitType(0xb0) parentName(0xb8) orgName(0xc0)
//              parentId(0xc8) category(0xd0) parkingStatisticsMode(0xd8)
//   - linkage is parentId (NOT pId / NOT parentCode in this schema)
//   - state key is `online`, typeCode=2 => STRING "1" (a JSON number is dropped)
//   - nodeType: 0 = site/org-root, 1 = device, 2 = channel (UICommonModule
//     CGroupSortFilterProxyModel filterAcceptsRow 0x18001e2a9 reads this role;
//     hasChild role 0x2ff on orgs is REQUIRED for the node to expand)
// The existing v1.0 payloads (departments/devices/channelList with parentCode)
// are KEPT as aliases; this module only ADDS the paged {totalCount, results}.
// ===========================================================================
import { DEVICE_REGISTRY, dssChannelCode } from './e025-devices.js';
import { listOrgs, deviceOrgCode } from './e041-orgs.js';
import { filterNativeDevices, DSS_ROOT_ORG } from './e037-native-tree.js';
import { maskDeviceIp } from './e143-ip-mask.js';

const str = (v) => (v === null || v === undefined ? '' : String(v));

function registryDevices() {
  return [...DEVICE_REGISTRY.values()];
}

// ---- orgs ---------------------------------------------------------------
export function pagedOrgResult(org) {
  const orgs = listOrgs();
  const devices = registryDevices();
  const devs = devices.filter((d) => deviceOrgCode(d) === org.code);
  const childCount = orgs.filter((o) => o.parentCode === org.code && o.code !== org.code).length;
  const parent = orgs.find((o) => o.code === org.parentCode);
  const hasKids = childCount > 0 || devs.length > 0;
  return {
    // FUN_18071dac0 results[] element fields (all scalars STRING, typeCode=2)
    sourceType: '0', assistStream: '0', capability: '', domainId: str(org.domainId || DSS_ROOT_ORG.domainId),
    isParent: hasKids ? '1' : '0', sourceId: '', manufacturer: '', channelSeq: '0',
    decodeMode: '0', channelRemoteType: '0', deviceModel: '',
    online: '1',                          // 0x88 - STRING (JSON number is dropped)
    subType: '0', nodeType: '0',          // 0x98 - 0 = org/site node
    cameraType: '', channelType: '', unitType: '',
    parentName: parent ? str(parent.name) : '', orgName: str(org.name),
    parentId: str(org.parentCode),        // 0xc8 - linkage in THIS schema
    category: '', parkingStatisticsMode: '0',
    // identity + aliases (grade-tree / SPA parsers)
    code: str(org.code), id: str(org.code), name: str(org.name),
    orgCode: str(org.code), parentCode: str(org.parentCode),
    hasChild: hasKids ? '1' : '0',        // role 0x2ff - mandatory to expand
    checked: '0', hasAuthority: '1', authority: '1', disabled: '0', selectable: '1',
    orgType: str(org.orgType || '1'), deparmentsCount: String(childCount),
    sort: '0',
    device: devs.map((d, i) => ({ id: str(d.deviceCode), sort: String(i) })),
    channel: []
  };
}

// ---- devices --------------------------------------------------------------
export function pagedDeviceResult(d) {
  const orgCode = str(deviceOrgCode(d));
  const status = str(d.online ?? d.status ?? 1);
  const orgs = listOrgs();
  const parent = orgs.find((o) => o.code === orgCode);
  return {
    sourceType: str(d.sourceType || '0'), assistStream: '0', capability: '',
    domainId: str(d.domainId || DSS_ROOT_ORG.domainId),
    isParent: '1', sourceId: str(d.sourceId || ''), manufacturer: str(d.manufacturer || ''),
    channelSeq: '0', decodeMode: '0', channelRemoteType: '0',
    deviceModel: str(d.model || ''),
    online: status,                        // STRING "1"
    subType: '0', nodeType: '1',           // 1 = device (hidden if offline & showOfflineNode=0)
    cameraType: '', channelType: '', unitType: '1',
    parentName: parent ? str(parent.name) : '', orgName: parent ? str(parent.name) : '',
    parentId: orgCode,                     // device -> owning org
    category: str(d.deviceCategory || '1'), parkingStatisticsMode: '0',
    // identity + aliases
    code: str(d.deviceCode), id: str(d.deviceCode), name: str(d.deviceName),
    deviceCode: str(d.deviceCode), deviceName: str(d.deviceName), deviceId: str(d.deviceCode),
    orgCode, parentCode: orgCode, status, onlineStatus: status,
    deviceType: str(d.deviceType || '1'), deviceCategory: str(d.deviceCategory || '1'),
    deviceIp: maskDeviceIp(d), devicePort: str(d.devicePort || ''),
    protocolType: str(d.protocolType || ''), sn: str(d.serialNumber || ''),
    serverCode: str(d.serverCode || ''), addType: str(d.source || ''),
    checked: '0', hasAuthority: '1', authority: '1', hasChild: '1',
    sort: '0', channelNum: Math.max(1, Number(d.channelNum) || 1)
  };
}

// ---- channels -------------------------------------------------------------
export function pagedChannelResult(d, seq) {
  const s = Math.max(0, Number(seq) || 0);
  const code = dssChannelCode(d.deviceCode, s);
  const status = str(d.online ?? d.status ?? 1);
  return {
    sourceType: '0', assistStream: '0', capability: '', domainId: str(d.domainId || DSS_ROOT_ORG.domainId),
    isParent: '0', sourceId: '', manufacturer: '', channelSeq: String(s),
    decodeMode: '0', channelRemoteType: '0', deviceModel: str(d.model || ''),
    online: status,                        // STRING "1"
    subType: '0', nodeType: '2',           // 2 = channel
    cameraType: '', channelType: '1', unitType: '1',
    parentName: str(d.deviceName), orgName: str(deviceOrgCode(d)),
    parentId: str(d.deviceCode),           // channel -> owning device
    category: str(d.deviceCategory || '1'), parkingStatisticsMode: '0',
    // identity + aliases
    code, id: code, name: s === 0 ? str(d.deviceName) : `${d.deviceName} CH${s + 1}`,
    channelId: code, channelCode: code, channelName: s === 0 ? str(d.deviceName) : `${d.deviceName} CH${s + 1}`,
    channelNo: String(s + 1), deviceCode: str(d.deviceCode), deviceName: str(d.deviceName),
    orgCode: str(deviceOrgCode(d)), parentCode: str(d.deviceCode),
    status, onlineStatus: status, channelStatus: status,
    checked: '0', hasAuthority: '1', authority: '1', hasChild: '0',
    sort: String(s), channelType: '1', unitType: '1'
  };
}

// ---- paged envelopes per endpoint -----------------------------------------
export function buildPagedOrgsPayload() {
  const results = listOrgs().map(pagedOrgResult);
  return { totalCount: results.length, results };
}

export function buildPagedDevicesPayload(body = {}) {
  const results = filterNativeDevices(body).map(pagedDeviceResult);
  return { totalCount: results.length, results };
}

export function buildPagedChannelsPayload() {
  const results = [];
  for (const d of registryDevices()) {
    const count = Math.max(1, Number(d.channelNum) || 1);
    for (let seq = 0; seq < count; seq++) results.push(pagedChannelResult(d, seq));
  }
  return { totalCount: results.length, results };
}
