// ===== E-124: full grade device tree for the Role/User permission dialogs ===
//
// RE evidence (DPSDK.dll string pool, subagent 2026-11-08):
//   GET v1.1/tree/full/grade-device-tree            @0xc9cc40
//     -> GetFullGradeDeviceTree @0xc9cc10 -> BRMS.Tree.GetFullGradeDeviceTree
//        @0xcdb070/0xcdb090; UserLogical wrapper
//        HandleQueryRoleConfigGradeDeviceTree (UserLogical.dll 0xc5560)
//        -> DPSDK_GetFullGradeDeviceTree @0xf7f56
//   GET v1.1/tree/full/grade-device-tree/search/list @0xc9cb40
//   variants: v1.1/tree/grade-device-tree @0xc9cce0, v1.1/tree/device-tree @0xc9cd68
//   Node JSON keys (pool): organizations @0xcda368, checked @0xcda378,
//   hasChild @0xcda380, deviceCapability @0xcda390, isParent @0xcdd560,
//   parentName @0xcdd570; resource keys: deivceNodes @0xcd9348 (SDK typo,
//   kept), menuNodes @0xcd9358, functionNodes @0xcd9370, roleType @0xcd9308;
//   authority: hasAuthority @0xcd3168, hasPermission @0xcd3020,
//   authority @0xcacfd8, orgCodes @0xcacfe8.
//   UI: PlatformConfigUI::CRoleManagerEditDlg (PluginFactory.dll 0x19e0210)
//   renders 4 trees (device/control/menu/subsystem); a node is CLICKABLE when
//   checked binds (string) and hasAuthority is "1" - there is NO "disabled"
//   JSON field; the grey state came from authority/checked never binding.
//
// Shape served (superset, all flags STRING per the E-095/E-087 lesson):
//   { organizations: [ OrgNode ], devices: [...], channels: [...], ... }
//   OrgNode: { orgCode, orgName, code, name, parentCode, isParent, hasChild,
//              checked, hasAuthority, hasPermission, authority,
//              organizations: [children], devices: [DeviceNode] }
//   DeviceNode: { deviceCode, deviceName, code, name, orgCode, checked,
//                 hasAuthority, hasChild, isParent, status, channels: [...] }
//   ChannelNode: { channelCode, channelName, id, name, deviceCode, orgCode,
//                  checked, hasAuthority, hasChild: '0', isParent: '0', status }
import { DEVICE_REGISTRY, allChannels, dssChannelCode } from './e025-devices.js';
import { listOrgs, deviceOrgCode } from './e041-orgs.js';

const str = (v) => String(v ?? '');

function channelNode(device, seq) {
  const code = dssChannelCode(device.deviceCode, seq);
  const name = seq === 0 ? device.deviceName : `${device.deviceName} CH${seq + 1}`;
  return {
    channelCode: code, channelId: code, id: code, code,
    channelName: name, name,
    // E-126: pId is the parent binding the native tree renderer uses
    // (channel.pId -> deviceCode); without it devices render orphaned.
    pId: device.deviceCode,
    deviceCode: device.deviceCode, orgCode: deviceOrgCode(device),
    checked: '1', hasAuthority: '1', hasPermission: '1', authority: '1',
    hasChild: '0', isParent: '0', disabled: '0', selectable: '1',
    status: str(device.online ?? device.status ?? 1), channelSeq: String(seq),
    parentCode: device.deviceCode, sort: String(seq),
    // E-126: remaining native descriptor keys (FUN_1806d33a0 pool)
    channelType: '1', channelSubtype: '0', streamType: '0', unitType: '1',
    cameraType: '1', capability: '', deviceCapability: '1',
    sourceType: str(device.sourceType || ''), associateId: '', sourceId: '',
    autoAuthorize: '1', deviceIp: str(device.deviceIp || ''), deviceModel: str(device.model || ''),
    protocolType: str(device.protocolType || '')
  };
}

function deviceNode(device, adminChecked) {
  const count = Math.max(1, Number(device.channelNum) || 1);
  const channels = [];
  for (let s = 0; s < count; s++) channels.push(channelNode(device, s));
  const checked = adminChecked ? '1' : '0';
  return {
    deviceCode: device.deviceCode, deviceId: device.deviceCode,
    code: device.deviceCode, id: device.deviceCode,
    deviceName: device.deviceName, name: device.deviceName,
    // E-126: pId = owning org (device.pId -> orgCode binding)
    pId: deviceOrgCode(device),
    orgCode: deviceOrgCode(device), parentCode: deviceOrgCode(device),
    checked, hasAuthority: '1', hasPermission: '1', authority: '1',
    hasChild: channels.length ? '1' : '0', isParent: channels.length ? '1' : '0',
    disabled: '0', selectable: '1',
    status: str(device.online ?? device.status ?? 1),
    deviceType: str(device.deviceType || '1'), deviceCategory: str(device.deviceCategory || '1'),
    deviceCapability: '1', sort: '0',
    // E-126: remaining native descriptor keys
    deviceIp: str(device.deviceIp || ''), devicePort: str(device.devicePort || ''),
    deviceModel: str(device.model || ''), capability: '', unitType: '1',
    sourceType: str(device.sourceType || ''), associateId: '', sourceId: '',
    autoAuthorize: '1', protocolType: str(device.protocolType || ''),
    channels, channel: channels, channelList: channels
  };
}

function orgNode(org, devices, allDevices, adminChecked) {
  const children = listOrgs().filter((o) => o.parentCode === org.code && o.code !== org.code);
  const own = devices.filter((d) => deviceOrgCode(d) === org.code);
  const devNodes = own.map((d) => deviceNode(d, adminChecked));
  const checked = adminChecked ? '1' : '0';
  const node = {
    orgCode: org.code, code: org.code, id: org.code,
    orgName: org.name, name: org.name,
    // E-126: pId = parent org (the native tree binds node.pId -> parent)
    pId: org.parentCode,
    parentCode: org.parentCode, parentName: (listOrgs().find((o) => o.code === org.parentCode) || {}).name || '',
    orgType: str(org.orgType || '1'), domainId: str(org.domainId || '0'),
    isParent: children.length ? '1' : '0',
    hasChild: (children.length || devNodes.length) ? '1' : '0',
    checked, hasAuthority: '1', hasPermission: '1', authority: '1',
    disabled: '0', selectable: '1',
    deparmentsCount: String(children.length), deviceCount: String(devNodes.length),
    sort: '0',
    // E-126: remaining native descriptor keys
    sourceType: '', associateId: '', sourceId: '', autoAuthorize: '1',
    capability: '', deviceCapability: '1',
    organizations: children.map((c) => orgNode(c, devices, allDevices, adminChecked)),
    devices: devNodes, device: devNodes.map((d) => ({ id: d.deviceCode, sort: '0' })),
    deviceList: devNodes, deivceNodes: devNodes, // SDK typo key kept (0xcd9348)
    channel: devNodes.flatMap((d) => d.channels.map((c) => ({ id: c.channelCode, sort: c.channelSeq })))
  };
  return node;
}

export function buildFullGradeDeviceTreePayload(query = {}) {
  // admin (roleId 1 / roleType Administrator) gets every node pre-checked;
  // any other role starts unchecked but still selectable (hasAuthority 1).
  const roleId = str(query.roleId || query.roleCode || '1');
  const roleType = str(query.roleType || '').toLowerCase();
  const adminChecked = roleId === '1' || roleType === 'administrator' || roleType === '1' || query.admin === '1';
  const allDevices = [...DEVICE_REGISTRY.values()];
  const orgs = listOrgs();
  // E-137: serve organizations/departments FLAT (every org, linked by pId)
  // AND keep the nested `organizations` children inside each node. The native
  // parser builds the hierarchy from parentCode over the flat list, while the
  // role-dialog renderer walks nested children; serving roots-only collapsed
  // the Monitoring Center Resources tree to the static "Browser" node.
  const organizations = orgs.map((o) => orgNode(o, allDevices, allDevices, adminChecked));
  const flatDevices = allDevices.map((d) => deviceNode(d, adminChecked));
  const flatChannels = [];
  for (const d of allDevices) {
    const count = Math.max(1, Number(d.channelNum) || 1);
    for (let s = 0; s < count; s++) flatChannels.push(channelNode(d, s));
  }
  return {
    organizations,
    orgList: organizations,
    departments: organizations,
    devices: flatDevices,
    deviceList: flatDevices,
    deivceNodes: flatDevices,
    channels: flatChannels,
    channelList: flatChannels,
    list: organizations,
    items: organizations,
    results: organizations,
    roleType: adminChecked ? '1' : '2',
    hasData: '1',
    // EXCEEDED_FLAG_ENUM values ("0" = UNDER, nothing truncated) - the SPA
    // BatchLoadingTree.load asserts them on the grade-device-tree payload
    deviceExceeded: '0',
    organizationExceeded: '0',
    channelExceeded: '0',
    total: String(organizations.length),
    totalCount: String(organizations.length)
  };
}

export function buildFullGradeDeviceTreeSearchPayload(query = {}) {
  const kw = str(query.keyword || query.keywords || '').toLowerCase();
  const full = buildFullGradeDeviceTreePayload(query);
  if (!kw) return full;
  const hitDev = full.devices.filter((d) =>
    d.deviceCode.toLowerCase().includes(kw) || d.deviceName.toLowerCase().includes(kw));
  const hitCh = full.channels.filter((c) =>
    c.channelCode.toLowerCase().includes(kw) || c.channelName.toLowerCase().includes(kw));
  return {
    ...full,
    devices: hitDev, deviceList: hitDev, deivceNodes: hitDev,
    channels: hitCh, channelList: hitCh,
    list: hitDev, items: hitDev, results: hitDev,
    total: String(hitDev.length), totalCount: String(hitDev.length)
  };
}
