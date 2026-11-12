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
import { maskDeviceIp } from './e143-ip-mask.js';

const str = (v) => String(v ?? '');

function channelNode(device, seq) {
  const code = dssChannelCode(device.deviceCode, seq);
  const name = seq === 0 ? device.deviceName : `${device.deviceName} CH${seq + 1}`;
  // E-143b: real shape (gdt child real, channel "1000013$1$0$0") - 19 keys,
  // channelId (NOT channelCode), pId = deviceCode, checked string.
  return {
    channelId: code,
    pId: device.deviceCode,
    channelName: name,
    unitType: '1',
    channelType: '1',
    channelSubtype: '0',
    channelRemoteType: '0',
    cameraType: '1',
    checked: '1',
    orgCode: deviceOrgCode(device),
    deviceType: '1',
    deviceCategory: '1',
    deviceCapability: '1024',
    capability: '0',
    status: str(device.online ?? device.status ?? 1),
    domainId: '',
    inputAlarmType: '',
    // E-160: highest available stream (1 = main, 2 = +sub1, 3 = +sub2) — the
    // client checks it before opening a sub stream.
    streamType: '3'
  };
}

function deviceNode(device, adminChecked) {
  const count = Math.max(1, Number(device.channelNum) || 1);
  const channels = [];
  for (let s = 0; s < count; s++) channels.push(channelNode(device, s));
  // E-143b: real shape (gdt device "1000013" ABU) - 19 keys.
  return {
    deviceCode: device.deviceCode,
    pId: deviceOrgCode(device),
    deviceName: device.deviceName,
    checked: adminChecked ? '1' : '0',
    deviceCategory: '1',
    deviceType: '1',
    channels,
    orgCode: deviceOrgCode(device),
    status: str(device.online ?? device.status ?? 1),
    domainId: '',
    deviceModel: str(device.model || ''),
    softwareVersion: '',
    deviceIp: maskDeviceIp(device),
    addType: '4',
    capability: '1024',
    sourceType: '1',
    sourceId: null,
    associateId: '',
    protocolType: '1',
    unlockModes: null
  };
}

function orgNode(org, scopedDevices, allDevices, adminChecked, scopeCode) {
  // E-140: in scoped (lazy) mode the response must carry ONLY the direct
  // children of the requested orgCode. The native Resources tree does NOT
  // re-parent by pId/orgCode (UICommonModule CreateChildItem 0x1804f2200 ->
  // QStandardItem::appendRows hangs EVERY organizations[]/devices[] element
  // as a direct child of the expanded node), so the SERVER must scope.
  const scoped = scopeCode !== '';
  const realChildren = listOrgs().filter((o) => o.parentCode === org.code && o.code !== org.code);
  const children = scoped ? [] : realChildren; // no recursion in lazy mode
  const ownAll = allDevices.filter((d) => deviceOrgCode(d) === org.code);
  const own = scopedDevices.filter((d) => deviceOrgCode(d) === org.code);
  const devNodes = own.map((d) => deviceNode(d, adminChecked));
  // E-143b: real shape (gdt org "001001" Patronato) - 9 keys ONLY:
  // {orgCode, pId, orgName, checked, domainId, sourceType, sourceId,
  //  associateId, hasChild, autoAuthorize}. The real hasChild reflects the
  // full (unscoped) children so the expander arrow still renders in lazy mode.
  const isRoot = str(org.code) === '001';
  return {
    orgCode: org.code,
    pId: org.parentCode,
    orgName: org.name,
    checked: adminChecked ? '1' : '0',
    domainId: isRoot ? '0' : '',
    sourceType: '1',
    sourceId: null,
    associateId: '',
    hasChild: (realChildren.length || ownAll.length) ? '1' : '0',
    autoAuthorize: '1',
    organizations: children.map((c) => orgNode(c, scopedDevices, allDevices, adminChecked, scopeCode)),
    devices: devNodes
  };
}

export function buildFullGradeDeviceTreePayload(query = {}) {
  // admin (roleId 1 / roleType Administrator) gets every node pre-checked;
  // any other role starts unchecked but still selectable (hasAuthority 1).
  const roleId = str(query.roleId || query.roleCode || '1');
  const roleType = str(query.roleType || '').toLowerCase();
  const adminChecked = roleId === '1' || roleType === 'administrator' || roleType === '1' || query.admin === '1';
  const allDevices = [...DEVICE_REGISTRY.values()];
  const orgs = listOrgs();
  // ===== E-140: scope the payload by orgCode (lazy expansion) =====
  // REA (rea-dataflow-resources.md, 2026-11-10): the native Monitoring Center
  // Resources tree is populated ONLY by GET /brms/api/v1.1/tree/full/grade-device-tree
  // ?orgCode=<node>&roleId=1 (HanldeQueryGradeDeviceTree 0x1804f1d70 ->
  // IGroupManager::GetGradeDeviceTree vfunc +0x3c0). CreateChildItem 0x1804f2200
  // does NOT re-pair by pId/orgCode: it appends EVERY organizations[]/devices[]
  // of the response as DIRECT children of the expanded node. The server MUST
  // therefore return only the direct children of the requested orgCode:
  //   orgCode absent/'' or scope=full -> full tree (role dialog + admin mirror)
  //   orgCode = '001'    -> orgs with parentCode==='001' (VIGILAB), devices orgCode==='001' (none)
  //   orgCode = 'VIGILAB'-> devices with orgCode==='VIGILAB' + nested channels[]
  // (E-137's "client rebuilds the hierarchy from the flat list" premise was
  // refuted by REA - the flattening is client-side by design.)
  const requested = str(query.orgCode ?? query.org ?? '').trim();
  const forceFull = str(query.scope || '').toLowerCase() === 'full';
  const scopeCode = (requested === '' || forceFull) ? '' : requested;
  const scopedDevices = scopeCode === ''
    ? allDevices
    : allDevices.filter((d) => deviceOrgCode(d) === scopeCode);
  const scopedOrgs = scopeCode === ''
    ? orgs
    : orgs.filter((o) => o.parentCode === scopeCode && o.code !== scopeCode);
  // Full mode (no orgCode): organizations/departments FLAT (every org, linked
  // by pId) AND nested children inside each node - the role-dialog renderer
  // walks nested children while other consumers bind the flat list by pId.
  const organizations = scopedOrgs.map((o) => orgNode(o, scopedDevices, allDevices, adminChecked, scopeCode));
  const flatDevices = scopedDevices.map((d) => deviceNode(d, adminChecked));
  const flatChannels = [];
  for (const d of scopedDevices) {
    const count = Math.max(1, Number(d.channelNum) || 1);
    for (let s = 0; s < count; s++) flatChannels.push(channelNode(d, s));
  }
  // E-143b: real shape (gdt root real "001") - data carries EXACTLY these 11
  // keys: {orgCode, orgName, checked, domainId, autoAuthorize, sourceType,
  // sourceId, associateId, organizations, devices, channels}. Every harness
  // alias (orgList/departments/deivceNodes/roleType/hasData/*Exceeded/total)
  // was a hypothesis the real server never sends.
  const rootOrg = orgs.find((o) => o.code === '001') || orgs[0] || { code: '001', name: 'Current Site' };
  return {
    orgCode: scopeCode || str(rootOrg.code),
    orgName: scopeCode ? (orgs.find((o) => o.code === scopeCode) || {}).name || '' : str(rootOrg.name),
    checked: '1',
    domainId: scopeCode ? '' : '0',
    autoAuthorize: '1',
    sourceType: '1',
    sourceId: null,
    associateId: null,
    organizations,
    devices: flatDevices,
    channels: flatChannels
  };
}

export function buildFullGradeDeviceTreeSearchPayload(query = {}) {
  const kw = str(query.keyword || query.keywords || '').toLowerCase();
  // E-140: search always scans the FULL tree (scope=full), regardless of any
  // orgCode that came along with the search request.
  const full = buildFullGradeDeviceTreePayload({ ...query, scope: 'full' });
  if (!kw) return full;
  const hitDev = full.devices.filter((d) =>
    d.deviceCode.toLowerCase().includes(kw) || d.deviceName.toLowerCase().includes(kw));
  const hitCh = full.channels.filter((c) =>
    c.channelId.toLowerCase().includes(kw) || c.channelName.toLowerCase().includes(kw));
  return {
    ...full,
    devices: hitDev,
    channels: hitCh
  };
}
