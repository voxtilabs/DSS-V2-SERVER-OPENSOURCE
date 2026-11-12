// ===== E-124: full grade device tree for the Role/User permission dialogs ====
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
// ---------------------------------------------------------------------------
// E-163 - IDEMPOTENT TREE (duplicate accumulation fix)
// ---------------------------------------------------------------------------
// Symptom: the Monitoring Center Resources tree accumulated duplicate rows
// forever (2 -> 6 -> 44 -> 58 -> 156 -> 324 -> 352 -> ... -> 562) while the
// server only ever held 2 devices.
//
// Measured (2026-11-12, gateway request journal + Frida on DSS Client 5344):
//   * the growth is NOT driven by a new HTTP request: 0 grade-device-tree
//     requests are logged while the counter climbs (the client re-appends the
//     children it already holds from its parsed model).
//   * every rebuild appends ONE QStandardItem::appendRows batch of EXACTLY 4
//     items (Qt5Gui ?appendRows@QStandardItem@@QEAAXAEBV?$QList@...), i.e. the
//     2 element copies the old payload served twice: data.devices[] (2) +
//     data.channels[] (2).
//   * the old payload repeated the same channel in FOUR arrays and the same
//     device in THREE (data.devices[] + organizations/001/VIGILAB.devices[] +
//     organizations/VIGILAB.devices[]): 6 device nodes / 6+2 channel nodes for
//     2 devices (measured with /tmp/e163-measure.js against the live gateway).
//
// Contract now served: EXACTLY ONE copy of every node.
//   organizations[] : org nodes. Each org carries its own devices (canonical
//                     location of a device) and each device its channels.
//                     Scoped (lazy) requests return only the DIRECT children
//                     of the requested orgCode, with hasChild coherent so the
//                     expander arrow still renders.
//   devices[]       : []  - the device nodes already live under their org
//                     (serving them again made the client append a second
//                     copy to the expanded node on every rebuild).
//   channels[]      : []  - the channel nodes already live under their device.
// Every flag stays a STRING (the native matchers never coerce).
//
// Shape:
//   { organizations: [ OrgNode ], devices: [], channels: [], ... }
//   OrgNode: { orgCode, orgName, checked, domainId, autoAuthorize, sourceType,
//              sourceId, associateId, hasChild, pId, organizations: [children],
//              devices: [DeviceNode] }
//   DeviceNode: { deviceCode, deviceName, code, name, orgCode, checked,
//                 hasAuthority, hasChild, isParent, status, channels: [...] }
//   ChannelNode: { channelId, channelName, id, name, deviceCode, orgCode,
//                  checked, hasAuthority, hasChild: '0', isParent: '0', status }
import { DEVICE_REGISTRY, dssChannelCode } from './e025-devices.js';
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

function devicesOf(orgCode, allDevices) {
  return allDevices.filter((d) => deviceOrgCode(d) === orgCode);
}

function childOrgsOf(orgCode, orgs) {
  return orgs.filter((o) => o.parentCode === orgCode && o.code !== orgCode);
}

// OrgNode (9 real keys + pId + the two child arrays the client walks).
// E-143b: real shape (gdt org "001001" Patronato) - {orgCode, pId, orgName,
// checked, domainId, sourceType, sourceId, associateId, hasChild,
// autoAuthorize}. E-163: hasChild is coherent with what THIS response serves
// (children of the node) so the expander arrow is only drawn when a child
// request can return something.
function orgNodeShape(org, childCount, deviceCount, adminChecked) {
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
    hasChild: (childCount || deviceCount) ? '1' : '0',
    autoAuthorize: '1'
  };
}

// SCOPED (lazy) node: only the direct children of the requested orgCode are
// served. E-163: the node itself carries NO children (the client asks again
// with orgCode=<child> when the user expands it) - its devices come back in
// data.devices[] of the CHILD request, so a device is never served twice.
function scopedOrgNode(org, orgs, allDevices, adminChecked) {
  const kids = childOrgsOf(org.code, orgs);
  const own = devicesOf(org.code, allDevices);
  return {
    ...orgNodeShape(org, kids.length, own.length, adminChecked),
    organizations: [],
    devices: []
  };
}

// FULL node: complete canonical tree - every org once, every device once,
// every channel once, linked by hasChild/organizations[]/devices[].
function fullOrgNode(org, orgs, allDevices, adminChecked, seen) {
  const nextSeen = new Set(seen);
  nextSeen.add(org.code);
  const kids = childOrgsOf(org.code, orgs).filter((o) => !nextSeen.has(o.code));
  const own = devicesOf(org.code, allDevices);
  return {
    ...orgNodeShape(org, kids.length, own.length, adminChecked),
    organizations: kids.map((c) => fullOrgNode(c, orgs, allDevices, adminChecked, nextSeen)),
    devices: own.map((d) => deviceNode(d, adminChecked))
  };
}

function scopedHeader(scopeCode, orgs, requested) {
  const isFull = scopeCode === '';
  const root = orgs.find((o) => o.code === '001') || orgs[0] || { code: '001', name: 'Current Site' };
  const scopeOrg = isFull ? root : (orgs.find((o) => o.code === scopeCode) || null);
  return {
    orgCode: isFull ? str(root.code) : scopeCode,
    orgName: scopeOrg ? str(scopeOrg.name) : '',
    checked: '1',
    domainId: isFull ? '0' : '',
    autoAuthorize: '1',
    sourceType: '1',
    sourceId: null,
    associateId: null
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
  //   orgCode = '001'    -> orgs with parentCode==='001' (VIGILAB)
  //   orgCode = 'VIGILAB'-> the org node with its devices + nested channels
  // E-163: no node is served twice (see the header note).
  const requested = str(query.orgCode ?? query.org ?? '').trim();
  const forceFull = str(query.scope || '').toLowerCase() === 'full';
  const scopeCode = (requested === '' || forceFull) ? '' : requested;
  const header = scopedHeader(scopeCode, orgs, requested);
  if (scopeCode === '') {
    // FULL: top-level = only the true roots (E-163: the old payload listed
    // every org flat AND nested, so VIGILAB and its devices appeared twice).
    // Devices live nested under their org - the single canonical copy.
    const roots = orgs.filter((o) => !orgs.some((p) => p.code === o.parentCode && p.code !== o.code));
    const organizations = (roots.length ? roots : orgs)
      .map((o) => fullOrgNode(o, orgs, allDevices, adminChecked, new Set()));
    return { ...header, organizations, devices: [], channels: [] };
  }
  // SCOPED: the direct child orgs of the requested node plus that node's own
  // devices (each device exactly once, its channels nested inside it). The
  // flat channel array stays empty: a channel already hangs under its device,
  // and the client appends channels[] as sibling rows on every rebuild
  // (E-163: that duplicate produced half of the accumulated rows).
  const organizations = childOrgsOf(scopeCode, orgs)
    .map((o) => scopedOrgNode(o, orgs, allDevices, adminChecked));
  const devices = devicesOf(scopeCode, allDevices).map((d) => deviceNode(d, adminChecked));
  return { ...header, organizations, devices, channels: [] };
}

// Channel list of one device (kept for consumers that need a flat channel
// feed - the search endpoint and the /admin RPC mirror).
function flatChannelsOf(devices) {
  const out = [];
  for (const d of devices) {
    const count = Math.max(1, Number(d.channelNum) || 1);
    for (let s = 0; s < count; s++) out.push(channelNode(d, s));
  }
  return out;
}

// E-163: keyword filtering walks the canonical nested tree; the result keeps
// the same single-copy layout (orgs that survive keep only matching devices).
function filterFullTree(organizations, kw) {
  const hitDevice = (d) =>
    str(d.deviceCode).toLowerCase().includes(kw) ||
    str(d.deviceName).toLowerCase().includes(kw) ||
    (d.channels || []).some((c) =>
      str(c.channelId).toLowerCase().includes(kw) || str(c.channelName).toLowerCase().includes(kw));
  const walk = (nodes) => {
    const out = [];
    for (const o of nodes) {
      const kids = walk(o.organizations || []);
      const devs = (o.devices || []).filter(hitDevice);
      if (kids.length || devs.length) out.push({ ...o, organizations: kids, devices: devs });
    }
    return out;
  };
  return walk(organizations);
}

export function buildFullGradeDeviceTreeSearchPayload(query = {}) {
  const kw = str(query.keyword || query.keywords || '').toLowerCase();
  // E-140: search always scans the FULL tree (scope=full), regardless of any
  // orgCode that came along with the search request.
  const full = buildFullGradeDeviceTreePayload({ ...query, scope: 'full' });
  // An empty keyword lists everything (filterFullTree keeps every node), so the
  // result is always the flat device feed + the canonical nested tree.
  // The search view renders a FLAT result list, so the matched devices are
  // returned both where they belong (nested under their org) and once in
  // devices[] - this endpoint never feeds a tree rebuild (E-163).
  const matched = [];
  const collect = (nodes) => {
    for (const o of nodes) {
      matched.push(...(o.devices || []));
      collect(o.organizations || []);
    }
  };
  const organizations = filterFullTree(full.organizations, kw);
  collect(organizations);
  return { ...full, organizations, devices: matched, channels: [] };
}

// E-163: exported for the tests - the exact number of device nodes a payload
// serves (must equal the number of registered devices in scope, no copies).
export function countDeviceNodes(organizations, devices = []) {
  let n = devices.length;
  for (const o of organizations || []) {
    n += (o.devices || []).length;
    n += countDeviceNodes(o.organizations || []);
  }
  return n;
}

// Flat channel catalogue of the deployment (each channel once), for callers
// that need the feed without walking the tree.
export function allGradeChannels() {
  return flatChannelsOf([...DEVICE_REGISTRY.values()]);
}
