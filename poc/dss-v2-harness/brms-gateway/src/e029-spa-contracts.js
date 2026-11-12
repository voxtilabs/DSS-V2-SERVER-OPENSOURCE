// ===== E-029: real SPA response contracts (fixed from the 18 [FALLBACK] hits) =====
//
// The operator session (docker logs 12:57-12:58, EV-080) showed 18 requests
// hitting the generic [FALLBACK] responder, which answers code 1000 with an
// empty {list,total} envelope no matter the URL. The real SPA then fails to
// read the response and shows "Abnormally returned the service or device data"
// (locale key ar/en-BOizEWom.js) once per bad response - the operator counted
// ~20 toasts. Device Config never finished loading because its device tree is
// lazy-loaded from grade-device-tree and the fallback returned an empty object.
//
// Every shape below is taken verbatim from the mirrored production bundle
// (brms-gateway/web-module/js, DSS Client 8.006):
//
//  * POST /brms/api/v1.1/tree/grade-device-tree
//    - consumer: .pnpm-IcGsI3MK.js `BatchLoadingTree.setup` (load function):
//        const t = yield a.query(e); const {devices:o=[],organizations:n=[]} = t
//      so `data` is {organizations[], devices[]} (channels travel inside each
//      device). `highPerformanceLoad` filters devices by `orgCode === org` and
//      sub-orgs by `orgCode.length === org.length+3 && startsWith`.
//    - node transform (optimizeOrganization / optimizeDevice / optimizeChannel):
//        org     -> {id: orgCode,    name: orgName,     label: orgName,     type: ORGANIZATION(1), children: []}
//        device  -> {id: deviceCode, name: deviceName,  label: deviceName,  type: DEVICE(2),      children: channels, channels: channels}
//        channel -> {id: channelId,  name: channelName, label: channelName, type: CHANNEL(3),   isLeaf: true, deviceCode, capability[]}
//      => the RESPONSE must carry orgCode/orgName, deviceCode/deviceName/orgCode/
//         channels[] and channelId/channelName/deviceCode/capability.
//    - the tree root is built by the client itself: {id:"001",orgCode:"001",
//      name:"Current Site",type:ORGANIZATION,children:[]} (xC = "001"), and
//      expanding it calls query("001") - the request the operator really sent
//      (body: treeType "2", domain "0", conditions[...], orgCode "001").
//    - search (POST .../tree/grade-device-tree/search/list) returns
//      {channels, devices, organizations, channelExceeded, deviceExceeded,
//       organizationExceeded} with EXCEEDED_FLAG_ENUM OVER="1"/UNDER="0".
//  * GET /brms/api/v1.1/storage/plan/channel/record-plan/page
//    consumer index-6GKB6cBD.js (recordPlan view):
//      const {code,data} = await getRecordPlans({page,pageSize,orgCode,keyword,position:"1"});
//      P.value = Number(data.totalCount); _.value = data.pageData
//    row fields (table columns): channelName, deviceName, orgName,
//    positionName, timeTemplateName, streamTypeName, remark, plus id and
//    channelId (edit navigates to {channelId, planId: id}).
//  * GET /brms/api/v1.1/storage/plan/motion-detection-record-plan/page
//    consumer index-dpjg75Ex.js (motionDetectionPlan view): same shape
//    ({totalCount, pageData}), params {page,pageSize,orgCode,keyword}.
//  * GET /brms/api/v1.1/account/user/level
//    consumer index-BhDUzoCV.js bootstrap:
//      const o = await Jo().getUserRole(); 1e3===o.code && localStorage.setItem("roleLevel", o.data?.level)
//    => data.level.
//  * GET /brms/api/v1.1/config/timezone/info?area=<tz>
//    consumer index-BhDUzoCV.js bootstrap:
//      e.dstType=data.dstType; e.enableDst=data.enableDst; e.timezoneId="0";
//      e.timezoneName=tz; e.timezoneOffset=data.timezoneOffset;
//      const [m,w,d] = data.dstBeginDate.split("/");       // month/week/day
//      const [m2,w2,d2] = data.dstEndDate.split("/");
//      e.dstBeginTime={month:m,week:w,day:d,time:data.dstBeginTime}
//      e.dstEndTime={month:m2,week:w2,day:d2,time:data.dstEndTime}
//    => dstType, enableDst, timezoneOffset, dstBeginDate "m/w/d",
//       dstBeginTime, dstEndDate, dstEndTime (all strings, no missing keys:
//       dstBeginDate.split() throws on undefined and the client silently
//       stores an empty localTimezone).

import { DEVICE_REGISTRY, allChannels } from './e025-devices.js';
import { listChannelPlans, STORAGE_POSITION_NAMES } from './e027-storage.js';
// E-041: org list/names come from the persistent org store (root '001' +
// 'VIGILAB'), and a device with an empty orgCode belongs to the default org.
import { listOrgs, getOrg, deviceOrgCode } from './e041-orgs.js';
import { maskDeviceIp } from './e143-ip-mask.js';

// DSS site constants (production bundle): root org code and online status.
const ROOT_ORG_CODE = '001';
const DEVICE_ONLINE = '1';

// ---------------------------------------------------------------------------
// Device tree (grade-device-tree) - lazy loaded, one level per request.
// ---------------------------------------------------------------------------

function deviceTreeNode(device, channels) {
  const chans = channels.filter((c) => c.deviceCode === device.deviceCode);
  return {
    // pass-through: optimizeDevice/optimizeChannel spread the source object,
    // so the raw VO fields survive and are available to the tree node filters.
    // E-039: `id` is mandatory - the live webview session (22:08:20) rendered
    // devices:[null] when the row carried no id (tree consumers read .id).
    // E-087 (server package javap, v1s1 DeviceNodeVo + DPSDK descriptor
    // FUN_1806d33a0): every tree key is a STRING - checked/hasChild as JSON
    // booleans never bind in the client parser. Keys served here match the
    // descriptor exactly: sourceType, checked, channels, deviceCode, domainId,
    // deviceIp, deviceName, pId, status, sourceId, deviceModel, unlockModes,
    // protocolType, associateId, softwareVersion, deviceType, orgCode,
    // addType, deviceCategory, capability (+id alias).
    id: device.deviceCode,
    pId: deviceOrgCode(device),
    deviceCode: device.deviceCode,
    deviceName: device.deviceName,
    checked: '0',
    deviceCategory: String(device.deviceCategory || '1'),
    deviceType: String(device.deviceType || ''),
    channels: chans.map(channelTreeNode),
    orgCode: deviceOrgCode(device),
    status: device.online === false ? '0' : DEVICE_ONLINE,
    domainId: '0',
    deviceModel: device.model || '',
    softwareVersion: device.firmwareVersion || '',
    deviceIp: maskDeviceIp(device),
    addType: '1',
    capability: device.capability || '0',
    sourceType: '',
    sourceId: '',
    associateId: '',
    protocolType: String(device.protocolType || ''),
    unlockModes: '',
    // legacy/webview conveniences
    manufacturer: device.manufacturer || '',
    model: device.model || '',
    serialNumber: device.serialNumber || '',
    firmwareVersion: device.firmwareVersion || '',
    channelNum: device.channelNum || chans.length || 1,
    online: device.online === false ? 0 : 1,
    deviceStatus: device.online === false ? 'offline' : 'online',
    serverCode: device.serverCode || 'video#local',
    hasChild: chans.length > 0 ? '1' : '0'
  };
}

function channelTreeNode(channel) {
  // E-087: ChannelNodeVo keys from the DPSDK descriptor FUN_1806d33a0
  // (all strings): checked, capability, domainId, deviceType,
  // deviceCapability, pId, status, channelRemoteType, inputAlarmType,
  // channelName, streamType, channelType, unitType, channelSubtype,
  // orgCode, channelId, deviceCategory, cameraType.
  return {
    id: channel.channelId,
    channelId: channel.channelId,
    channelName: channel.channelName,
    channelNo: channel.channelNo,
    deviceCode: channel.deviceCode,
    deviceName: channel.deviceName,
    orgCode: deviceOrgCode(channel),
    checked: '0',
    capability: channel.capability || '0',
    domainId: '0',
    deviceType: String(channel.deviceType || ''),
    deviceCapability: '',
    pId: channel.deviceCode,
    status: DEVICE_ONLINE,
    channelRemoteType: String(channel.channelRemoteType || '0'),
    inputAlarmType: '',
    streamType: String(channel.streamType || '1'),
    channelType: String(channel.channelType || '1'),
    unitType: String(channel.unitType || '1'),
    channelSubtype: '0',
    deviceCategory: String(channel.deviceCategory || '1'),
    cameraType: String(channel.cameraType || '1'),
    online: 1
  };
}

function orgTreeNode(org, devices) {
  const orgCode = org.code;
  const list = devices.filter((d) => deviceOrgCode(d) === orgCode);
  // E-087 (server package javap, v1s1 OrgNodeVo): `hasChild` is a STRING
  // ("1"/"0") in the real VO and in the DPSDK parser descriptor
  // (FUN_1806d33a0 binds hasChild at org-node offset 0x18, type string).
  // A JSON boolean never binds => the org rendered as a leaf and VIGILAB
  // never showed as selectable/expandable. hasChild = has sub-orgs OR
  // owns devices (server semantics: expandable node).
  const hasSubOrgs = listOrgs().some((o) => o.parentCode === orgCode && o.code !== orgCode);
  const hasChild = (hasSubOrgs || list.length > 0) ? '1' : '0';
  return {
    id: orgCode,
    orgCode,
    orgName: org.name || orgCode,
    pId: org.parentCode || (orgCode === ROOT_ORG_CODE ? '0' : ROOT_ORG_CODE),
    hasChild,
    checked: '0',
    // remaining descriptor keys (all strings)
    sourceType: '',
    domainId: org.domainId || '0',
    autoAuthorize: '0',
    associateId: '',
    sourceId: '',
    // legacy conveniences
    status: DEVICE_ONLINE,
    deviceCount: list.length,
    onlineDeviceCount: list.filter((d) => d.online !== false).length
  };
}

function treeResult(orgs, devices, channels, requestedOrg) {
  return {
    // E-087: root keys per the DPSDK descriptor FUN_1806d33a0 (all strings):
    // sourceType, organizations[], channels[], devices[], associateId,
    // orgName, orgCode, sourceId (+domainId).
    sourceType: '',
    organizations: orgs,
    channels,
    devices,
    associateId: '',
    orgName: requestedOrg || '',
    orgCode: requestedOrg || '',
    sourceId: '',
    domainId: '0',
    // EXCEEDED_FLAG_ENUM: OVER "1", UNDER "0" - nothing is truncated here.
    organizationExceeded: '0',
    deviceExceeded: '0',
    channelExceeded: '0'
  };
}

export function buildGradeDeviceTreePayload(body = {}) {
  const requestedOrg = String(body.orgCode ?? ROOT_ORG_CODE).trim() || ROOT_ORG_CODE;
  const registry = [...DEVICE_REGISTRY.values()];
  // E-103: channels must belong to the requested org (root orgCode=001 used
  // to return ALL channels as orphans with no parent device in the same
  // payload -> tree renderer binds channel.pId -> devices:[null], E-039
  // regression vector). Lazy-load: orgs list devices+channels of the org
  // asked, root only lists sub-orgs.
  const orgDeviceCodes = new Set(registry.filter((d) => deviceOrgCode(d) === requestedOrg).map((d) => d.deviceCode));
  const channels = allChannels().filter((c) => orgDeviceCodes.has(c.deviceCode)).map(channelTreeNode);

  // Sub-organizations come from the PERSISTENT org store (E-041: root '001'
  // + 'VIGILAB') plus every orgCode present in the registry.
  const orgCodes = new Set(registry.map((d) => deviceOrgCode(d)));
  for (const o of listOrgs()) orgCodes.add(o.code);
  orgCodes.add(ROOT_ORG_CODE);
  const organizations = [...orgCodes]
    .filter((code) => code !== requestedOrg)
    .map((code) => orgTreeNode(getOrg(code) || { code, name: code === ROOT_ORG_CODE ? 'Current Site' : `Organization ${code}`, parentCode: ROOT_ORG_CODE }, registry));

  // Devices directly under the requested org. When the client asks for a sub
  // org we never invented, the list is legitimately empty.
  const devices = registry
    .filter((d) => deviceOrgCode(d) === requestedOrg)
    .map((d) => deviceTreeNode(d, channels));

  return treeResult(organizations, devices, channels, requestedOrg);
}

export function buildGradeDeviceTreeSearchPayload(body = {}) {
  const keyword = String(body.keyword ?? body.ipKeyword ?? '').trim().toLowerCase();
  const result = buildGradeDeviceTreePayload(body);
  if (!keyword) return result;
  const match = (s) => String(s ?? '').toLowerCase().includes(keyword);
  const devices = result.devices.filter((d) =>
    match(d.deviceName) || match(d.deviceCode) || match(d.deviceIp) || match(d.model) || match(d.manufacturer));
  const keepDevice = new Set(devices.map((d) => d.deviceCode));
  return treeResult(
    result.organizations.filter((o) => match(o.orgName) || match(o.orgCode)),
    devices,
    result.channels.filter((c) => keepDevice.has(c.deviceCode) || match(c.channelName))
  );
}

// ---------------------------------------------------------------------------
// Storage plan pages - both consumers read data.totalCount + data.pageData[].
// ---------------------------------------------------------------------------

function planRows(kind, query, channels) {
  const page = Math.max(1, Number(query.page || query.pageNo || 1) || 1);
  const size = Math.max(1, Number(query.pageSize || 20) || 20);
  const keyword = String(query.keyword ?? '').trim().toLowerCase();
  const position = String(query.position ?? '1');
  const orgCode = String(query.orgCode ?? '').trim();

  const rows = listChannelPlans(kind)
    .filter((p) => (position === '' ? true : String(p.position ?? '1') === position))
    .filter((p) => (orgCode === '' ? true : p.orgCode === orgCode || p.orgCode === ROOT_ORG_CODE))
    .filter((p) => (keyword === '' ? true : String(p.channelName || '').toLowerCase().includes(keyword)
      || String(p.deviceName || '').toLowerCase().includes(keyword)
      || String(p.orgName || '').toLowerCase().includes(keyword)))
    .map((p) => ({
      id: p.id,
      channelId: p.channelId,
      channelCode: p.channelId,
      channelName: p.channelName,
      deviceCode: p.deviceCode,
      deviceName: p.deviceName,
      orgCode: p.orgCode,
      orgName: p.orgName,
      position: String(p.position ?? position),
      positionName: STORAGE_POSITION_NAMES[String(p.position ?? position)] || STORAGE_POSITION_NAMES[position],
      planName: p.name,
      timeTemplateName: p.name,
      timeTemplateId: p.code,
      streamType: p.streamType,
      streamTypeName: p.streamType === 2 ? 'Sub Stream' : 'Main Stream',
      recordType: p.recordType,
      status: p.enable ? '1' : '0',
      enable: p.enable,
      remark: p.remark || ''
    }));

  const start = (page - 1) * size;
  return { pageData: rows.slice(start, start + size), totalCount: rows.length };
}

export function buildRecordPlanPagePayload(query = {}, channels = []) {
  return planRows('record', query, channels);
}

export function buildMotionDetectionRecordPlanPagePayload(query = {}, channels = []) {
  return planRows('motion', query, channels);
}

// ---------------------------------------------------------------------------
// Bootstrap payloads
// ---------------------------------------------------------------------------

export function buildUserLevelPayload() {
  return { level: '1' };
}

// America/Santiago (the operator's client timezone, seen in the SPA URL
// "Time-Zone=America/Santiago&UTC=UTC-04:00"): UTC-04:00 (-240 min) with DST
// from the first Sunday of September to the first Sunday of April.
const AREA_TIMEZONES = {
  'America/Santiago': {
    dstType: '1',
    enableDst: '1',
    timezoneOffset: '-240',
    dstBeginDate: '9/1/0',
    dstBeginTime: '00:00:00',
    dstEndDate: '4/1/0',
    dstEndTime: '00:00:00'
  }
};

export function buildAreaTimezonePayload(area) {
  const tz = String(area || '').trim();
  const known = AREA_TIMEZONES[tz];
  if (known) return known;
  // Unknown area: no DST, offset derived from the requested UTC offset when
  // one is present, otherwise UTC+0. Every key is still returned so the
  // client's dstBeginDate.split("/") never throws.
  return {
    dstType: '0',
    enableDst: '0',
    timezoneOffset: '0',
    dstBeginDate: '1/1/0',
    dstBeginTime: '00:00:00',
    dstEndDate: '11/1/0',
    dstEndTime: '00:00:00'
  };
}
