// ===== E-037: REAL native DSS contracts (menu catalog, function rights,
// native device/org tree) =====================================================
//
// Every value in this file comes from the ORIGINAL DSS SERVER V8.008 package
// (General_DSS-Ultimate_Server_Win64_IS_V8.008.0000000.0.R.20260930.exe),
// decoded with the E-009 pipeline (outer-db.bin + LZMA blocks + javap):
//
//  A) sys_menu seed table (p_data.sql, 86 rows)
//       MenuVo{menuCode, menuName, pid}  <- com.dcc.admin.restapi.api.v1s1.menu.vo.MenuVo
//       MenuController.getMenusById(Long) -> ResponseInfo<ListVo<MenuVo>>
//       GET /brms/api/v1.1/menu/available/list
//     MENU_CODE -> menuCode, MEMO -> menuName, MENU_NAME -> i18n key (menuNameKey),
//     parent code derived from the 3-digit DSS code hierarchy (pid).
//
//  B) sys_role_menu_default_relation (p_data.sql)
//       ROLE_TYPE 1 = Super Administrator -> ALL 86 menus (the role our admin
//       account holds). ROLE_TYPE 2 -> 81, ROLE_TYPE 3 -> 68.
//
//  C) adm_role_function (p_data.sql) + com.dcc.admin.restapi.common.constant.FunctionType
//       FunctionType enum -> the real function codes:
//         record=1 ptzOperateAndConfig=2 talk=3 recordLock=5 recordTips=6
//         liveView=8 playback=9 download=10 privacyMasking=11 ptzOperate=13
//         syncTime=15 livePreview=17 deviceWeb=21 broadcast=23 playAudio=24
//         controlVolume=25 panoramicSplicing=27
//       adm_role_function(ROLE_ID=1) -> '1','2','3','5','6','8','9','10','11'
//       => the Super Administrator owns liveView(8) and playback(9).
//       BRM.User.GetUserFunctions -> UserFunctionVo{List<String> functions}.
//
//  D) adm_dev_privilege (p_data.sql)
//       ROLE_ID=1 holds DEVICE_PRIV_CODE 8 (liveView), 9 (playback),
//       10 (download), 11 (privacyMasking) over NODE_CODE '001' (all devices)
//       => the admin role sees every device in the Live View / Playback tree.
//
//  E) Native device tree (com.dcc.admin.restapi.api.v1s0)
//       GET  /admin/API/tree/deviceOrg  -> DeviceOrgTreeVo{departments:[OrgNodeVo]}
//       POST /admin/API/tree/devices    -> DeviceTreeVo{devices:[DeviceInfoVo]}
//       OrgNodeVo{code,parentCode,name,orgType,modifyTime,deparmentsCount,
//                  domainId,device:[{id,sort}],channel:[{id,sort}],sn,
//                  sourceType,sourceId,associateId,remark,authority}
//       DeviceInfoVo{code,name,category,type,model,deviceModelStr,status,
//                  offlineReason,protocol,manufacturer,deviceIp,devicePort,
//                  registId,proxyIp,proxyPort,userName,password,callNumber,
//                  loginType,sn,alarmRecordPosition,capability,orgCode,
//                  units:[DeviceUnitInfoVo],sipId,sipPwd,
//                  bindingConfirmVtoDeviceCodes,unitEnable,buildingEnable,
//                  liftEnable,softwareVersion,hardwareVersion,domainId,
//                  modifyTime,isVideoNexus,timezoneId,timezoneName,
//                  timezoneOffset,timezoneDesc,enableDst,dstType,dstBeginTime,
//                  dstEndTime,serverCode,sourceType,sourceId,associateId,
//                  authority,solarBattery}
//       DeviceUnitInfoVo{unitType,unitSeq,...,channels:[DeviceChannelInfoVo]}
//       DeviceChannelInfoVo{channelCode,channelName,channelSeq,status,...}
//     The native DSS Client 8.006 (DPSDK.dll string pool 0x180cdd138) parses
//     "departments" for Resource.Tree.GetDeviceOrg and "isParent"/"parentName"
//     for Resource.Tree.GetDeviceTree; the web SPA (production bundle) reads
//     "deviceList"/"orgList". Both key sets are served (real values only).
//
//  F) Resource.* BRM RPC methods used by the Monitor Center (Live View):
//       Resource.Tree.GetDeviceOrg   -> {departments:[...]}
//       Resource.Tree.GetDeviceTree  -> {devices:[...]} + isParent/parentName
//       Resource.Tree.GetDevices     -> {devices:[...]} (categories/containVirtualDevice)
//       Resource.Device.GetDeviceAllOrg -> {departments,orgType,subOrgCount,hasData}

export const DSS_MENU_CATALOG = [
  { menuCode: '001', menuName: "basicConfiguration", menuNameKey: "menu.basic.basicConfiguration", pid: '0', sort: 1, systemCode: "2" },
  { menuCode: '001001', menuName: "device", menuNameKey: "menu.second.device", pid: '001', sort: 1, systemCode: "2" },
  { menuCode: '001001001', menuName: "addDevice", menuNameKey: "menu.third.addDevice", pid: '001001', sort: 1, systemCode: "2" },
  { menuCode: '001001002', menuName: "deviceConfiguration", menuNameKey: "menu.third.deviceConfiguration", pid: '001001', sort: 2, systemCode: "2" },
  { menuCode: '001002', menuName: "user", menuNameKey: "menu.second.user", pid: '001', sort: 2, systemCode: "2" },
  { menuCode: '001002001', menuName: "role", menuNameKey: "menu.third.role", pid: '001002', sort: 1, systemCode: "2" },
  { menuCode: '001002002', menuName: "user", menuNameKey: "menu.third.user", pid: '001002', sort: 2, systemCode: "2" },
  { menuCode: '001003', menuName: "storage", menuNameKey: "menu.second.storage", pid: '001', sort: 3, systemCode: "2" },
  { menuCode: '001003001', menuName: "netDisk", menuNameKey: "menu.third.netDisk", pid: '001003', sort: 1, systemCode: "2" },
  { menuCode: '001003002', menuName: "localDisk", menuNameKey: "menu.third.localDisk", pid: '001003', sort: 2, systemCode: "2" },
  { menuCode: '001003003', menuName: "diskGroup", menuNameKey: "menu.third.diskGroup", pid: '001003', sort: 3, systemCode: "2" },
  { menuCode: '002', menuName: "applicationConfiguration", menuNameKey: "menu.basic.applicationConfiguration", pid: '0', sort: 2, systemCode: "2" },
  { menuCode: '002001', menuName: "event", menuNameKey: "menu.second.event", pid: '002', sort: 11, systemCode: "2" },
  { menuCode: '002002', menuName: "map", menuNameKey: "menu.second.map", pid: '002', sort: 2, systemCode: "2" },
  { menuCode: '002003', menuName: "personnelandVehicleInformation", menuNameKey: "menu.second.personnelandVehicleInformation", pid: '002', sort: 3, systemCode: "2" },
  { menuCode: '002003001', menuName: "personnelList", menuNameKey: "menu.third.personnelList", pid: '002003', sort: 1, systemCode: "2" },
  { menuCode: '002003002', menuName: "vehicleList", menuNameKey: "menu.third.vehicleList", pid: '002003', sort: 2, systemCode: "2" },
  { menuCode: '002004', menuName: "watchList", menuNameKey: "menu.second.watchList", pid: '002', sort: 4, systemCode: "2" },
  { menuCode: '002004001', menuName: "faceWatchList", menuNameKey: "menu.third.faceWatchList", pid: '002004', sort: 1, systemCode: "2" },
  { menuCode: '002004002', menuName: "vehicleWatchList", menuNameKey: "menu.third.vehicleWatchList", pid: '002004', sort: 2, systemCode: "2" },
  { menuCode: '002005', menuName: "accessControl", menuNameKey: "menu.second.accessControl", pid: '002', sort: 9, systemCode: "2" },
  { menuCode: '002005001', menuName: "doorGroup", menuNameKey: "menu.third.doorGroup", pid: '002005', sort: 1, systemCode: "2" },
  { menuCode: '002005002', menuName: "accessPermissionGroup", menuNameKey: "menu.third.accessPermissionGroup", pid: '002005', sort: 2, systemCode: "2" },
  { menuCode: '002005003', menuName: "Public Password", menuNameKey: "menu.third.publicPassword", pid: '002005', sort: 3, systemCode: "2" },
  { menuCode: '002005004', menuName: "advancedRule", menuNameKey: "menu.third.advancedRule", pid: '002005', sort: 4, systemCode: "2" },
  { menuCode: '002006', menuName: "videoIntercom", menuNameKey: "menu.second.videoIntercom", pid: '002', sort: 8, systemCode: "2" },
  { menuCode: '002006001', menuName: "callManagement", menuNameKey: "menu.third.callManagement", pid: '002006', sort: 1, systemCode: "2" },
  { menuCode: '002006002', menuName: "residenceConfiguration", menuNameKey: "menu.third.residenceConfiguration", pid: '002006', sort: 2, systemCode: "2" },
  { menuCode: '002006003', menuName: "contactsSynchronization", menuNameKey: "menu.third.contactsSynchronization", pid: '002006', sort: 3, systemCode: "2" },
  { menuCode: '002006004', menuName: "Private passwd", menuNameKey: "menu.third.privatePassword", pid: '002006', sort: 4, systemCode: "2" },
  { menuCode: '002006005', menuName: "appUser", menuNameKey: "menu.third.appUser", pid: '002006', sort: 5, systemCode: "2" },
  { menuCode: '002007', menuName: "attendance", menuNameKey: "menu.second.attendance", pid: '002', sort: 10, systemCode: "2" },
  { menuCode: '002007001', menuName: "attendancePeriod", menuNameKey: "menu.third.attendancePeriod", pid: '002007', sort: 1, systemCode: "2" },
  { menuCode: '002007002', menuName: "attendanceHolidaySchedule", menuNameKey: "menu.third.attendanceHolidaySchedule", pid: '002007', sort: 2, systemCode: "2" },
  { menuCode: '002007003', menuName: "attendanceShift", menuNameKey: "menu.third.attendanceShift", pid: '002007', sort: 3, systemCode: "2" },
  { menuCode: '002007004', menuName: "shiftManagement", menuNameKey: "menu.third.shiftManagement", pid: '002007', sort: 4, systemCode: "2" },
  { menuCode: '002008', menuName: "visitor", menuNameKey: "menu.second.visitor", pid: '002', sort: 1, systemCode: "2" },
  { menuCode: '002009', menuName: "EntranceAndExit", menuNameKey: "menu.second.EntranceAndExit", pid: '002', sort: 6, systemCode: "2" },
  { menuCode: '002009001', menuName: "parkingLot", menuNameKey: "menu.third.parkingLot", pid: '002009', sort: 1, systemCode: "2" },
  { menuCode: '002009002', menuName: "vehicleGroup", menuNameKey: "menu.third.vehicleGroup", pid: '002009', sort: 2, systemCode: "2" },
  { menuCode: '003', menuName: "systemConfiguration", menuNameKey: "menu.basic.systemConfiguration", pid: '0', sort: 3, systemCode: "2" },
  { menuCode: '003001', menuName: "systemDeployment", menuNameKey: "menu.second.systemDeployment", pid: '003', sort: 3, systemCode: "2" },
  { menuCode: '003001001', menuName: "distributedConfiguration", menuNameKey: "menu.third.distributedConfiguration", pid: '003001', sort: 1, systemCode: "2" },
  { menuCode: '003001002', menuName: "cascadeConfiguration", menuNameKey: "menu.third.cascadeConfiguration", pid: '003001', sort: 2, systemCode: "2" },
  { menuCode: '003002', menuName: "license", menuNameKey: "menu.second.license", pid: '003', sort: 2, systemCode: "2" },
  { menuCode: '003003', menuName: "systemParameter", menuNameKey: "menu.second.systemParameter", pid: '003', sort: 1, systemCode: "2" },
  { menuCode: '003004', menuName: "backupandRestore", menuNameKey: "menu.second.backupandRestore", pid: '003', sort: 4, systemCode: "2" },
  { menuCode: '004', menuName: "application", menuNameKey: "menu.basic.application", pid: '0', sort: 4, systemCode: "2" },
  { menuCode: '004001', menuName: "monitoringCenter", menuNameKey: "menu.second.monitoringCenter", pid: '004', sort: 1, systemCode: "2" },
  { menuCode: '004001001', menuName: "monitor", menuNameKey: "menu.third.monitor", pid: '004001', sort: 1, systemCode: "2" },
  { menuCode: '004001002', menuName: "videoWall", menuNameKey: "menu.third.videoWall", pid: '004001', sort: 2, systemCode: "2" },
  { menuCode: '004001003', menuName: "map", menuNameKey: "menu.third.map", pid: '004001', sort: 3, systemCode: "2" },
  { menuCode: '004002', menuName: "eventCenter", menuNameKey: "menu.second.eventCenter", pid: '004', sort: 2, systemCode: "2" },
  { menuCode: '004002001', menuName: "realTimeEvent", menuNameKey: "menu.third.realTimeEvent", pid: '004002', sort: 1, systemCode: "2" },
  { menuCode: '004002002', menuName: "historyEvent", menuNameKey: "menu.third.historyEvent", pid: '004002', sort: 2, systemCode: "2" },
  { menuCode: '004002003', menuName: "eventStatistics", menuNameKey: "menu.third.eventStatistics", pid: '004002', sort: 3, systemCode: "2" },
  { menuCode: '004003', menuName: "intelligentSearch", menuNameKey: "menu.second.intelligentSearch", pid: '004', sort: 3, systemCode: "2" },
  { menuCode: '004003001', menuName: "intelligentSearch", menuNameKey: "menu.third.intelligentSearch", pid: '004003', sort: 1, systemCode: "2" },
  { menuCode: '004003002', menuName: "caseBank", menuNameKey: "menu.third.caseBank", pid: '004003', sort: 2, systemCode: "2" },
  { menuCode: '004004', menuName: "maintenanceCenter", menuNameKey: "menu.second.maintenanceCenter", pid: '004', sort: 4, systemCode: "2" },
  { menuCode: '004004001', menuName: "overview", menuNameKey: "menu.third.overview", pid: '004004', sort: 1, systemCode: "2" },
  { menuCode: '004004002', menuName: "channelStatus", menuNameKey: "menu.third.channelStatus", pid: '004004', sort: 2, systemCode: "2" },
  { menuCode: '004004003', menuName: "deviceStatus", menuNameKey: "menu.third.deviceStatus", pid: '004004', sort: 3, systemCode: "2" },
  { menuCode: '004004004', menuName: "serviceStatus", menuNameKey: "menu.third.serviceStatus", pid: '004004', sort: 4, systemCode: "2" },
  { menuCode: '004004005', menuName: "fault", menuNameKey: "menu.third.fault", pid: '004004', sort: 5, systemCode: "2" },
  { menuCode: '004005', menuName: "accessManagement", menuNameKey: "menu.second.accessManagement", pid: '004', sort: 5, systemCode: "2" },
  { menuCode: '004005001', menuName: "accessControl", menuNameKey: "menu.third.accessControl", pid: '004005', sort: 1, systemCode: "2" },
  { menuCode: '004005001001', menuName: "accessControlConsole", menuNameKey: "menu.four.accessControlConsole", pid: '004005001', sort: 1, systemCode: "2" },
  { menuCode: '004005001002', menuName: "accessControlRecord", menuNameKey: "menu.four.accessControlRecord", pid: '004005001', sort: 2, systemCode: "2" },
  { menuCode: '004005002', menuName: "videoIntercom", menuNameKey: "menu.third.videoIntercom", pid: '004005', sort: 2, systemCode: "2" },
  { menuCode: '004005002001', menuName: "callCenter", menuNameKey: "menu.four.callCenter", pid: '004005002', sort: 1, systemCode: "2" },
  { menuCode: '004005002002', menuName: "releaseInformation", menuNameKey: "menu.four.releaseInformation", pid: '004005002', sort: 2, systemCode: "2" },
  { menuCode: '004005002003', menuName: "videoIntercomRecord", menuNameKey: "menu.four.videoIntercomRecord", pid: '004005002', sort: 3, systemCode: "2" },
  { menuCode: '004005003', menuName: "attendance", menuNameKey: "menu.third.attendance", pid: '004005', sort: 3, systemCode: "2" },
  { menuCode: '004005004', menuName: "visitor", menuNameKey: "menu.third.visitor", pid: '004005', sort: 4, systemCode: "2" },
  { menuCode: '004005004001', menuName: "visitorManagement", menuNameKey: "menu.four.visitorManagement", pid: '004005004', sort: 1, systemCode: "2" },
  { menuCode: '004005004002', menuName: "visitorRecord", menuNameKey: "menu.four.visitorRecord", pid: '004005004', sort: 2, systemCode: "2" },
  { menuCode: '004006', menuName: "vehicleEntrance", menuNameKey: "menu.second.vehicleEntrance", pid: '004', sort: 6, systemCode: "2" },
  { menuCode: '004006001', menuName: "entranceAndExitMonitoring", menuNameKey: "menu.third.entranceAndExitMonitoring", pid: '004006', sort: 1, systemCode: "2" },
  { menuCode: '004006002', menuName: "vehicleSearch", menuNameKey: "menu.third.vehicleSearch", pid: '004006', sort: 2, systemCode: "2" },
  { menuCode: '010', menuName: "management", menuNameKey: "menu.basic.management", pid: '0', sort: 10, systemCode: "2" },
  { menuCode: '010001', menuName: "log", menuNameKey: "menu.second.log", pid: '010', sort: 1, systemCode: "2" },
  { menuCode: '010001001', menuName: "operatorLog", menuNameKey: "menu.third.operatorLog", pid: '010001', sort: 1, systemCode: "2" },
  { menuCode: '010001002', menuName: "deviceLog", menuNameKey: "menu.third.deviceLog", pid: '010001', sort: 2, systemCode: "2" },
  { menuCode: '010001003', menuName: "systemLog", menuNameKey: "menu.third.systemLog", pid: '010001', sort: 3, systemCode: "2" },
  { menuCode: '010002', menuName: "downloadCenter", menuNameKey: "menu.second.downloadCenter", pid: '010', sort: 2, systemCode: "2" }
];

// ROLE_TYPE -> menu codes granted by sys_role_menu_default_relation
export const DSS_ROLE_MENU_CODES = {
  '1': ["001","001001","001001001","001001002","001002","001002001","001002002","001003","001003001","001003002","001003003","002","002001","002002","002003","002003001","002003002","002004","002004001","002004002","002005","002005001","002005002","002005003","002005004","002006","002006001","002006002","002006003","002006004","002006005","002007","002007001","002007002","002007003","002007004","002008","002009","002009001","002009002","003","003001","003001001","003001002","003002","003003","003004","004","004001","004001001","004001002","004001003","004002","004002001","004002002","004002003","004003","004003001","004003002","004004","004004001","004004002","004004003","004004004","004004005","004005","004005001","004005001001","004005001002","004005002","004005002001","004005002002","004005002003","004005003","004005004","004005004001","004005004002","004006","004006001","004006002","010","010001","010001001","010001002","010001003","010002"],
  '2': ["001","001001","001001001","001001002","001002","001002001","001002002","001003","001003001","001003002","001003003","002","002001","002002","002003","002003001","002003002","002004","002004001","002004002","002005","002005001","002005002","002005003","002005004","002006","002006001","002006002","002006003","002006004","002006005","002007","002007001","002007002","002007003","002007004","002008","002009","002009001","002009002","003","003003","004","004001","004001001","004001002","004001003","004002","004002001","004002002","004002003","004003","004003001","004003002","004004","004004001","004004002","004004003","004004004","004004005","004005","004005001","004005001001","004005001002","004005002","004005002001","004005002002","004005002003","004005003","004005004","004005004001","004005004002","004006","004006001","004006002","010","010001","010001001","010001002","010001003","010002"],
  '3': ["002","002001","002002","002003","002003001","002003002","002004","002004001","002004002","002005","002005001","002005002","002005003","002005004","002006","002006001","002006002","002006003","002006004","002006005","002007","002007001","002007002","002007003","002007004","002008","002009","002009001","002009002","004","004001","004001001","004001002","004001003","004002","004002001","004002002","004002003","004003","004003001","004003002","004004","004004001","004004002","004004003","004004004","004004005","004005","004005001","004005001001","004005001002","004005002","004005002001","004005002002","004005002003","004005003","004005004","004005004001","004005004002","004006","004006001","004006002","010","010001","010001001","010001002","010001003","010002"]
};

// FunctionType enum (real function codes of the DSS server)
export const DSS_FUNCTION_CATALOG = [
  { functionCode: '1', functionName: 'record', pId: '0' },
  { functionCode: '2', functionName: 'ptzOperateAndConfig', pId: '0' },
  { functionCode: '3', functionName: 'talk', pId: '0' },
  { functionCode: '5', functionName: 'recordLock', pId: '0' },
  { functionCode: '6', functionName: 'recordTips', pId: '0' },
  { functionCode: '8', functionName: 'liveView', pId: '0' },
  { functionCode: '9', functionName: 'playback', pId: '0' },
  { functionCode: '10', functionName: 'download', pId: '0' },
  { functionCode: '11', functionName: 'privacyMasking', pId: '0' },
  { functionCode: '13', functionName: 'ptzOperate', pId: '0' },
  { functionCode: '15', functionName: 'syncTime', pId: '0' },
  { functionCode: '17', functionName: 'livePreview', pId: '0' },
  { functionCode: '21', functionName: 'deviceWeb', pId: '0' },
  { functionCode: '23', functionName: 'broadcast', pId: '0' },
  { functionCode: '24', functionName: 'playAudio', pId: '0' },
  { functionCode: '25', functionName: 'controlVolume', pId: '0' },
  { functionCode: '27', functionName: 'panoramicSplicing', pId: '0' }
];

// adm_role_function(ROLE_ID = 1) - the Super Administrator role
export const DSS_ADMIN_FUNCTION_CODES = ['1', '2', '3', '5', '6', '8', '9', '10', '11'];

// adm_dev_privilege(ROLE_ID = 1): liveView(8), playback(9), download(10),
// privacyMasking(11) over the whole tree node '001'
export const DSS_ADMIN_DEVICE_PRIVILEGES = ['8', '9', '10', '11'];

export function menuCatalogForRole(roleId) {
  const type = String(roleId ?? '1');
  const codes = DSS_ROLE_MENU_CODES[type] || DSS_ROLE_MENU_CODES['1'] || [];
  const set = new Set(codes);
  return DSS_MENU_CATALOG.filter((m) => set.has(m.menuCode));
}

export function buildMenuAvailablePayload(roleId = '1') {
  const results = menuCatalogForRole(roleId).map((m) => ({
    menuCode: m.menuCode,
    menuName: m.menuName,
    menuNameKey: m.menuNameKey,
    pid: m.pid,
    sort: m.sort,
    systemCode: m.systemCode
  }));
  return { results, list: results, items: results, menuList: results, total: results.length };
}

export function buildMenuAvailableFlag(menuCode) {
  const code = String(menuCode || '');
  const known = DSS_MENU_CATALOG.some((m) => m.menuCode === code);
  return { available: known ? '1' : '0', menuCode: code };
}

export function buildFunctionListPayload() {
  const results = DSS_FUNCTION_CATALOG.map((f) => ({
    functionCode: f.functionCode,
    functionName: f.functionName,
    pId: f.pId
  }));
  return { results, list: results, items: results, functionList: results, total: results.length };
}

// ===========================================================================
// NATIVE DEVICE / ORG TREE  (the tabs the operator reported as empty)
// ===========================================================================
import { DEVICE_REGISTRY, dssChannelCode, DSS_UNIT_TYPE_ENC } from './e025-devices.js';
// E-041: persistent org store (data/orgs.json) - the native org tree lists
// every persisted org (root '001' + 'VIGILAB') instead of a single hardcoded
// root node, and devices with an empty orgCode fall under the default org.
import { listOrgs, deviceOrgCode } from './e041-orgs.js';

// UNIT_TYPE map of the production DSS web bundle (web-module/js/device-JBrSmGvP.js)
export const DSS_UNIT_TYPE = {
  ENC: '1', DEC: '2', ALARM_IN: '3', ALARM_OUT: '4', TVWALLIN: '5', DOORCTRL: '7',
  VOICE: '8', POS: '11', VIRTUAL: '12', LED: '15', CVI_ALARM: '16', ALARM_BOX: '17',
  AL: '18', EAS: '21', SIRENOUT: '22', IP_SPEAKER: '23', UVSS: '24',
  BOX_ALARM_OUT: '26', RADAR: '43', LIFT_CONTROL: '50'
};

// LoginType enum of the server package (com.dcc.omms.common.constants.LoginType)
export const DSS_LOGIN_TYPE = {
  DIRECT_LOGIN: '0', REGIST: '6', PROXY_LOGIN: '7', MCD: '8',
  ONVIF: '9', GB28181: '10', P2P: '14', RTSP: '15'
};

// The root organization of the real DSS seed (sys_organization row 1)
export const DSS_ROOT_ORG = { code: '001', name: 'root', parentCode: '0', orgType: '1', domainId: '0' };

const str = (v) => (v === null || v === undefined ? '' : String(v));

// DeviceInfoUtil.getAddType() (server package) maps the login type to the
// registration path. The gateway must expose the SAME value for every
// registration funnel (manual add, Discover join, ONVIF, Dahua auto-register,
// P2P by serial, RTSP) so the client classifies the device correctly.
export function dssLoginType(d) {
  const source = String(d?.source || '');
  const protocol = String(d?.protocolType || '');
  if (source === 'auto-register') return DSS_LOGIN_TYPE.REGIST;
  if (source === 'p2p' || d?.devSequence) return DSS_LOGIN_TYPE.P2P;
  if (protocol === '68') return DSS_LOGIN_TYPE.RTSP;
  if (protocol === '99') return DSS_LOGIN_TYPE.ONVIF;
  if (protocol === '120' || protocol === '110') return DSS_LOGIN_TYPE.GB28181;
  return DSS_LOGIN_TYPE.DIRECT_LOGIN;
}

export function dssAddType(d) {
  const lt = dssLoginType(d);
  if (lt === DSS_LOGIN_TYPE.RTSP) return 'rtsp';
  if (lt === DSS_LOGIN_TYPE.ONVIF) return 'onvif';
  if (lt === DSS_LOGIN_TYPE.GB28181) return 'gb28181';
  if (lt === DSS_LOGIN_TYPE.REGIST) return 'regist';
  if (lt === DSS_LOGIN_TYPE.P2P) return 'sn';
  return d?.deviceIp ? 'ip' : '';
}

// DeviceChannelInfoVo (server package) - the channel node of the native tree
export function buildNativeChannelVo(device, channelSeq) {
  const seq = Math.max(0, Number(channelSeq) || 0);
  const code = dssChannelCode(device.deviceCode, seq);
  return {
    channelCode: code,
    channelName: seq === 0 ? device.deviceName : `${device.deviceName} CH${seq + 1}`,
    channelSeq: seq,
    status: str(device.online ?? device.status ?? 1),
    sn: str(device.serialNumber || ''),
    cameraType: '',
    channelType: '1',          // ChannelCategory.VideoChannel = "1"
    channelSubtype: '0',
    remoteType: '0',
    streamType: '0',
    capability: '',
    orgCode: str(device.orgCode || DSS_ROOT_ORG.code),
    domainId: str(device.domainId || DSS_ROOT_ORG.domainId),
    ipcIp: str(device.deviceIp || ''),
    multicastIp: '',
    multicastPort: '',
    recordType: '0',
    interfaceType: '',
    alarmType: '',
    alarmLevel: '',
    signalType: '',
    accessType: '',
    posType: '',
    posModel: '',
    dynCode: '',
    faceFunctions: '',
    keyCode: '',
    db33Code: '',
    intelliState: '',
    faceAnalyseType: '',
    videoSource: '',
    targetDetection: '',
    maxSplitNum: '1',
    decodeMode: '0',
    conbineStatus: '0',
    parentTargetSeq: '',
    thirdPartyControl: '0',
    fingerPrintAuth: '0',
    cardAuth: '0',
    faceAuth: '0',
    palmVeinAuth: '0',
    userIsolate: '0',
    unlockModes: '',
    floorNum: '',
    floorInfos: [],
    parkingSpaceMode: '0',
    solarBattery: '',
    // aliases used by the web SPA / older parsers
    channelId: code,
    channelNo: seq + 1,
    deviceCode: device.deviceCode,
    deviceName: device.deviceName,
    deviceIp: device.deviceIp,
    devicePort: device.devicePort,
    protocolType: device.protocolType,
    videoEncode: 'H.265',
    audioEncode: '',
    ptz: 0,
    audio: 1,
    record: 0,
    online: device.online ?? 1
  };
}

// DeviceUnitInfoVo - one encoder unit holding the video channels
export function buildNativeUnitVo(device) {
  const count = Math.max(1, Number(device.channelNum) || 1);
  const channels = [];
  for (let seq = 0; seq < count; seq++) channels.push(buildNativeChannelVo(device, seq));
  return {
    unitType: DSS_UNIT_TYPE_ENC,
    unitSeq: '0',
    assistStream: '0',
    zeroChnEncode: '0',
    ssServiceId: '',
    ptsServiceId: '',
    streamType: '0',
    decodeMode: '0',
    streamMode: '0',
    conbineStatus: '0',
    thirdPartyControl: '0',
    voiceServerIp: '',
    voiceServerPort: '',
    voiceStatusPort: '',
    voiceClientIp: '',
    dynCode: '',
    dynName: '',
    dynType: '',
    fingerPrintAuth: '0',
    cardAuth: '0',
    faceAuth: '0',
    palmVeinAuth: '0',
    userIsolate: '0',
    unlockModes: '',
    parkingStatisticsMode: '0',
    channels
  };
}

// DeviceInfoVo - the device node of the native tree
export function buildNativeDeviceInfoVo(d) {
  const units = [buildNativeUnitVo(d)];
  const orgCode = str(deviceOrgCode(d));
  const status = str(d.online ?? d.status ?? 1);
  return {
    // --- real DeviceInfoVo fields (server package) ---
    code: str(d.deviceCode),
    name: str(d.deviceName),
    category: str(d.deviceCategory || '1'),
    type: str(d.deviceType || '1'),
    model: str(d.model || ''),
    deviceModelStr: str(d.model || ''),
    status,
    offlineReason: '',
    protocol: str(d.protocolName || ''),
    manufacturer: str(d.manufacturer || ''),
    deviceIp: str(d.deviceIp || ''),
    devicePort: str(d.devicePort || ''),
    registId: str(d.registId || ''),
    proxyIp: '',
    proxyPort: '',
    userName: '',
    password: '',
    callNumber: '',
    loginType: dssLoginType(d),
    sn: str(d.serialNumber || ''),
    alarmRecordPosition: '',
    capability: '',
    orgCode,
    units,
    sipId: '',
    sipPwd: '',
    bindingConfirmVtoDeviceCodes: [],
    unitEnable: '1',
    buildingEnable: '0',
    liftEnable: '0',
    softwareVersion: str(d.firmwareVersion || ''),
    hardwareVersion: str(d.hardwareId || ''),
    domainId: str(d.domainId || DSS_ROOT_ORG.domainId),
    modifyTime: str(d.updateTime || d.createTime || ''),
    isVideoNexus: '0',
    timezoneId: str(d.timezoneId || '1'),
    timezoneName: str(d.timezoneName || 'UTC'),
    timezoneOffset: str(d.timezoneOffset ?? 0),
    timezoneDesc: str(d.timezoneDesc || ''),
    enableDst: '0',
    dstType: '0',
    dstBeginTime: { time: '', week: '0', day: '0', month: '0' },
    dstEndTime: { time: '', week: '0', day: '0', month: '0' },
    serverCode: str(d.serverCode || ''),
    sourceType: str(d.sourceType || ''),
    sourceId: str(d.sourceId || ''),
    associateId: str(d.associateId || ''),
    authority: '',
    solarBattery: '',
    // --- aliases parsed by the native client (DPSDK.dll string pool) ---
    enableUnit: '1',
    enableBuilding: '0',
    enableLift: '0',
    isParent: false,
    parentName: DSS_ROOT_ORG.name,
    streamProtocol: '',
    encrypType: '0',
    secretKey: '',
    accessKey: '',
    linkMode: '0',
    deviceId: str(d.deviceCode),
    deviceCode: str(d.deviceCode),
    deviceName: str(d.deviceName),
    deviceType: str(d.deviceType || '1'),
    deviceCategory: str(d.deviceCategory || '1'),
    protocolType: str(d.protocolType || ''),
    onlineStatus: status,
    source: str(d.source || ''),
    addType: dssAddType(d),
    channelNum: Math.max(1, Number(d.channelNum) || 1)
  };
}

// OrgNodeVo - the organization node of the native tree. `org` comes from the
// persistent org store (E-041); `devices` must already be filtered to that
// org (empty orgCode falls under the default org VIGILAB).
export function buildNativeOrgNodeVo(devices, org = DSS_ROOT_ORG) {
  const device = [];
  const channel = [];
  let sort = 0;
  for (const d of devices) {
    device.push({ id: str(d.deviceCode), sort: sort++ });
    const count = Math.max(1, Number(d.channelNum) || 1);
    for (let seq = 0; seq < count; seq++) {
      channel.push({ id: dssChannelCode(d.deviceCode, seq), sort: channel.length });
    }
  }
  return {
    // --- real OrgNodeVo fields (server package) ---
    code: org.code,
    parentCode: org.parentCode,
    name: org.name,
    orgType: org.orgType,
    modifyTime: new Date().toISOString(),
    deparmentsCount: '0',
    domainId: org.domainId,
    device,
    channel,
    sn: '',
    sourceType: '',
    sourceId: '',
    associateId: '',
    remark: '',
    authority: '',
    // --- aliases parsed by the native client ---
    id: org.code,
    orgCode: org.code,
    orgName: org.name,
    parentOrgCode: org.parentCode,
    isParent: false,
    parentName: '',
    sort: 0,
    roleIds: []
  };
}

function registryDevices() {
  return [...DEVICE_REGISTRY.values()];
}

// Filter helper - mirrors DeviceTreeXo (deviceCodes / categories / sourceTypes
// / orgCode / containVirtualDevice) of the server package.
export function filterNativeDevices(body = {}) {
  let list = registryDevices();
  const codes = Array.isArray(body.deviceCodes) ? body.deviceCodes.map(String) : [];
  if (codes.length) list = list.filter((d) => codes.includes(String(d.deviceCode)));
  const categories = Array.isArray(body.categories) ? body.categories.map(String) : [];
  if (categories.length) list = list.filter((d) => categories.includes(String(d.deviceCategory || '1')));
  const sourceTypes = Array.isArray(body.sourceTypes) ? body.sourceTypes.map(String) : [];
  if (sourceTypes.length) list = list.filter((d) => sourceTypes.includes(dssAddType(d)));
  const orgCode = String(body.orgCode || '');
  if (orgCode) list = list.filter((d) => deviceOrgCode(d) === orgCode);
  return list;
}

// POST /admin/API/tree/devices  ->  DeviceTreeVo{devices:[DeviceInfoVo]}
export function buildNativeDeviceTreePayload(body = {}) {
  const devices = filterNativeDevices(body).map(buildNativeDeviceInfoVo);
  return {
    // real contract
    devices,
    // aliases for the web SPA (reads deviceList) and old parsers
    deviceList: devices,
    list: devices,
    items: devices,
    orgCode: String(body.orgCode || ''),
    containVirtualDevice: String(body.containVirtualDevice || '1'),
    total: devices.length,
    totalCount: devices.length
  };
}

// GET /admin/API/tree/deviceOrg  ->  DeviceOrgTreeVo{departments:[OrgNodeVo]}
// E-041: one OrgNodeVo per PERSISTED org (root '001' + 'VIGILAB' + any org the
// operator adds); each node carries only the devices whose orgCode is that
// org (empty orgCode -> default org VIGILAB).
export function buildNativeOrgTreePayload() {
  const devices = registryDevices();
  const departments = listOrgs().map((o) =>
    buildNativeOrgNodeVo(devices.filter((d) => deviceOrgCode(d) === o.code), o));
  const deviceList = devices.map(buildNativeDeviceInfoVo);
  const channelList = [];
  for (const d of devices) {
    const unit = buildNativeUnitVo(d);
    for (const ch of unit.channels) channelList.push(ch);
  }
  return {
    // real contract
    departments,
    // aliases for the web SPA / old parsers
    orgList: departments,
    deviceList,
    channelList,
    orgCode: DSS_ROOT_ORG.code,
    containVirtualDevice: '1',
    total: deviceList.length,
    totalCount: deviceList.length
  };
}

// Resource.Device.GetDeviceAllOrg -> {departments, orgType, subOrgCount, hasData}
export function buildNativeAllOrgPayload() {
  const payload = buildNativeOrgTreePayload();
  return {
    ...payload,
    orgType: DSS_ROOT_ORG.orgType,
    subOrgCount: '0',
    hasData: payload.departments.length > 0 ? '1' : '0'
  };
}

