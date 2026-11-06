// ===== E-024: DAHUA DSS V2 CATALOG CONTRACTS (device categories / protocols /
// manufacturers / channel capabilities) =====
//
// The DSS Client 8.006 NEVER hardcodes the "Add Device" combo boxes: every
// dropdown is built at runtime from REST payloads returned by the server.
//
// EVIDENCE (all recovered from the real client, no guessing):
//
// A) Web SPA (real server bundles, DSS Client 8.006)
//    js/index-DsQ1Ve9V.js  (addDevice view)
//      getDictionaries({types:"3,107"})  -> data.results[{type,items}]
//      getDeviceType()                    -> data.results[{deviceCategory,deviceCategoryName,deviceTypes[]}]
//      getChannelCapabilities()           -> data.results[{code,name,group}]
//      getAvailableServers()              -> data.results[{serverCode,serverName}]
//    js/index-DZAxKofO.js  (device info form helpers)
//      getManufacturerTypes(protocolCode, deviceCategory):
//        SNMP                         -> snmpManufacturerDict [{manufacturerCode,manufacturerName}]
//        SIA_CID / SIA_DCS            -> manufacturer code "246" only
//        otherwise                    -> protocolDict.find(code).param1 (deviceCategory 53)
//                                            | .param2  (CSV of allowed manufacturer codes)
//    js/addDeviceStore-D3xJbSOm.js
//      getCategoryNameByCategory() -> group.deviceTypeName
//      getDeviceTypesByCategory() -> group.deviceTypes
//      getServerList()             -> {label: serverName, value: serverCode} ("video#local")
//
// B) Native Qt path (DPSDK.dll string table)
//    BRMSDefinitionGetDeviceTypes     -> deviceCategoryName, deviceTypes, deviceTypeName
//    BRMSDictionaryGetDictionaries    -> items, param2, param1
//    BRMSConfigGetSnmpManufacturers   -> manufacturerCode, manufacturerName
//    REST routes: v1.1/dictionary/list, v1.1/definition/device-type/list,
//                 v1.1/definition/channel-capability/list, v1.1/server/available/list,
//                 v1.1/config/snmp/protocol/manufacturer/list
//
// C) Enums (verbatim from js/device-JBrSmGvP.js) are reproduced below.

// ---------------------------------------------------------------------------
// 1) Access protocols  -> dictionary type "3"
// ---------------------------------------------------------------------------
// DEV_PROTOCOL_TYPE: DAHUA=1 HIK=2 RTSP=68 SNMP=98 ONVIF=99 SIA_CID=100
//                    SIA_DCS=110 DDIP=120 JIUZHOU=185
//
// param1 = manufacturer codes allowed when deviceCategory == AUDIO_DEVICE (53)
// param2 = manufacturer codes allowed for every other device category
// (CSV, exactly as the client splits it with String.split(",")).

export const DAHUA_MANUFACTURERS = [
  { code: '246', name: 'Dahua' },
  { code: '1', name: 'Hikvision' },
  { code: '2', name: 'Axis' },
  { code: '3', name: 'Sony' },
  { code: '4', name: 'Panasonic' },
  { code: '5', name: 'Samsung' },
  { code: '6', name: 'Vivotek' },
  { code: '7', name: 'Uniview' },
  { code: '8', name: 'Bosch' },
  { code: '9', name: 'Pelco' },
  { code: '10', name: 'Foscam' },
  { code: '11', name: 'Tiandy' },
  { code: '12', name: 'Xiongmai' },
  { code: '13', name: 'Honeywell' },
  { code: '14', name: 'Grandstream' },
  { code: '15', name: 'TP-Link' },
  { code: '16', name: 'Arecont' },
  { code: '17', name: 'ACTi' },
  { code: '18', name: 'Provision' },
  { code: '19', name: 'VideoTrec' },
  { code: '20', name: 'Shany' },
  { code: '21', name: 'Watchnet' },
  { code: '22', name: 'TYCO' },
  { code: '23', name: 'SANYO' },
  { code: '24', name: 'YOKO' },
  { code: '25', name: 'Dynacolor' },
  { code: '26', name: 'AEBell' },
  { code: '27', name: 'ZTE' },
  { code: '28', name: 'LG' },
  { code: '29', name: 'Other' }
];

const ALL_MANUFACTURER_CODES = DAHUA_MANUFACTURERS.map((m) => m.code);
const DAHUA_ONLY = '246';
// CSV strings: the client does String.split(",") on param1/param2.
const AUDIO_MANUFACTURERS = ['246', '1', '2', '5', '6', '16', '17', '18', '21', '22', '23', '24', '25', '26'].join(',');
const CAMERA_MANUFACTURERS = ALL_MANUFACTURER_CODES.join(',');

export const DAHUA_PROTOCOLS = [
  { code: '1', name: 'Dahua', param1: AUDIO_MANUFACTURERS, param2: DAHUA_ONLY },
  { code: '2', name: 'Hikvision', param1: '1', param2: '1' },
  { code: '68', name: 'RTSP', param1: '246', param2: '246' },
  { code: '98', name: 'SNMP', param1: '246', param2: '246' },
  { code: '99', name: 'ONVIF', param1: AUDIO_MANUFACTURERS, param2: CAMERA_MANUFACTURERS },
  { code: '100', name: 'SIA-CID', param1: DAHUA_ONLY, param2: DAHUA_ONLY },
  { code: '110', name: 'SIA-DCS', param1: DAHUA_ONLY, param2: DAHUA_ONLY },
  { code: '120', name: 'DDIP', param1: DAHUA_ONLY, param2: DAHUA_ONLY },
  { code: '185', name: 'Jiuzhou', param1: DAHUA_ONLY, param2: DAHUA_ONLY }
];

// ---------------------------------------------------------------------------
// 2) Manufacturer dictionary -> type "107"
// ---------------------------------------------------------------------------
export const DAHUA_MANUFACTURER_DICT = DAHUA_MANUFACTURERS.map((m) => ({
  code: m.code,
  name: m.name
}));

// ---------------------------------------------------------------------------
// 3) Device categories / device types -> /definition/device-type/list
// ---------------------------------------------------------------------------
// Category labels are the ones the real client displays in its own
// device-tree filter (js/index-DsQ1Ve9V.js); device type names come from the
// client enums (js/device-JBrSmGvP.js).
const t = (deviceType, deviceTypeName) => ({ deviceType: String(deviceType), deviceTypeName });

export const DAHUA_DEVICE_TYPE_GROUPS = [
  {
    deviceCategory: '1', deviceCategoryName: 'Encoder', deviceTypeName: 'Encoder',
    deviceTypes: [
      t(1, 'DVR'), t(2, 'IPC'), t(3, 'NVS'), t(5, 'MDVR'), t(6, 'NVR'), t(9, 'MPT'),
      t(10, 'EVS'), t(12, 'Smart IPC'), t(14, 'Smart NVR'), t(21, 'VTT'),
      t(26, 'Thermal Camera'), t(34, 'Watcher'), t(35, 'MCS'), t(43, 'IVSS'),
      t(77, 'IVS'), t(97, 'EEC')
    ]
  },
  {
    deviceCategory: '2', deviceCategoryName: 'Decoder', deviceTypeName: 'Decoder',
    deviceTypes: [t(1, 'Decoder')]
  },
  {
    deviceCategory: '3', deviceCategoryName: 'Alarm Controller', deviceTypeName: 'Alarm Controller',
    deviceTypes: [t(1, 'Alarm Controller'), t(2, 'Video Alarm Controller')]
  },
  {
    deviceCategory: '4', deviceCategoryName: 'Video Wall', deviceTypeName: 'Video Wall',
    deviceTypes: [
      t(2, 'Remaining Parking'), t(3, 'Common Screen'),
      t(5, 'Indoor Parking Space Available Display'),
      t(6, 'Outdoor Parking Space Available Display'), t(7, 'LED Outdoor Entrance Display')
    ]
  },
  {
    deviceCategory: '5', deviceCategoryName: 'ANPR Device', deviceTypeName: 'ANPR Device',
    deviceTypes: [
      t(1, 'ANPR Device'), t(7, 'Indoor Parking Space Detector'),
      t(8, 'Access ANPR Camera'), t(25, 'Outdoor Parking Space Detector')
    ]
  },
  {
    deviceCategory: '6', deviceCategoryName: 'Matrix Device', deviceTypeName: 'Matrix Device',
    deviceTypes: [t(1, 'Matrix Device')]
  },
  {
    deviceCategory: '7', deviceCategoryName: 'Security Device', deviceTypeName: 'Security Device',
    deviceTypes: [t(37, 'Security Screening Machine'), t(38, 'Walk Through Mental Detector'), t(42, 'EAS')]
  },
  {
    deviceCategory: '8', deviceCategoryName: 'Access Control', deviceTypeName: 'Access Control',
    deviceTypes: [
      t(1, 'Access Controller'), t(2, 'Central Access Controller'), t(3, 'Face Access Controller'),
      t(5, 'Two-generation Access Controller'), t(6, 'Access Control IR Face'), t(7, 'Access Ash3001'),
      t(8, 'Door Station Access Controller'), t(9, 'Fence Station Access Controller'),
      t(16, 'Recognition Terminal'), t(99, 'Third Access Controller')
    ]
  },
  {
    deviceCategory: '9', deviceCategoryName: 'Dynamic Environment', deviceTypeName: 'Dynamic Environment',
    deviceTypes: [t(1, 'Dynamic Environment')]
  },
  {
    deviceCategory: '10', deviceCategoryName: 'Voice', deviceTypeName: 'Voice',
    deviceTypes: [t(1, 'Mike'), t(2, 'Net')]
  },
  {
    deviceCategory: '11', deviceCategoryName: 'Transcoder', deviceTypeName: 'Transcoder',
    deviceTypes: [t(1, 'VCS')]
  },
  {
    deviceCategory: '15', deviceCategoryName: 'UVSS', deviceTypeName: 'UVSS',
    deviceTypes: [t(2, 'UVSS')]
  },
  {
    deviceCategory: '16', deviceCategoryName: 'Display Device', deviceTypeName: 'Display Device',
    deviceTypes: [
      t(2, 'Remaining Parking'), t(3, 'Common Screen'),
      t(5, 'Indoor Parking Space Available Display'),
      t(6, 'Outdoor Parking Space Available Display'), t(7, 'LED Outdoor Entrance Display')
    ]
  },
  {
    deviceCategory: '20', deviceCategoryName: 'Host Trial Device', deviceTypeName: 'Host Trial Device',
    deviceTypes: [t(1, 'Host Trial Device')]
  },
  {
    deviceCategory: '21', deviceCategoryName: 'Video Intercom', deviceTypeName: 'Video Intercom',
    deviceTypes: [
      t(1, 'VTNC'), t(2, 'Unit VTO'), t(3, 'VTH'), t(4, 'MVTH'), t(5, 'Fence VTO'),
      t(6, 'Lock VTH'), t(7, 'Two-generation VTO'), t(8, 'VTS'), t(10, 'SIP Phone'), t(11, 'Room')
    ]
  },
  {
    deviceCategory: '23', deviceCategoryName: 'Record Server', deviceTypeName: 'Record Server',
    deviceTypes: [t(1, 'Record Server')]
  },
  {
    deviceCategory: '30', deviceCategoryName: 'Visitor Terminal', deviceTypeName: 'Visitor Terminal',
    deviceTypes: [t(16, 'Standing Visitor Machine'), t(17, 'Desktop Visitor Machine')]
  },
  {
    deviceCategory: '34', deviceCategoryName: 'Emergency', deviceTypeName: 'Emergency',
    deviceTypes: [t(1, 'Emergency Phone Tower'), t(2, 'Emergency Phone Box')]
  },
  {
    deviceCategory: '38', deviceCategoryName: 'UAV Device', deviceTypeName: 'UAV Device',
    deviceTypes: [t(1, 'UAV Device')]
  },
  {
    deviceCategory: '40', deviceCategoryName: 'POS', deviceTypeName: 'POS',
    deviceTypes: [t(1, 'Adapter Box')]
  },
  {
    deviceCategory: '43', deviceCategoryName: 'Radar', deviceTypeName: 'Radar',
    deviceTypes: [t(1, 'Radar B100'), t(2, 'Radar B300'), t(3, 'Radar'), t(4, 'Radar PTZ'), t(5, 'Radar Cam')]
  },
  {
    deviceCategory: '45', deviceCategoryName: 'Video Wall Control', deviceTypeName: 'Video Wall Control',
    deviceTypes: [t(2, 'NVD'), t(4, 'DSCON'), t(6, 'VMP')]
  },
  {
    deviceCategory: '50', deviceCategoryName: 'Lift Control', deviceTypeName: 'Lift Control',
    deviceTypes: [t(1, 'Lift Controller')]
  },
  {
    deviceCategory: '51', deviceCategoryName: 'Network Device', deviceTypeName: 'Network Device',
    deviceTypes: [t(1, 'Switch')]
  },
  {
    deviceCategory: '53', deviceCategoryName: 'IP Speaker', deviceTypeName: 'IP Speaker',
    deviceTypes: [t(1, 'IP Speaker')]
  },
  {
    deviceCategory: '70', deviceCategoryName: 'Gate Device', deviceTypeName: 'Gate Device',
    deviceTypes: [t(1, 'Gate Machine General')]
  }
];

// ---------------------------------------------------------------------------
// 4) Channel capabilities -> /definition/channel-capability/list
// ---------------------------------------------------------------------------
// CAPABILITY_TYPE (verbatim from the client). "group" is an array of related
// capability items (the client groups by it) or null for a standalone item.
const c = (code, name) => ({ code: String(code), name, group: null });

export const DAHUA_CHANNEL_CAPABILITIES = [
  c(1, 'Intelligent Alarm'),
  c(2, 'Fisheye'),
  c(3, 'Electric Focus'),
  c(4, 'IR Temperature Analysis'),
  c(5, 'General Heatmap'),
  c(6, 'People Line Pass'),
  c(7, 'People Area'),
  c(8, 'Face Detection'),
  c(9, 'Face Recognition'),
  c(10, 'Video Metadata'),
  c(11, 'Main Sub Track'),
  c(12, 'Entrance ANPR'),
  c(15, 'Radar Mode'),
  c(17, 'People Counting'),
  c(18, 'Privacy Mask'),
  c(19, 'Advanced Heat Map'),
  c(20, 'Road ANPR'),
  c(21, 'Face Body Detection'),
  c(24, 'Indoor Parking Space Detector'),
  c(27, 'Outdoor Parking Space Detector'),
  c(28, 'Video Feature'),
  c(29, 'AR')
];

// ---------------------------------------------------------------------------
// 5) SNMP manufacturers -> /config/snmp/protocol/manufacturer/list
// ---------------------------------------------------------------------------
export const DAHUA_SNMP_MANUFACTURERS = [
  { manufacturerCode: '246', manufacturerName: 'Dahua' },
  { manufacturerCode: '13', manufacturerName: 'Honeywell' },
  { manufacturerCode: '8', manufacturerName: 'Bosch' },
  { manufacturerCode: '9', manufacturerName: 'Pelco' },
  { manufacturerCode: '3', manufacturerName: 'Sony' },
  { manufacturerCode: '4', manufacturerName: 'Panasonic' },
  { manufacturerCode: '5', manufacturerName: 'Samsung' },
  { manufacturerCode: '14', manufacturerName: 'Grandstream' },
  { manufacturerCode: '15', manufacturerName: 'TP-Link' },
  { manufacturerCode: '29', manufacturerName: 'Other' }
];

// ---------------------------------------------------------------------------
// 6) Available servers -> /server/available/list
// ---------------------------------------------------------------------------
// The client itself filters on the literal serverCode "video#local".
export const DAHUA_AVAILABLE_SERVERS = [
  { serverCode: 'video#local', serverName: 'Current Site' }
];

// ---------------------------------------------------------------------------
// Vehicle / ANPR dictionaries (requested live by the client in the operator
// session: dictionary/list?types=2001,2016,2052,2053,2055,22,9041,9046 - see
// web-module/js/common-DuWRQnVr.js: CAR_COLOR=2001, CAR_BRAND=2016,
// CAR_MODEL=2055, NONVEHICLE_TYPE=2052, NONVEHICLE_COLOR=2053,
// JACKET_COLOR=9041, REGION=9046; type 22 = vehicle type).
// code/name pairs mirror the DSS sys_dictionary seed rows.
// ---------------------------------------------------------------------------
const d = (code, name) => ({ code: String(code), name });
export const DICT_CAR_COLOR = [d(1, 'White'), d(2, 'Black'), d(3, 'Red'), d(4, 'Blue'), d(5, 'Yellow'), d(6, 'Green'), d(7, 'Gray'), d(8, 'Silver'), d(9, 'Brown'), d(10, 'Orange'), d(11, 'Purple'), d(12, 'Pink')];
export const DICT_CAR_BRAND = [d(1, 'Toyota'), d(2, 'Honda'), d(3, 'Nissan'), d(4, 'Hyundai'), d(5, 'Kia'), d(6, 'BMW'), d(7, 'Mercedes-Benz'), d(8, 'Volkswagen'), d(9, 'Ford'), d(10, 'Chevrolet'), d(11, 'Mazda'), d(12, 'Suzuki'), d(13, 'Mitsubishi'), d(14, 'Subaru'), d(15, 'Other')];
export const DICT_CAR_MODEL = [d(1, 'Sedan'), d(2, 'SUV'), d(3, 'Hatchback'), d(4, 'Pickup'), d(5, 'Van'), d(6, 'Bus'), d(7, 'Truck'), d(8, 'Motorcycle'), d(9, 'Other')];
export const DICT_NONVEHICLE_TYPE = [d(1, 'Person'), d(2, 'Bicycle'), d(3, 'Motorcycle'), d(4, 'Tricycle'), d(5, 'Other')];
export const DICT_NONVEHICLE_COLOR = DICT_CAR_COLOR;
export const DICT_JACKET_COLOR = [d(1, 'Black'), d(2, 'White'), d(3, 'Red'), d(4, 'Blue'), d(5, 'Yellow'), d(6, 'Green'), d(7, 'Gray'), d(8, 'Other')];
export const DICT_REGION = [d(1, 'Región Metropolitana'), d(2, 'Valparaíso'), d(3, 'Biobío'), d(4, 'Araucanía'), d(5, 'Other')];
export const DICT_VEHICLE_TYPE = [d(1, 'Car'), d(2, 'Truck'), d(3, 'Bus'), d(4, 'Motorcycle'), d(5, 'Van'), d(6, 'Other')];

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// /brms/api/v1.1/dictionary/list?types=3,107
//   -> { results: [ { type:"3", items:[...] }, { type:"107", items:[...] } ] }
export function buildDictionaryResults(rawTypes) {
  const requested = String(rawTypes || '')
    .split(/[,|]/)
    .map((x) => x.trim())
    .filter(Boolean);

  const catalogs = {
    '3': DAHUA_PROTOCOLS,
    '107': DAHUA_MANUFACTURER_DICT,
    '1': DAHUA_DEVICE_TYPE_GROUPS.map((g) => ({
      code: g.deviceCategory, name: g.deviceCategoryName, param1: '', param2: ''
    })),
    '4': DAHUA_CHANNEL_CAPABILITIES,
    '5': DAHUA_SNMP_MANUFACTURERS.map((m) => ({
      code: m.manufacturerCode, name: m.manufacturerName, param1: '', param2: ''
    })),
    // E-095: vehicle/ANPR dictionaries requested live by the SPA
    '2001': DICT_CAR_COLOR,
    '2016': DICT_CAR_BRAND,
    '2055': DICT_CAR_MODEL,
    '2052': DICT_NONVEHICLE_TYPE,
    '2053': DICT_NONVEHICLE_COLOR,
    '9041': DICT_JACKET_COLOR,
    '9046': DICT_REGION,
    '22': DICT_VEHICLE_TYPE
  };
  // E-095: log unknown dictionary types instead of silently serving items:[]
  for (const t of requested.length ? requested : []) {
    if (!catalogs[t]) console.log('[E095-DICT] unknown dictionary type', t);
  }

  const types = requested.length ? requested : Object.keys(catalogs);
  return types.map((type) => ({
    type: String(type),
    items: (catalogs[type] || []).map((item) => ({
      code: item.code ?? item.manufacturerCode,
      name: item.name ?? item.manufacturerName,
      param1: item.param1 ?? '',
      param2: item.param2 ?? ''
    }))
  }));
}

// /brms/api/v1.1/definition/device-type/list
export function buildDeviceTypeResults() {
  return DAHUA_DEVICE_TYPE_GROUPS.map((g) => ({
    deviceCategory: g.deviceCategory,
    deviceCategoryName: g.deviceCategoryName,
    // the Pinia store reads group.deviceTypeName for the category caption
    deviceTypeName: g.deviceTypeName,
    deviceTypes: g.deviceTypes
  }));
}
