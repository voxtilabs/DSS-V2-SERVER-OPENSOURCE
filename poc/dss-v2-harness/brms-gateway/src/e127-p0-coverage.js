// ===== E-127: P0 coverage closure from the residual REA report =====
// Source: reverse-engineer agent ses_e46bd58b8ffe2Tfmm3n6r4m2uP report
// (2026-11-08): 533 literals of DPSDK.dll not served; P0 list below with
// offsets. Registered on every plausible root; hasRoute + try/catch guard
// so a duplicate can NEVER abort the Fastify boot.
import crypto from 'node:crypto';

const P0 = [
  // device / privileges / PTZ (DPSDK device block)
  'privileges/resources/menus/user/', 'privileges/resources/menus/', 'accounts/users/',
  'v1.1/device/satellite-line/list', 'v1.1/definition/record-storage-position/list',
  'devicesManager/deviceTree', 'devicesManager/devicesInfo', 'devicesManager/deviceAllOrg',
  'devicesManager/devicesGroup/', 'devicesManager/collection/channels',
  'devicesManager/collection/batchDelete', 'devicesManager/resourceBinding/',
  'devicesManager/deviceTypes', 'devicesManager/devices/offlineReasons',
  'devicesManager/track/devices/', 'devicesManager/rectLocate/devices/',
  'devicesManager/locate/devices/', 'devicesManager/autoTrackEnable/devices/',
  'v1.1/device/sleep/status/regulate/batch', 'v1.1/device/channel/volume/fetch/batch',
  'v1.1/device/channel/volume/regulate/batch', 'v1.1/device/channel/audio-light/regulate',
  'v1.1/device/video-intercom/template', 'v1.1/device/video-intercom/import',
  'accounts/users/password/', 'account/security/secret/deliver',
  'DMS/Ptz/OperateFunction', 'DMS/Ptz/OperateFocus', 'DMS/Ptz/GetFocusStatus',
  'DMS/Ptz/GetLensInfo', 'DMS/Ptz/GetPosition', 'DMS/Ptz/SetVisibleArea',
  'DMS/Ptz/GetVisibleArea', 'DMS/Ptz/SitPosition', 'DMS/Ptz/ArrangePtz',
  'DMS/Ptz/GetPresetPoints', 'DMS/Ptz/OperatePresetPoint', 'DMS/Ptz/OperateDirect',
  'DMS/Ptz/OperateCamera', 'DMS/Cruise/GetCruise', 'DMS/Cruise/DeleteCruise',
  'DMS/Cruise/SaveCruise', 'DMS/Device/TransportData', 'DMS/Device/GetMainSubGroup',
  // alarm business / duty / host
  'v1.1/alarm/disarm', 'alarmBusiness/askForHandle', 'alarmDuty/duty', 'alarmDuty/stopDuty',
  'alarmBusiness/pendAlarmList', 'alarmBusiness/processdAlarmList', 'alarmBusiness/onfile',
  'alarmBusiness/alarmList', 'alarmBusiness/exportAlarmList', 'alarmTemplate/alarmTemplateList',
  'alarm-host/area/page', 'alarm-host/zone/page', 'alarm-host/area/operate/batch',
  'alarm-host/zone/operate/batch', 'alarm-host/device/',
  'alarm-host/alarm-out/channel/operate/batch', 'alarm-host/alarm-signal/channel/operate/batch',
  'v1.1/alarm/link/output/channel/close', 'v1.1/alarm/soft-trigger/generate',
  'v1.1/alarm/handle/batch', 'v1.1/alarm/record/',
  // config server/mail/ldap/key/callMode
  'v1.1/config/server/time', 'v1.1/config/mail/test', 'v1.1/config/mail/send',
  'v1.1/config/ldap/dn/fetch', 'v1.1/config/ldap/test', 'v1.1/config/key/generate',
  'v1.1/config/getCallMode', 'v1.1/config/callMode', 'v1.1/config/apple/cert/',
  'v1.1/config/port/allow-list/ip', 'v1.1/config/hot-spare/status',
  'v1.1/config/outside-database/support/list', 'v1.1/config/outside-database',
  'v1.1/config/pos-end-mark',
  // upgrade OMC
  'v1.1/omc/device/upgrade/plan', 'omc/device/upgrade/plan/list',
  'omc/device/upgrade/task/page', 'v1.1/omc/device/software/information/list',
  'omc/device/upgrade/task/execute', 'omc/device/upgrade/task', 'omc/device/upgrade/package/delete',
  // emap / event / misc
  'v1.1/map/raster', 'v1.1/map/vector/status', 'api/actualGps', 'api/message',
  'api/upDateHandleMessageByClient/', 'eventCenter/messages/subscribeAddress', 'event/',
  'common/request/', 'v1.1/inspect/plan/page', 'v1.1/inspect/plan/'
];

export const DEFAULT_DATA = {
  success: true, list: [], results: [], items: [], records: [], pageData: [],
  total: '0', totalCount: '0', pageNo: '1', pageSize: '20', pageCount: '0'
};

// E-132: full warning key set (client IsKeyValid CommonFunc.cpp:149 fails on
// warningContent/warningType/standbyServerRemainDays -> ErrorId 3101 toasts).
export const WARN_KEYS = {
  warning: 0, warningHappened: '0', warningHappenedNum: '0', warningTime: '0',
  warningContent: '', warningType: '0', warningLevel: '0', warningTitle: '',
  standbyServerRemainDays: '0', abnormityType: '0', abnormity: '0', abnormal: 0,
  expireRemainDays: '0',
  warningList: []
};

function customData(base) {
  const now = new Date().toISOString();
  // E-132: any warning/abnormity route carries every validated key as string.
  if (/warning|abnormity/i.test(base)) return { ...DEFAULT_DATA, ...WARN_KEYS };
  switch (base) {
    case 'config/server/time':
      return { ...DEFAULT_DATA, serverTime: now, time: now, timeZone: 'GMT+08:00', zoneOffset: '480', ntpEnable: '0', syncEnable: '0', dst: { enable: '0', startTime: '', endTime: '' } };
    case 'config/key/generate':
      return { ...DEFAULT_DATA, key: crypto.randomBytes(32).toString('hex'), publicKey: '', privateKey: '', expireTime: '' };
    case 'eventCenter/messages/subscribeAddress':
      return { ...DEFAULT_DATA, subscribeAddress: 'tcp://127.0.0.1:61616', publishAddress: 'tcp://127.0.0.1:61616', topic: 'brms.notify', subscribeTopics: [] };
    case 'alarm/disarm': case 'alarm/handle/batch': case 'alarm/link/output/channel/close':
    case 'alarm/soft-trigger/generate': case 'accounts/users/password/':
    case 'account/security/secret/deliver': case 'common/request/':
      return { ...DEFAULT_DATA, handled: '1', handledIds: [], cancel: '1' };
    case 'api/actualGps':
      return { ...DEFAULT_DATA, longitude: '0', latitude: '0', altitude: '0' };
    case 'map/raster': case 'map/vector/status':
      return { ...DEFAULT_DATA, status: '0', rasterList: [], vectorList: [] };
    default:
      if (base.startsWith('devicesManager/')) return { ...DEFAULT_DATA, tree: [], devices: [], organizations: [], deviceList: [] };
      if (base.startsWith('omc/')) return { ...DEFAULT_DATA, plans: [], tasks: [], packages: [], upgradeable: false };
      if (base.startsWith('alarm') || base.startsWith('alarmBusiness')) return { ...DEFAULT_DATA, alarms: [], duties: [], templates: [], zones: [], areas: [] };
      if (base.startsWith('DMS/')) return { ...DEFAULT_DATA, ret: '0', result: '0', presetPoints: [], focus: '0' };
      return DEFAULT_DATA;
  }
}

export function urlsFor(p) {
  const out = new Set();
  const vers = /^v\d\.\d\//.test(p);
  const bases = vers ? [p, p.replace(/^v\d\.\d\//, '')] : [p, 'v1.1/' + p];
  for (const b of bases) {
    const roots = /^v\d\.\d\//.test(b)
      ? ['/brms/api', '', '/admin/api', '/cfgs/api']
      : ['/brms/api/v1.1', '/brms/api/v1.0', '/admin/API', '', '/v1.1', '/v1.0',
         '/emap/api', '/emap/api/v1.1', '/omms/api', '/omms/api/v1.1',
         '/obms/api', '/obms/api/v1.1', '/ipms/api', '/ipms/api/v1.1',
         '/arms/api', '/arms/api/v1.1', '/videoService'];
    for (const r of roots) out.add((r + '/' + b).replace(/\/+/g, '/').replace(/\/$/, '') || '/');
  }
  return [...out];
}

export function registerP0Coverage(app, envelope) {
  let added = 0, skipped = 0;
  for (const p of P0) {
    const base = p.replace(/\/$/, '');
    const data = customData(base);
    for (const url of urlsFor(p)) {
      const variants = url.endsWith('/') || p.endsWith('/') ? [url + '/:id', url] : [url];
      for (const u of variants) {
        for (const method of ['GET', 'POST']) {
          try {
            // NOTE: do NOT use app.hasRoute() as a guard - find-my-way's
            // hasRoute() also matches wildcard/param routes, and index.js has
            // a '*' catch-all registered as a real route, which made hasRoute
            // return true for every URL and silently skip the whole P0 list
            // (live probe 2026-11-08: POST /brms/api/v1.1/alarm/disarm still
            // hit [FALLBACK] 40B). Register unconditionally; only an exact
            // duplicate (FST_ERR_DUPLICATED_ROUTE) or a param-name conflict is
            // caught and counted as skipped - static routes always win over
            // the '*' wildcard in find-my-way.
            app[method.toLowerCase()](u, async () => envelope(typeof data === 'function' ? data() : data));
            added++;
          } catch (e) { skipped++; }
        }
      }
    }
  }
  console.log(`[E127-P0] registered=${added} skipped(dup/conflict)=${skipped}`);
}
