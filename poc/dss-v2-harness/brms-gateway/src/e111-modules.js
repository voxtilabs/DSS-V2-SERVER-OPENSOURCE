// ===== E-111: module coverage - Logs, Alarm, License, TVWall, System config =
//
// SPA API inventory (web-module/js) cross-checked against gateway routes:
// these are the module-open endpoints with NO registration (they hit the
// benign catch-all, so those submenus opened empty):
//   Log (useLogApi-BPm4Cd0K.js):      log/system-log/page, log/operate-log,
//        log/system-log/event-type/list, log/service-log/service/$/status,
//        log/omc/service/type/list, log/client-config
//   Alarm (useEventApi-DiKk_pnU.js):  alarm/plan (+CRUD), alarm/plan/fetch/page,
//        alarm/plan/resource/config-status/fetch/batch/list,
//        alarm/record/fetch/page (DPSDK GetPageAlarmRecords @0xc7f...)
//   License (useLicenseApi):          license/item/list, license/used/list,
//        license/detail, license/components, */file/export
//   TVWall (useTVWallApi):            /admin/API/tvwall/window,
//        /admin/API/VMS/TvWall/GetTvWallCapacity
//   Config (index-BhDUzoCV.js):       config/message-storage, config/time-sync
//        (+/immediate), config/quick/command/list, config/tls/cert/detail
//        (+generate/import/export), config/sub-oss-port, config/export-password
// Shapes follow the DPSDK/SPA consumers: pageData[] + STRING totalCount
// (E-095 lesson), string flags, superset aliases (list/results/items).

import { OMMS_ALERT_TYPES } from './e025-devices.js';

const pageOf = (rows) => ({
  pageData: rows, list: rows, results: rows, items: rows,
  total: String(rows.length), totalCount: String(rows.length),
  pageNo: '1', page: '1', pageSize: '100', pageCount: '1'
});

// ---- Log module ------------------------------------------------------------
export function buildSystemLogPagePayload() {
  // Real server has logs; ours is a lab gateway with an empty journal by
  // design (no operations recorded yet) - honest empty page, correct shape.
  return pageOf([]);
}
export function buildOperateLogPagePayload() {
  return pageOf([]);
}
export function buildSystemLogEventTypeListPayload() {
  const rows = OMMS_ALERT_TYPES.map((a) => ({
    eventType: a.alertType, eventTypeName: a.alertName, type: String(a.category),
    enable: '1', status: '1', level: String(a.level)
  }));
  return { list: rows, results: rows, items: rows, eventTypeList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildServiceStatusPayload() {
  return { status: '1', online: '1', serviceStatus: '1', list: [], results: [], items: [] };
}
export function buildOmcServiceTypeListPayload() {
  const rows = [
    { serviceType: 'brms', serviceName: 'Business Center', status: '1' },
    { serviceType: 'omms', serviceName: 'Alarm Service', status: '1' },
    { serviceType: 'videoService', serviceName: 'Video Service', status: '1' }
  ];
  return { list: rows, results: rows, items: rows, serviceTypeList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildLogClientConfigPayload() {
  return {
    level: '2', logLevel: '2', keepDays: '30', maxSize: '100',
    enable: '1', clientLogLevel: '2', sdkLogLevel: '2'
  };
}

// ---- Alarm module ----------------------------------------------------------
export function buildAlarmPlanPagePayload() {
  return pageOf([]);
}
export function buildAlarmRecordPagePayload() {
  return { ...pageOf([]), pageCount: '0', recordList: [] };
}
export function buildAlarmPlanResourceConfigStatusPayload() {
  const list = [{ resourceId: 'VIGILAB', resourceType: '1', configStatus: '1', status: '1' }];
  return { list, results: list, items: list, total: String(list.length), totalCount: String(list.length) };
}

// ---- License module --------------------------------------------------------
export function buildLicenseItemListPayload() {
  const rows = [
    { itemId: '1', itemCode: 'channel', itemName: 'Channel', total: '100', used: '2', left: '98', status: '1' },
    { itemId: '2', itemCode: 'device', itemName: 'Device', total: '100', used: '2', left: '98', status: '1' }
  ];
  return { list: rows, results: rows, items: rows, itemList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildLicenseUsedListPayload() {
  const rows = [
    { usedId: '1', itemCode: 'channel', usedCount: '2', orgCode: '001' },
    { usedId: '2', itemCode: 'device', usedCount: '2', orgCode: '001' }
  ];
  return { list: rows, results: rows, items: rows, usedList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildLicenseDetailPayload() {
  return {
    licenseType: '1', status: '1', activateStatus: '1', trial: '0',
    expireTime: '2099-12-31 23:59:59', channelLeft: '98', deviceLeft: '98',
    detail: [], list: [], results: [], items: []
  };
}
export function buildLicenseComponentsPayload() {
  const rows = [
    { componentCode: 'brms', componentName: 'Business Center', status: '1', expireTime: '2099-12-31 23:59:59' },
    { componentCode: 'videoService', componentName: 'Video Service', status: '1', expireTime: '2099-12-31 23:59:59' }
  ];
  return { list: rows, results: rows, items: rows, componentList: rows, total: String(rows.length), totalCount: String(rows.length) };
}

// ---- TVWall ----------------------------------------------------------------
export function buildTvWallWindowPayload() {
  return { list: [], results: [], items: [], windows: [], total: '0', totalCount: '0' };
}
export function buildTvWallCapacityPayload() {
  return { capacity: '9', windowCapacity: '9', decodeCapacity: '9', total: '9' };
}

// ---- System config pages ---------------------------------------------------
export function buildMessageStorageConfigPayload() {
  return { enable: '0', status: '0', keepDays: '30', maxSize: '100', list: [], results: [], items: [] };
}
export function buildTimeSyncConfigPayload() {
  return { enable: '0', status: '0', mode: '0', interval: '24', server: '', syncTime: '', lastSyncTime: '' };
}
export function buildQuickCommandListPayload() {
  const rows = [
    { commandId: '1', commandCode: 'reboot', commandName: 'Reboot', enable: '1' },
    { commandId: '2', commandCode: 'syncTime', commandName: 'Sync Time', enable: '1' }
  ];
  return { list: rows, results: rows, items: rows, commandList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildTlsCertDetailPayload() {
  return {
    certId: '1', status: '1', enable: '1', type: '1', selfSigned: '1',
    commonName: process.env.PUBLIC_HOST || '10.10.20.120', issuer: 'DSS-V2-LAB',
    notBefore: '2026-01-01 00:00:00', notAfter: '2099-12-31 23:59:59',
    fingerprint: '', cert: '', key: ''
  };
}
export function buildSubOssPortPayload() {
  return { port: '8443', ossPort: '8443', enable: '0', status: '0' };
}
export function buildExportPasswordPayload() {
  return { enable: '0', status: '0', password: '', needPassword: '0', verifyMode: '0' };
}
