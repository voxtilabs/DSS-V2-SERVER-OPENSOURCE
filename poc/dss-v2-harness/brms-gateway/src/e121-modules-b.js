// ===== E-121: remaining Event Config / TVWall / OMMS alert routes ===========
//
// Final forensic gap list (log-analyzer, 2026-11-07): P0 alarm/plan/
// alarm-type/list served an empty list while OMMS has the catalog; P0
// alarm/plan/fetch/page empty; P0 PUT alarm/general/event/{id} did not
// persist (the client lost the "ANPR_EBA" edit silently); P1 event ids
// changed from 1/2/3 to ge-<epoch> breaking clients that stored numeric
// ids; P1 POST view-tree / tvwalls; P2 the 46 alarm/plan sub-routes, the
// 14 omms alert routes, TVWall RPCs; P3 event/subscription GET +
// alarm/overview/summary v1.0.
import { OMMS_ALERT_TYPES } from './e025-devices.js';
import { DEVICE_REGISTRY, allChannels } from './e025-devices.js';
import { deviceOrgCode, orgName } from './e041-orgs.js';

const str = (v) => String(v ?? '');
const page = (rows) => ({
  pageData: rows, list: rows, results: rows, items: rows,
  total: String(rows.length), totalCount: String(rows.length),
  pageNo: '1', page: '1', pageSize: '100', pageCount: '1'
});

// --- Event Config: alarm plans ------------------------------------------------
export function buildAlarmPlanListPayload() {
  // one default plan bound to the org tree so the panel is operable
  const plans = [{
    planId: '1', id: '1', planCode: 'default', planName: 'Default Plan',
    enable: '1', status: '1', template: '0',
    orgCode: '001', orgName: 'root',
    alarmTypeIds: ['1', '2', '3', '13'],
    channelIds: allChannels().slice(0, 8).map((c) => c.channelId || c.channelCode),
    linkVideo: '1', linkRecord: '1', linkTvwall: '0', linkSound: '0',
    createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00'
  }];
  return page(plans);
}

export function buildAlarmTypeListPayload() {
  // the FULL catalog (same as OMMS) - the plan panel was serving []
  const rows = OMMS_ALERT_TYPES.map((a) => ({
    alarmTypeId: a.alertType, alarmType: a.alertType,
    alarmTypeName: a.alertName, alarmName: a.alertName,
    eventType: a.alertType, category: a.category, level: a.level, enable: '1', status: '1'
  }));
  return { list: rows, results: rows, items: rows, alarmTypeList: rows, total: String(rows.length), totalCount: String(rows.length) };
}

const templateRows = (kind) => [
  { templateId: '1', id: '1', templateCode: kind + '-default', templateName: kind === 'time' ? 'All Day' : (kind === 'mail' ? 'Default Mail' : 'Default Vacation'), enable: '1', status: '1', remark: '' }
];
export function buildMailTemplateListPayload() { const rows = templateRows('mail'); return { list: rows, results: rows, items: rows, total: String(rows.length), totalCount: String(rows.length) }; }
export function buildVacationTemplateListPayload() { const rows = templateRows('vacation'); return { list: rows, results: rows, items: rows, total: String(rows.length), totalCount: String(rows.length) }; }
export function buildTimeTemplateListPayload() { const rows = templateRows('time'); return { list: rows, results: rows, items: rows, total: String(rows.length), totalCount: String(rows.length) }; }

// --- TVWall -------------------------------------------------------------------
export function buildTvWallsPayload() {
  const walls = [{
    tvWallId: '1', id: '1', tvWallCode: 'wall-1', tvWallName: 'TV Wall 1',
    rows: '2', cols: '2', windowTotal: '4', enable: '1', status: '1',
    orgCode: '001', createTime: '2026-01-01 00:00:00'
  }];
  return { list: walls, results: walls, items: walls, tvWallList: walls, tvwalls: walls, total: String(walls.length), totalCount: String(walls.length) };
}
export function buildTvWallDetailPayload(id) {
  return {
    tvWallId: str(id), id: str(id), tvWallCode: 'wall-' + str(id), tvWallName: 'TV Wall ' + str(id),
    rows: '2', cols: '2', windowTotal: '4', enable: '1', status: '1',
    windows: [], list: [], results: [], items: []
  };
}

// --- OMMS alert ---------------------------------------------------------------
export function buildOmmsAlertListPayload() {
  return { ...page([]), alertList: [], ruleList: [] };
}
export function buildOmmsAlertRuleListPayload() {
  const rows = OMMS_ALERT_TYPES.map((a) => ({
    ruleId: a.alertType, id: a.alertType, alertType: a.alertType, alertTypeId: a.alertType,
    ruleName: a.alertName, enable: '1', status: '1', level: a.level
  }));
  return { list: rows, results: rows, items: rows, ruleList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildOmmsAlertStatisticsPayload() {
  return { total: '0', unhandled: '0', handled: '0', today: '0', week: '0', month: '0', list: [], results: [], items: [] };
}

// --- Event Center summary + misc ----------------------------------------------
export function buildAlarmOverviewSummaryPayload() {
  return {
    total: '0', todayCount: '0', unhandledCount: '0', handledCount: '0',
    weekCount: '0', monthCount: '0',
    byType: [], byLevel: [], byOrg: [], list: [], results: [], items: []
  };
}
export function buildIvssListPayload() {
  const rows = [...DEVICE_REGISTRY.values()].map((d) => ({
    deviceCode: d.deviceCode, deviceName: d.deviceName, ivssEnable: '0',
    orgCode: deviceOrgCode(d), orgName: orgName(deviceOrgCode(d)), status: '1'
  }));
  return { list: rows, results: rows, items: rows, ivssList: rows, total: String(rows.length), totalCount: String(rows.length) };
}
export function buildEventSubscriptionPayload() {
  return { subscribe: '1', enable: '1', status: '1', subscriptionId: 'sub-1', list: [], results: [], items: [] };
}
