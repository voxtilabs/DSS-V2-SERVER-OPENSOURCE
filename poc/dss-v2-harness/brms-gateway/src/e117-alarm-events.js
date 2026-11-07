// ===== E-117: Event Center + Event Config + Generic Event ingestion ========
//
// SPA API inventory (web-module/js) + the client log show the Event Center
// module contracts (DSS Client 8.006):
//   /brms/api/v1.1/alarm/general/event (+ /$, /list)   generic event ingest
//   /brms/api/v1.1/config/general/event                 generic event config
//   /omms/api/v1.1/alert/subscribe                      alert subscription
//   /brms/api/v1.1/alarm/overview/top/alarm-source/list  event center stats
//   /brms/api/v1.1/alarm/overview/top/alarm-type/list
//   /brms/api/v1.1/alarm/overview/trend
//   /brms/api/v1.1/alarm/config/prerecord/channel/page (+update/batch)
//   /brms/api/v1.1/alarm/disarm/config/page (+update/batch)
//   /brms/api/v1.1/alarm/storm/restrain/alarm-type/list
//   /brms/api/v1.1/alarm/combination/source/page
// Generic events are ingested via POST alarm/general/event (or the admin
// bridge /admin/API/GenericEvent/Report) and pushed to the client over
// brms.notifyAlarms + mq.alarm.msg.topic.* (see e039 alarmEvent), so they
// appear LIVE in the Event Center - the DSS "custom event" channel.
import fs from 'node:fs';
import { DEVICE_REGISTRY, OMMS_ALERT_TYPES, allChannels } from './e025-devices.js';
import { deviceOrgCode } from './e041-orgs.js';

const EVENTS_FILE = process.env.EVENTS_FILE || (fs.existsSync('/app/data') ? '/app/data/events.json' : './data/events.json');
const MAX_EVENTS = 500;

function loadEvents() {
  try { return JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8')); } catch { return []; }
}
function saveEvents(list) {
  try { fs.writeFileSync(EVENTS_FILE, JSON.stringify(list.slice(0, MAX_EVENTS), null, 1)); } catch { /* best effort */ }
}
let EVENT_STORE = loadEvents(); // newest first

export function ingestGeneralEvent(body = {}) {
  const now = new Date().toISOString();
  const event = {
    eventId: String(body.eventId || ('ge-' + Date.now())),
    alarmId: String(body.eventId || ('ge-' + Date.now())),
    eventType: String(body.eventType ?? '1'),
    eventTypeName: String(body.eventTypeName || body.description || 'Generic Event'),
    eventLevel: String(body.eventLevel ?? '1'),
    channelId: String(body.channelId ?? ''),
    channelName: String(body.channelName ?? ''),
    deviceCode: String(body.deviceCode ?? ''),
    deviceName: String(body.deviceName ?? ''),
    orgCode: String(body.orgCode ?? (body.deviceCode ? (deviceOrgCodeOf(body.deviceCode) || '001') : '001')),
    eventTime: String(body.eventTime ?? now),
    description: String(body.description ?? ''),
    handleStatus: '0', status: '1',
    source: 'generic', createTime: now
  };
  EVENT_STORE.unshift(event);
  EVENT_STORE = EVENT_STORE.slice(0, MAX_EVENTS);
  saveEvents(EVENT_STORE);
  return event;
}

function deviceOrgCodeOf(deviceCode) {
  const d = DEVICE_REGISTRY.get(deviceCode) || [...DEVICE_REGISTRY.values()].find((x) => String(deviceCode).startsWith(x.deviceCode));
  return d ? deviceOrgCode(d) : '001';
}

export function buildGeneralEventPagePayload(query = {}) {
  const page = Math.max(1, Number(query.page || 1) || 1);
  const pageSize = Math.max(1, Number(query.pageSize || 20) || 20);
  const kw = String(query.keyword || '').toLowerCase();
  let rows = EVENT_STORE;
  if (kw) rows = rows.filter((e) => (e.description || '').toLowerCase().includes(kw) || (e.deviceCode || '').toLowerCase().includes(kw));
  const total = rows.length;
  const pageData = rows.slice((page - 1) * pageSize, page * pageSize);
  return {
    pageData, list: pageData, results: pageData, items: pageData, eventList: pageData,
    total: String(total), totalCount: String(total),
    pageNo: String(page), page: String(page), pageSize: String(pageSize),
    pageCount: String(Math.max(1, Math.ceil(total / pageSize)))
  };
}

export function buildGeneralEventConfigPayload() {
  return {
    enable: '1', status: '1', eventEnable: '1',
    keepDays: '30', maxCount: '10000',
    autoHandle: '0', soundEnable: '1', popupEnable: '0',
    list: [], results: [], items: []
  };
}

// omms alert subscription: which alert types the user subscribes to (all).
export function buildAlertSubscribePayload() {
  const rows = OMMS_ALERT_TYPES.map((a) => ({
    alertType: a.alertType, alertTypeId: a.alertType, alertTypeName: a.alertName,
    subscribe: '1', enable: '1', level: String(a.level)
  }));
  return {
    list: rows, results: rows, items: rows, subscribeList: rows, alertTypeList: rows,
    subscribe: '1', enable: '1',
    total: String(rows.length), totalCount: String(rows.length)
  };
}

const page0 = () => ({ pageData: [], list: [], results: [], items: [], total: '0', totalCount: '0', pageNo: '1', page: '1', pageSize: '20', pageCount: '1' });

export function buildAlarmOverviewTopSourcePayload() {
  const rows = [...DEVICE_REGISTRY.values()].map((d) => ({
    deviceCode: d.deviceCode, deviceName: d.deviceName, orgCode: deviceOrgCode(d),
    alarmCount: '0', ratio: '0'
  }));
  return { list: rows, results: rows, items: rows, topList: rows, total: String(rows.length), totalCount: String(rows.length) };
}

export function buildAlarmOverviewTopTypePayload() {
  const rows = OMMS_ALERT_TYPES.slice(0, 5).map((a) => ({
    alarmType: a.alertType, alarmTypeId: a.alertType, alarmTypeName: a.alertName, alarmCount: '0', ratio: '0'
  }));
  return { list: rows, results: rows, items: rows, topList: rows, total: String(rows.length), totalCount: String(rows.length) };
}

export function buildAlarmOverviewTrendPayload() {
  const points = [];
  const now = Date.now();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    points.push({ date: d.toISOString().slice(0, 10), time: d.toISOString().slice(0, 10), alarmCount: '0', count: '0' });
  }
  return { list: points, results: points, items: points, trendList: points, total: String(points.length), totalCount: String(points.length) };
}

export function buildPrerecordChannelPagePayload() {
  // the registered channels with prerecord disabled by default (honest empty)
  const chans = allChannels().slice(0, 50).map((c) => ({
    channelId: c.channelId || c.channelCode, channelCode: c.channelCode,
    channelName: c.channelName, deviceCode: c.deviceCode,
    prerecord: '0', prerecordTime: '10', enable: '0', status: '1'
  }));
  const pageData = chans;
  return {
    pageData, list: pageData, results: pageData, items: pageData, channelList: pageData,
    total: String(pageData.length), totalCount: String(pageData.length),
    pageNo: '1', page: '1', pageSize: '20', pageCount: '1'
  };
}

export function buildDisarmConfigPagePayload() {
  return { ...page0(), disarmConfigList: [] };
}

export function buildStormRestrainAlarmTypePayload() {
  const rows = OMMS_ALERT_TYPES.map((a) => ({ alarmType: a.alertType, alarmTypeId: a.alertType, alarmTypeName: a.alertName, restrain: '0', enable: '1' }));
  return { list: rows, results: rows, items: rows, alarmTypeList: rows, total: String(rows.length), totalCount: String(rows.length) };
}

export function buildCombinationSourcePagePayload() {
  return { ...page0(), sourceList: [] };
}
