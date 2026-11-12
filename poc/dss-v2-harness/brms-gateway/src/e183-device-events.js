// ===== E-183: ingesta de eventos de dispositivo (IVS / IA / intrusión) ======
//
// Hasta ahora un DVR/NVR Dahua con tripwire o analitica NO podia reportar nada:
// el gateway solo aceptaba el body generico de `alarm/general/event` y no
// traducia los codigos de evento del fabricante (research del dominio EVENTS,
// gaps P0-1/P0-2).
//
// Este modulo normaliza CUALQUIERA de las formas que llegan del dispositivo:
//   - { code: "CrossLineDetection" | "EVENT_IVS_CROSSLINEDETECTION" | 0x0010, action, index }
//   - { eventType: "13", channelId, deviceCode, time, picData } (ya generico)
//   - { alarmType, deviceCode, channel, eventTime, picture }
// a un body que `ingestGeneralEvent` entiende (eventType = id DSS 1..22/99).
import { DEVICE_REGISTRY, dssChannelCode } from './e025-devices.js';

// Dahua SDK event codes -> DSS alarmTypeId. DSS_ALARM_TYPE_CATALOG
// (e118-alarm-notify.js) es la fuente de los ids: 13..19 IVS, 20..22 AI.
export const DAHUA_EVENT_MAP = {
  // video base (ids del catalogo DSS)
  VideoMotion: '1', MotionDetect: '1', MotionDetection: '1',
  AlarmLocal: '2', VideoLoss: '3', VideoBlind: '6', VideoAbnormal: '7',
  // IVS (tripwire / intrusion / comportamiento)
  CrossLineDetection: '13', CrossLine: '13',
  CrossRegionDetection: '14', CrossRegion: '14',
  Intrusion: '15', IntrusionDetection: '15',
  FastMove: '16', AbruptSlowdown: '17', AbruptSpeedup: '18', Freeze: '19',
  // IA
  FaceDetection: '20', FaceDetect: '20',
  FaceRecognition: '21', FaceRecognitionDetect: '21',
  ANPR: '22', TrafficJunction: '22', NumberPlateDetection: '22'
};

// Numeric SDK constants (EVENT_* in dhnetsdk) for the same families.
const NUMERIC_EVENT_MAP = {
  0x0001: '1', 0x0002: '3', 0x0003: '6', 0x0004: '7',
  0x0010: '13', 0x0011: '13', 0x0013: '14', 0x0014: '15',
  0x0015: '16', 0x0016: '17', 0x0017: '18', 0x0018: '19',
  0x0019: '20', 0x001a: '21', 0x001b: '22'
};

const KNOWN_IDS = new Set(['1', '2', '3', '6', '7', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '99']);

const NAME_BY_ID = {
  '1': { code: 'VideoMotion', name: 'Motion Detection' },
  '2': { code: 'AlarmLocal', name: 'Local Alarm' },
  '3': { code: 'VideoLoss', name: 'Video Loss' },
  '6': { code: 'VideoBlind', name: 'Video Blind' },
  '7': { code: 'VideoAbnormal', name: 'Video Abnormal' },
  '13': { code: 'CrossLineDetection', name: 'Tripwire (Cross Line)' },
  '14': { code: 'CrossRegionDetection', name: 'Intrusion Region' },
  '15': { code: 'Intrusion', name: 'Intrusion' },
  '16': { code: 'FastMove', name: 'Fast Move' },
  '17': { code: 'AbruptSlowdown', name: 'Loitering' },
  '18': { code: 'AbruptSpeedup', name: 'Abrupt Speedup' },
  '19': { code: 'Freeze', name: 'Freeze' },
  '20': { code: 'FaceDetection', name: 'Face Detection' },
  '21': { code: 'FaceRecognition', name: 'Face Recognition' },
  '22': { code: 'ANPR', name: 'ANPR / Plate' },
  '99': { code: 'Generic', name: 'Generic Alarm' }
};

function str(v) {
  if (v === undefined || v === null) return '';
  return String(v);
}

function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null && String(obj[k]).length) return obj[k];
  }
  return '';
}

// Accepts "CrossLineDetection", "EVENT_IVS_CROSSLINEDETECTION", 0x10, "16",
// "13" and returns the DSS alarmTypeId.
export function resolveAlarmTypeId(raw) {
  const v = raw;
  if (typeof v === 'number') {
    const byNum = NUMERIC_EVENT_MAP[v];
    if (byNum) return byNum;
    if (KNOWN_IDS.has(String(v))) return String(v);
  }
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (!s) return '99';
  if (KNOWN_IDS.has(s)) return s;
  if (/^0x[0-9a-f]+$/i.test(s)) {
    const n = parseInt(s, 16);
    if (NUMERIC_EVENT_MAP[n]) return NUMERIC_EVENT_MAP[n];
  }
  const norm = s.replace(/^EVENT_/i, '').replace(/^IVS_/i, '').replace(/_/g, '').toLowerCase();
  for (const [name, id] of Object.entries(DAHUA_EVENT_MAP)) {
    if (name.toLowerCase() === norm) return id;
  }
  for (const [name, id] of Object.entries(DAHUA_EVENT_MAP)) {
    if (norm.includes(name.toLowerCase())) return id;
  }
  return '99';
}

function channelIdFor(body, deviceCode) {
  const direct = str(pick(body, ['channelId', 'channelCode', 'Channel', 'channel', 'ChannelId']));
  if (direct.includes('$')) return direct;
  const idxRaw = pick(body, ['channel', 'Channel', 'index', 'Index', 'channelIndex', 'channelNo']);
  const idx = Number.parseInt(String(idxRaw === '' ? '0' : idxRaw), 10);
  if (!deviceCode) return direct;
  const seq = Number.isFinite(idx) && idx >= 0 ? idx : 0;
  try { return dssChannelCode(deviceCode, seq); } catch { return `${deviceCode}$1$0$${seq}`; }
}

// Normalizes a device push into the body accepted by ingestGeneralEvent.
export function deviceEventToGeneral(body = {}) {
  const b = body && typeof body === 'object' ? body : {};
  const nested = (b.data && typeof b.data === 'object') ? b.data : {};
  const merged = { ...b, ...nested };

  const rawType = pick(merged, ['code', 'eventCode', 'eventType', 'alarmType', 'AlarmType', 'type', 'eventTypeId']);
  const alarmTypeId = resolveAlarmTypeId(rawType);
  const meta = NAME_BY_ID[alarmTypeId] || NAME_BY_ID['99'];

  const deviceCode = str(pick(merged, ['deviceCode', 'deviceId', 'deviceID', 'DeviceID', 'DeviceId', 'machineName']));
  const device = deviceCode ? DEVICE_REGISTRY.get(deviceCode) : null;
  const channelId = channelIdFor(merged, deviceCode);

  const timeRaw = pick(merged, ['eventTime', 'alarmTime', 'time', 'Time', 'utc', 'occurTime']);
  let eventTime = '';
  if (timeRaw) {
    if (typeof timeRaw === 'number' || /^\d{10,13}$/.test(String(timeRaw))) {
      const n = Number(timeRaw);
      eventTime = new Date(String(timeRaw).length <= 10 ? n * 1000 : n).toISOString();
    } else {
      const parsed = new Date(timeRaw);
      eventTime = Number.isNaN(parsed.getTime()) ? String(timeRaw) : parsed.toISOString();
    }
  }

  const description = str(pick(merged, ['description', 'strMessage', 'eventRemark', 'memo', 'name'])) || meta.name;
  const picture = str(pick(merged, ['alarmPicture', 'picture', 'picData', 'snapshot', 'imageUrl', 'picUrl']));

  return {
    ...merged,
    eventType: alarmTypeId,
    alarmTypeId,
    alarmType: meta.code,
    eventTypeName: meta.name,
    eventLevel: str(pick(merged, ['eventLevel', 'alarmLevel', 'alarmGrade', 'level'])) || '1',
    deviceCode,
    deviceId: deviceCode,
    deviceName: str(pick(merged, ['deviceName'])) || (device ? str(device.deviceName) : deviceCode),
    channelId,
    channelCode: channelId,
    channelName: str(pick(merged, ['channelName', 'ChannelName'])) || (channelId ? channelId : ''),
    orgCode: str(pick(merged, ['orgCode'])) || (device ? str(device.orgCode) : '001'),
    eventTime: eventTime || undefined,
    alarmTime: eventTime || undefined,
    description,
    strMessage: description,
    alarmPicture: picture,
    eventSourceType: str(pick(merged, ['eventSourceType'])) || '3',
    source: str(pick(merged, ['source'])) || 'device',
    linkVideoChannels: Array.isArray(b.linkVideoChannels) ? b.linkVideoChannels : (channelId ? [channelId] : [])
  };
}
