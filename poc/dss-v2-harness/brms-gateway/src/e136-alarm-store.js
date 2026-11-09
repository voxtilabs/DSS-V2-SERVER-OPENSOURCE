// ===== E-136: persistent alarm store (data/alarms.json) + plans/users/roles ===
//
// Que resuelve: el Event Center del cliente DSS 8.006 (WINPC_V2) es un
// backend de verdad, no un stub. La matriz de gaps (rea-gap-client.md filas
// 25/37/38/41/42/43/44/50/51) exige un ALMACEN PERSISTENTE de alarmas con
// paginado+filtrado, confirmacion (handle) individual y en lote, CRUD de
// planes de alarma (62 campos + 13 `link*`), usuarios, roles y cambio de
// clave. Antes todo eso caia en el catch-all `rpcEnvelope(method,{})`
// (index.js:1111) -> payload vacio -> el Event Center del cliente native se
// queda en blanco.
//
// Este modulo es la CAPA DE DATOS (sin Fastify): stores JSON con carga
// perezosa + escritura atomica (tmp + rename), igual que e041-orgs.js.
//
// Los tests NUNCA tocan data/*.json compartido (brms.test.js corre en otro
// proceso y levanta el gateway en 11443): el path es inyectable.
//
// Evidencia:
//   - %TEMP%/opencode/rea-gap-client.md filas 25,37,38,41,42,43,44,50,51
//   - src/e118-event-center.js (esquema nativo ParseAlarmEventNotify)
//   - src/e039-mq-notify.js (sobre de alarma {method,info})
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = path.join(HERE, '..', 'data');
export const ALARM_STORE_PATH = path.join(DATA_DIR, 'alarms.json');
export const ALARM_PLAN_STORE_PATH = path.join(DATA_DIR, 'alarm-plans.json');
export const USER_STORE_PATH = path.join(DATA_DIR, 'users.json');
export const ROLE_STORE_PATH = path.join(DATA_DIR, 'roles.json');

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
export const str = (v) => (v === undefined || v === null ? '' : String(v));
const nowIso = () => new Date().toISOString();

let counter = 0;
/** Id estable y monotono: <prefijo><base36 time><base36 seq> */
export function nextId(prefix = 'ALM') {
  counter = (counter + 1) % 46656;
  return `${prefix}${Date.now().toString(36)}${counter.toString(36).padStart(3, '0')}`;
}

/** Normaliza a array: array -> copia filtrada, string -> split(','), null -> [] */
export function toArray(v) {
  if (Array.isArray(v)) return v.filter((x) => x !== undefined && x !== null && x !== '');
  if (v === undefined || v === null || v === '') return [];
  return String(v).split(',').map((s) => s.trim()).filter(Boolean);
}

/** Epoch ms de un timestamp; NaN si no parseable (el filtro se salta). */
export function toMillis(v) {
  if (v === undefined || v === null || v === '') return NaN;
  if (typeof v === 'number') return v;
  const t = Date.parse(String(v).replace(' ', 'T'));
  return Number.isNaN(t) ? Date.parse(String(v)) : t;
}

export function readJson(file) {
  if (!file) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/** Escritura atomica: tmp + rename (nunca deja un JSON a medias). */
export function writeJson(file, value) {
  if (!file) return false;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
    fs.renameSync(tmp, file);
    return true;
  } catch (err) {
    console.error(`[E136-STORE] no se pudo persistir ${file}: ${err.message}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// REGISTRO DE ALARMA
// ---------------------------------------------------------------------------
// Campos del esquema nativo ParseAlarmEventNotify (e118) + los que exige la
// matriz de gaps para handle/export (handleStatus/handleUser/handleMessage/
// comment/mailReceivers/alarmDate).
export const ALARM_FIELDS = [
  'alarmId', 'alarmCode', 'eventId', 'alarmTypeId', 'alarmType', 'alarmTypeName',
  'alarmGrade', 'alarmLevel', 'deviceCode', 'deviceId', 'deviceName',
  'channelId', 'channelCode', 'channelName', 'alarmTime', 'alarmDate', 'eventTime',
  'orgCode', 'nodeCode', 'handleStatus', 'handleUser', 'handleUserId',
  'handleUserName', 'handleMessage', 'handleDate', 'comment', 'mailReceivers',
  'alarmPicture', 'alarmRecordPosition', 'recordTime', 'preRecordTime',
  'linkVideoChannels', 'linkRecordChannels', 'mapIds', 'streamType',
  'strMessage', 'eventRemark', 'gpsX', 'gpsY', 'height', 'angle', 'speed',
  'disarmUserIds', 'createTime', 'updateTime'
];

/** Normaliza cualquier entrada a un registro de alarma completo. */
export function normalizeAlarm(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const alarmTime = str(src.alarmTime || src.eventTime || src.alarmDate || src.time || nowIso());
  const alarmCode = str(src.alarmCode || src.alarmId || src.eventId || '') || nextId('AC');
  const alarmTypeId = str(src.alarmTypeId ?? src.alarmType ?? '99');
  const deviceCode = str(src.deviceCode || src.deviceId);
  const channelId = str(src.channelId || src.channelCode);
  return {
    alarmId: str(src.alarmId || src.eventId || alarmCode),
    alarmCode,
    eventId: str(src.eventId || src.alarmId || alarmCode),
    alarmTypeId,
    alarmType: str(src.alarmType || alarmTypeId),
    alarmTypeName: str(src.alarmTypeName || src.alarmType || 'Generic Event'),
    alarmGrade: str(src.alarmGrade ?? '1'),
    alarmLevel: str(src.alarmLevel ?? '1'),
    deviceCode,
    deviceId: str(src.deviceId || deviceCode),
    deviceName: str(src.deviceName),
    channelId,
    channelCode: str(src.channelCode || channelId),
    channelName: str(src.channelName),
    alarmTime,
    alarmDate: str(src.alarmDate || alarmTime),
    eventTime: str(src.eventTime || alarmTime),
    orgCode: str(src.orgCode || src.nodeCode || '001'),
    nodeCode: str(src.nodeCode || src.orgCode || '001'),
    handleStatus: str(src.handleStatus ?? '0'),
    handleUser: str(src.handleUser || src.handleUserName),
    handleUserId: str(src.handleUserId),
    handleUserName: str(src.handleUserName || src.handleUser),
    handleMessage: str(src.handleMessage),
    handleDate: str(src.handleDate),
    comment: str(src.comment),
    mailReceivers: toArray(src.mailReceivers),
    alarmPicture: str(src.alarmPicture),
    alarmRecordPosition: str(src.alarmRecordPosition),
    recordTime: str(src.recordTime),
    preRecordTime: str(src.preRecordTime ?? '10'),
    linkVideoChannels: toArray(src.linkVideoChannels),
    linkRecordChannels: toArray(src.linkRecordChannels),
    mapIds: toArray(src.mapIds),
    streamType: str(src.streamType ?? '0'),
    strMessage: str(src.strMessage || src.description || src.eventRemark),
    eventRemark: str(src.eventRemark || src.description || src.strMessage),
    gpsX: str(src.gpsX ?? '0'),
    gpsY: str(src.gpsY ?? '0'),
    height: str(src.height ?? '0'),
    angle: str(src.angle ?? '0'),
    speed: str(src.speed ?? '0'),
    disarmUserIds: toArray(src.disarmUserIds),
    createTime: str(src.createTime || nowIso()),
    updateTime: str(src.updateTime || nowIso())
  };
}

// ---------------------------------------------------------------------------
// STORE DE ALARMAS
// ---------------------------------------------------------------------------
/**
 * Store de alarmas con carga perezosa del JSON y escritura atomica.
 * @param {object} opts
 * @param {string} [opts.filePath]  ruta del JSON (null => solo memoria)
 * @param {boolean} [opts.persist]  escribir en disco (default true)
 * @param {Array}  [opts.seed]      alarmas iniciales
 */
export function createAlarmStore({ filePath = ALARM_STORE_PATH, persist = true, seed = [] } = {}) {
  let alarms = null;

  function ensure() {
    if (alarms) return alarms;
    const loaded = readJson(filePath);
    alarms = Array.isArray(loaded) ? loaded.map((a) => normalizeAlarm(a)) : [];
    if (!alarms.length && Array.isArray(seed) && seed.length) {
      alarms = seed.map((a) => normalizeAlarm(a));
    }
    return alarms;
  }

  function save() {
    if (!persist) return false;
    return writeJson(filePath, ensure());
  }

  function findIndex(target) {
    const list = ensure();
    if (!target) return -1;
    // E-136 fix: cualquier identificador del target (alarmCode/alarmId/eventId,
    // string o numero) matchea contra CUALQUIER campo del registro - antes se
    // comparaba el objeto tal cual (nunca matcheaba) o solo alarmCode.
    const codes = (typeof target === 'object'
      ? [target.alarmCode, target.alarmId, target.eventId]
      : [target]).map(str).filter(Boolean);
    if (codes.length) {
      const idx = list.findIndex((a) =>
        codes.includes(str(a.alarmCode)) || codes.includes(str(a.alarmId)) || codes.includes(str(a.eventId)));
      if (idx >= 0) return idx;
    }
    const dev = str(typeof target === 'object' ? target.deviceCode : '');
    const when = str(typeof target === 'object' ? (target.alarmDate || target.alarmTime) : '');
    if (dev && when) {
      return list.findIndex((a) => a.deviceCode === dev && (a.alarmDate === when || a.alarmTime === when));
    }
    return -1;
  }

  /** Agrega una alarma y la persiste. */
  function add(input = {}) {
    const rec = normalizeAlarm(input);
    if (!rec.alarmCode) rec.alarmCode = nextId('AC');
    ensure().push(rec);
    save();
    return rec;
  }

  /** Agrega varias alarmas de una vez. */
  function addMany(list = []) {
    const out = (Array.isArray(list) ? list : [list]).map((a) => normalizeAlarm(a));
    ensure().push(...out);
    save();
    return out;
  }

  /** Actualiza campos sueltos de una alarma. */
  function update(target, patch = {}) {
    const idx = findIndex(target);
    if (idx < 0) return null;
    const rec = ensure()[idx];
    Object.assign(rec, normalizeAlarm({ ...rec, ...patch, alarmCode: rec.alarmCode }));
    rec.updateTime = nowIso();
    save();
    return rec;
  }

  /** Borra una alarma. */
  function remove(target) {
    const idx = findIndex(target);
    if (idx < 0) return false;
    ensure().splice(idx, 1);
    save();
    return true;
  }

  /** Reemplaza todo el contenido (seed / restore). */
  function replaceAll(list = []) {
    alarms = (Array.isArray(list) ? list : []).map((a) => normalizeAlarm(a));
    save();
    return alarms;
  }

  function clear() {
    alarms = [];
    save();
    return true;
  }

  function all() {
    return ensure().slice();
  }

  function get(target) {
    const idx = findIndex(target);
    return idx < 0 ? null : ensure()[idx];
  }

  function size() {
    return ensure().length;
  }

  // --- filtros de GetPageAlarmRecords -------------------------------------
  function matches(rec, q = {}) {
    const types = toArray(q.alarmTypes);
    if (types.length && !types.includes(str(rec.alarmTypeId)) && !types.includes(str(rec.alarmType))) return false;
    if (q.alarmGrade !== undefined && q.alarmGrade !== '' && str(rec.alarmGrade) !== str(q.alarmGrade)) return false;
    if (q.handleStatus !== undefined && q.handleStatus !== '' && str(rec.handleStatus) !== str(q.handleStatus)) return false;
    if (q.handleUser) {
      const hu = str(q.handleUser);
      if (str(rec.handleUser) !== hu && str(rec.handleUserName) !== hu) return false;
    }
    if (q.handleMessage && !str(rec.handleMessage).includes(str(q.handleMessage))) return false;
    if (q.deviceCode && str(rec.deviceCode) !== str(q.deviceCode)) return false;
    const devs = toArray(q.deviceCodes);
    if (devs.length && !devs.includes(str(rec.deviceCode))) return false;
    const chans = toArray(q.channelIds);
    if (chans.length && !chans.includes(str(rec.channelId)) && !chans.includes(str(rec.channelCode))) return false;
    if (q.splitId && !str(rec.alarmId).includes(str(q.splitId)) && !str(rec.alarmCode).includes(str(q.splitId))) return false;
    const start = toMillis(q.startAlarmTime);
    const end = toMillis(q.endAlarmTime);
    const at = toMillis(rec.alarmTime);
    if (!Number.isNaN(start) && !Number.isNaN(at) && at < start) return false;
    if (!Number.isNaN(end) && !Number.isNaN(at) && at > end) return false;
    return true;
  }

  /**
   * Paginado + filtrado (contrato BRMS.Alarm.GetPageAlarmRecords).
   * Acepta page/currentPage/pageNo, pageSize, alarmTypes[], alarmGrade,
   * handleStatus, handleUser, handleMessage, deviceCodes[], channelIds[],
   * startAlarmTime/endAlarmTime, splitId, orderType, orderDirection.
   */
  function page(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    const allRows = ensure().filter((r) => matches(r, q));
    const orderType = str(q.orderType || 'alarmTime');
    const dir = str(q.orderDirection || 'desc').toLowerCase() === 'asc' ? 1 : -1;
    allRows.sort((a, b) => {
      const av = str(a[orderType] ?? a.alarmTime);
      const bv = str(b[orderType] ?? b.alarmTime);
      if (av === bv) return str(a.alarmCode).localeCompare(str(b.alarmCode));
      return av > bv ? dir : -dir;
    });
    const pageNo = Math.max(1, parseInt(q.currentPage || q.pageNo || q.page || '1', 10) || 1);
    const pageSize = Math.max(1, parseInt(q.pageSize || '20', 10) || 20);
    const startIdx = (pageNo - 1) * pageSize;
    const slice = allRows.slice(startIdx, startIdx + pageSize);
    const total = allRows.length;
    return {
      records: slice, list: slice, results: slice, items: slice, pageData: slice,
      alarms: slice,
      total, totalCount: total, count: slice.length,
      page: pageNo, currentPage: pageNo, pageNo, pageSize,
      pageCount: Math.ceil(total / pageSize) || 0
    };
  }

  /**
   * Confirmacion (handle) individual o en lote.
   * Entrada: {alarmCode|deviceCode+alarmDate, handleUser, handleMessage,
   * handleStatus, comment, mailReceivers[]} o {alarms:[...]}.
   */
  function handle(request = {}) {
    const req = request && typeof request === 'object' ? request : {};
    const targets = Array.isArray(req.alarms) && req.alarms.length ? req.alarms : [req];
    const handleStatus = str(req.handleStatus ?? '1');
    const handleUser = str(req.handleUser ?? req.handleUserName ?? '');
    const handleMessage = str(req.handleMessage ?? '');
    const comment = str(req.comment ?? '');
    const mailReceivers = toArray(req.mailReceivers);
    const stamp = nowIso();
    const updated = [];
    for (const t of targets) {
      const idx = findIndex(t);
      if (idx < 0) continue;
      const rec = ensure()[idx];
      rec.handleStatus = handleStatus || '1';
      if (handleUser) { rec.handleUser = handleUser; rec.handleUserName = handleUser; }
      if (handleMessage) rec.handleMessage = handleMessage;
      rec.comment = comment;
      rec.mailReceivers = mailReceivers;
      rec.handleDate = stamp;
      rec.updateTime = stamp;
      updated.push(rec);
    }
    save();
    return {
      success: true,
      handled: updated.map((r) => r.alarmCode),
      handledIds: updated.map((r) => r.alarmCode),
      count: updated.length,
      records: updated, list: updated, results: updated
    };
  }

  /** Desarmado (BRMS.Alarm.DisarmAlarm): marca disarmUserIds + remark. */
  function disarm(request = {}) {
    const req = request && typeof request === 'object' ? request : {};
    const stamp = nowIso();
    const updated = [];
    const list = ensure().filter((r) => {
      if (req.alarmTypeId && str(r.alarmTypeId) !== str(req.alarmTypeId)) return false;
      if (req.alarmSourceCode && str(r.deviceCode) !== str(req.alarmSourceCode)) return false;
      if (req.channelId && str(r.channelId) !== str(req.channelId)) return false;
      return true;
    });
    for (const rec of list) {
      rec.disarmUserIds = toArray(req.disarmUserIds);
      rec.eventRemark = str(req.remark ?? rec.eventRemark);
      rec.updateTime = stamp;
      updated.push(rec);
    }
    save();
    return { success: true, disarmed: updated.length, records: updated, list: updated, results: updated };
  }

  /** Resumen del panel (BRMS.AlarmOverview.GetSummary). */
  function stats(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    const start = toMillis(q.startTime);
    const end = toMillis(q.endTime);
    const rows = ensure().filter((r) => {
      if (q.orgCode && str(r.orgCode) !== str(q.orgCode)) return false;
      const at = toMillis(r.alarmTime);
      if (!Number.isNaN(start) && !Number.isNaN(at) && at < start) return false;
      if (!Number.isNaN(end) && !Number.isNaN(at) && at > end) return false;
      return true;
    });
    const byType = new Map();
    const byDevice = new Map();
    let handled = 0;
    const today = new Date().toISOString().slice(0, 10);
    let todayCount = 0;
    for (const r of rows) {
      if (str(r.handleStatus) === '1') handled++;
      const tk = str(r.alarmTypeId);
      byType.set(tk, (byType.get(tk) || 0) + 1);
      const dk = str(r.deviceCode);
      byDevice.set(dk, (byDevice.get(dk) || 0) + 1);
      if (str(r.alarmDate).startsWith(today)) todayCount++;
    }
    const unhandled = rows.length - handled;
    return {
      mode: str(q.mode ?? '1'),
      orgCode: str(q.orgCode ?? ''),
      startTime: str(q.startTime ?? ''),
      endTime: str(q.endTime ?? ''),
      total: rows.length, totalCount: rows.length, count: rows.length,
      unhandledCount: unhandled, handledCount: handled, todayCount,
      alarmCount: rows.length,
      alarmTypeCounts: [...byType.entries()].map(([alarmTypeId, count]) => ({ alarmTypeId, count })),
      deviceCounts: [...byDevice.entries()].map(([deviceCode, count]) => ({ deviceCode, count })),
      status: '1', success: true
    };
  }

  return {
    add, addMany, update, remove, replaceAll, clear, all, get, size,
    page, handle, disarm, stats, save,
    get filePath() { return filePath; }
  };
}

export default { createAlarmStore, normalizeAlarm, ALARM_FIELDS, ALARM_STORE_PATH };
