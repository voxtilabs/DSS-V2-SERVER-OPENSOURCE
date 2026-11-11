// ===== E-135: MOTOR RPC (capa 3) - catalogo de metodos + payloads reales P0 =====
//
// Que resuelve: el gateway tenia un catch-all (`rpcEnvelope(method,{})` en
// index.js:1111) que devolvia 40B de payload vacio para los ~2000 metodos
// RPC del cliente DSS 8.006 (DPSDK.dll). Este modulo es el MOTOR: todo
// metodo CONOCIDO (catalogo cosechado en data/rpc-method-catalog.txt, 2024
// entradas) recibe un envelope con `code: 1000` + las claves de su FAMILIA
// (Get/Query/List/Page -> results/list/total/totalCount; Add/Update/Save/
// Create -> success; Delete/Batch -> success), y los metodos P0 del gap
// matrix reciben su payload REAL con las claves obligatorias del parser
// cliente (DPSDK IsKeyValid) + eco del body.
//
// Evidencia:
//   - data/rpc-method-catalog.txt  (2024 metodos, pool DPSDK/PROLogic)
//   - %TEMP%/opencode/rea-gap-client.md  (matriz 52 filas -> claves oblig.)
//   - %TEMP%/opencode/rea-gap-server.md  (TOP20 server, forma del envelope)
//
// Contrato de transporte (capa 3): el metodo puede llegar por `body.method`
// (RPC method-in-body, FUN_18066e570) o por la URL (`/root/:sub/:fn`).
//
// REGLA DURA: NUNCA devolver el catch-all 40B. Un metodo desconocido tambien
// responde envelope `code: 1000` (no 404, no payload vacio sin code).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CATALOG_PATH = path.join(HERE, 'data', 'rpc-method-catalog.txt');
export const NOTIFY_TOPICS_PATH = path.join(HERE, 'data', 'dpsdk-notify-topics.txt');

// ---------------------------------------------------------------------------
// CATALOGO
// ---------------------------------------------------------------------------
function readLines(file) {
  try {
    return fs.readFileSync(file, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch {
    return [];
  }
}

export const RPC_METHODS = new Set(readLines(CATALOG_PATH));
export const NOTIFY_TOPICS = readLines(NOTIFY_TOPICS_PATH);

// E-135 integracion: codigo de exito alineado con rpcEnvelope() de index.js
// (code 1000) - el cliente nativo ya lo verifica en vivo (live-verify 15/15).
export const RPC_CODE_OK = 1000;

/** Normaliza un metodo a forma canonica dotted (SS/Record/QueryRecords -> SS.Record.QueryRecords) */
export function normalizeMethod(method) {
  let m = String(method ?? '').trim();
  if (!m) return '';
  m = m.replace(/^\/+/, '');
  // quita prefijos de raiz observados (PROLogic.dll 0x722618-0x722720)
  m = m.replace(/^(?:admin\/API|admin\/api|brms\/api|obms\/api|ipms\/api|omms\/api|emap\/api|emapService|arms\/api|otms\/api|OTMS\/API|iams\/api|erms\/api|ecos\/api|vehicleServer|psib|faceService|alarmProcess|cfgs\/api)(?:\/v\d+(?:\.\d+)?)?\//i, '');
  // quita el versionado v1.0/ v1.1 inicial
  m = m.replace(/^v\d+(?:\.\d+)?\//i, '');
  m = m.replace(/\/+$/, '');
  return m;
}

/** Nombre canonico dotted de un metodo (SS/Record/X -> SS.Record.X) */
export function canonicalMethod(method) {
  return normalizeMethod(method).replace(/\//g, '.');
}

/** true si el metodo esta en el catalogo cosechado (dotted o slashed) */
export function catalogKnown(method) {
  const raw = String(method ?? '').trim();
  if (!raw) return false;
  if (RPC_METHODS.has(raw)) return true;
  const canon = canonicalMethod(raw);
  if (RPC_METHODS.has(canon)) return true;
  // variantes: prefijo de version, alias plano BRMSDeviceSynchronize...
  const noVersion = canon.replace(/^v\d+(?:\.\d+)?\./, '');
  if (RPC_METHODS.has(noVersion)) return true;
  const flat = canon.replace(/\./g, '');
  if (flat && RPC_METHODS.has(flat)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// FAMILIAS DE PAYLOAD
// ---------------------------------------------------------------------------
const str = (v) => (v === undefined || v === null ? '' : String(v));

/** Extrae el "data" util de un body RPC {method, data:{...}} */
export function bodyData(body) {
  if (!body || typeof body !== 'object') return {};
  if (body.data && typeof body.data === 'object' && !Array.isArray(body.data)) return body.data;
  if (body.info && typeof body.info === 'object' && !Array.isArray(body.info)) return body.info;
  return body;
}

/**
 * Body util de una request Fastify: query (GET RPC) + body (POST). Si el body
 * trae data/info anidado, la query se fusiona dentro (el cliente manda los
 * params ahi en ambos verbos).
 */
export function requestBody(req) {
  const q = (req && req.query && typeof req.query === 'object') ? req.query : {};
  const b = (req && req.body && typeof req.body === 'object') ? req.body : {};
  if (b.data && typeof b.data === 'object' && !Array.isArray(b.data)) return { ...b, data: { ...q, ...b.data } };
  if (b.info && typeof b.info === 'object' && !Array.isArray(b.info)) return { ...b, info: { ...q, ...b.info } };
  return { ...q, ...b };
}

/** Ultimo segmento del metodo (GetLocalDisks, AddDiskGroup, ...) */
export function methodLeaf(method) {
  const canon = canonicalMethod(method);
  const parts = canon.split('.').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : canon;
}

/**
 * Clasifica el metodo en su familia por el sufijo del nombre.
 *  - 'list'  -> Get*, Query*, List*, Page*, Fetch*, Export...
 *  - 'write' -> Add*, Update*, Save*, Create*, Set*, Open*, Control*, Handle*, Ack...
 *  - 'del'   -> Delete*, Remove*, Batch*
 *  - 'other' -> resto
 */
export function familyOf(method) {
  const leaf = methodLeaf(method);
  // case-insensitive: el catalogo mezcla BRMS.Storage.GetLocalDisks (CamelCase)
  // con arms.label.addLabel / brms.monitor.addView (lowercase, pool PROLogic).
  if (/^(?:get|query|list|page|export|download|fetch|search|find|read|load)/i.test(leaf)) return 'list';
  if (/^(?:add|update|save|create|set|open|close|start|stop|control|trigger|reboot|lock|unlock|arm|disarm|enable|disable|run|exec|handle|ack|bind|unbind|apply|send|push|register|unregister|upload|import|reset|clear)/i.test(leaf)) return 'write';
  if (/^(?:delete|remove|batch|unbind)/i.test(leaf)) return 'del';
  return 'other';
}

/**
 * Eco del body: el cliente manda claves que quiere recibir de vuelta
 * (channelId, page, pageSize, orgCode...). Se superponen sobre los defaults.
 */
export function echoBody(body, payload, { skip = ['method', 'optional'] } = {}) {
  const out = { ...payload };
  const src = bodyData(body);
  for (const [k, v] of Object.entries(src)) {
    if (skip.includes(k)) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Payload heuristico por familia (capa 3, motor generico).
 *   Get/Query/List/Page -> {results:[], list:[], total:'0', totalCount:'0'} + eco page/pageSize
 *   Add/Update/Save/Create -> {success:true} + eco
 *   Delete/Batch -> {success:true}
 *   default -> {}
 */
export function familyPayload(method, body) {
  const fam = familyOf(method);
  const d = bodyData(body);
  if (fam === 'list') {
    const p = { results: [], list: [], total: '0', totalCount: '0' };
    if (d && d.page !== undefined) p.page = d.page;
    if (d && d.pageSize !== undefined) p.pageSize = d.pageSize;
    if (d && d.pageNo !== undefined) p.pageNo = d.pageNo;
    return echoBody(body, p);
  }
  if (fam === 'write') return echoBody(body, { success: true });
  if (fam === 'del') return echoBody(body, { success: true });
  return echoBody(body, {});
}

/**
 * Envelope RPC. FORMA (rea-gap-server.md capa 3):
 *   {code, desc, method, info, data}  - DPSDK lee `data`/`info`.
 * El exito es `code: 1000` (alineado con rpcEnvelope de index.js; el
 * catch-all viejo devolvia 40B sin code).
 * Dual-key: las claves del payload se copian tambien a la raiz para que
 * cualquier capa del parser (info/data/root) las encuentre.
 */
export function rpcEnvelope(method, payload) {
  const data = payload && typeof payload === 'object' ? payload : {};
  const env = { code: RPC_CODE_OK, desc: 'Success', method: String(method ?? ''), info: data, data };
  return { ...env, ...data, code: RPC_CODE_OK };
}

// ---------------------------------------------------------------------------
// PAYLOADS P0 REALES (claves obligatorias del gap matrix -> parser cliente)
// Cada entrada: [defaults] -> se le superpone el eco del body.
// ---------------------------------------------------------------------------
const LIST_BASE = { results: [], list: [], total: '0', totalCount: '0' };
const OK_BASE = { success: true };

/** Map exacto: metodo canonico dotted -> defaults del payload */
export const P0_EXACT = {
  // ===== SS/Record (playback/almacenamiento) =====
  'SS.Record.QueryRecords': {
    // E-142: pageCount is STRING at the root and totalCount is INT (LIST_BASE
    // has totalCount as string; the native parser does atoi() on it).
    ...LIST_BASE, totalCount: 0, pageCount: '1', records: [], session: '', startTime: '', endTime: '', channelId: '',
    recordType: '', streamType: '', streamId: '', ssId: '', diskId: '', diskPath: '',
    planId: '', recordName: '', cardNo: '', page: '1', startIndex: '0', endIndex: '0',
    fileLength: '0', forgotten: '0', recordSource: '', optional: ''
  },
  'SS.Record.QueryLockInfos': {
    ...LIST_BASE, lockInfos: [], channelId: '', startTime: '', endTime: '', userId: '',
    userName: '', userIp: '', streamIds: [], reason: '', source: '', operateTime: '',
    optional: ''
  },
  'SS.Record.GetAlarmRecords': {
    ...LIST_BASE, records: [], channelId: '', startTime: '', endTime: '', alarmCode: '',
    recordType: '', streamType: '', streamId: '', ssId: '', diskId: '', planId: '',
    recordName: '', fileLength: '0', forgotten: '0', recordSource: '', optional: ''
  },
  'SS.Record.GetChannelMonthRecordStatus': {
    ...LIST_BASE, days: [], channelId: '', month: '', recordSource: '', optional: ''
  },
  // ===== SS/Tag (etiquetado de video) =====
  'SS.Tag.SaveRecordTag': {
    ...OK_BASE, tagId: '', subject: '', content: '', channelId: '', tagTime: '',
    beforeTagTime: '', afterTagTime: '', source: '', optional: ''
  },
  'SS.Tag.DeleteRecordTag': { ...OK_BASE, ids: [], optional: '' },
  'SS.Tag.QueryRecordTags': {
    ...LIST_BASE, tags: [], channelId: '', tagId: '', subject: '', content: '',
    startTime: '', endTime: '', tagTime: '', beforeTagTime: '', afterTagTime: '',
    keyword: '', source: '', userId: '', username: '', updateTime: '', optional: ''
  },
  // ===== DMS/Cruise (recorridas PTZ) =====
  'DMS.Cruise.GetCruises': { ...LIST_BASE, cruises: [], data: [], channelId: '', cruiseId: '', optional: '' },
  'DMS.Cruise.GetCruise': { ...LIST_BASE, cruises: [], data: [], channelId: '', cruiseId: '', optional: '' },
  'DMS.Cruise.SaveCruise': { ...OK_BASE, cruiseId: '', channelId: '' },
  'DMS.Cruise.DeleteCruise': { ...OK_BASE, cruiseId: '', channelId: '' },
  // ===== user/self/password (cambio de clave del propio usuario) =====
  'user.self.password': {
    ...OK_BASE, oldPassword: '', newPassword: '', unlockRemainTime: '0', unlockRemainTimes: '0'
  },
  'accounts.users.password': {
    ...OK_BASE, oldPassword: '', newPassword: '', unlockRemainTime: '0', unlockRemainTimes: '0'
  },
  // ===== tvwall/wall (configuracion de pantalla) =====
  'tvwall.wall': {
    ...LIST_BASE, wallScreenList: [], bigScreenList: [], alarmSourceNames: [],
    tvWallName: '', tvWallDesc: '', screenName: '', screenType: '', channelId: '',
    channelName: '', deviceCode: '', deviceName: '', deviceType: '', height: '0',
    width: '0', top: '0', left: '0', previewHeight: '0', previewWidth: '0',
    previewTop: '0', previewLeft: '0', isNewScreen: '0', parentId: '', wallId: '',
    screenId: ''
  },
  'tvwall.status': {
    ...LIST_BASE, status: '0', wallId: '', alarmSourceNames: [], tvWallName: '',
    result: '0', bResult: '0', time: '', param: ''
  },
  'tvwall.nameRepeat': { ...OK_BASE, tvWallName: '', result: '0', bResult: '0' },
  'tvwall.printDecoder': { ...OK_BASE, result: '0', bResult: '0', time: '', param: '' },
  'tvwall.del': { ...OK_BASE, wallId: '', tvWallName: '' },
  // ===== alarm/plan/template =====
  'alarm.plan.template': { ...LIST_BASE, name: '', content: '' },
  'alarm.plan.template.list': { ...LIST_BASE, name: '', content: '' },
  'alarm.plan.template.add': { ...OK_BASE, name: '', content: '' },
  'alarm.plan.template.update': { ...OK_BASE, name: '', content: '' },
  'alarm.plan.template.delete': { ...OK_BASE, name: '', content: '' },
  // ===== alarm/plan/alarm-type =====
  'alarm.plan.alarm-type.pos': {
    ...LIST_BASE, pricePeriods: [], alarmTypeId: '', alarmTypeName: '',
    minAmount: '0', maxAmount: '0', icon: '', mode: ''
  },
  'alarm.plan.alarm-type.transparence': {
    ...LIST_BASE, alarmTypeCode: '', alarmStatus: '0', alarmTypeName: '',
    subscribePicture: '0', siaSupportMode: '0', sourceTypeId: ''
  },
  // ===== account/favorite =====
  'account.favorite.channel': {
    ...LIST_BASE, channels: [], channelId: '', channelName: '', channelType: '',
    channelSubtype: '', cameraType: '', orgCode: '', sourceOrgCode: '',
    targetOrgCode: '', siteIp: '', siteName: ''
  },
  'account.favorite.organization': {
    ...LIST_BASE, channels: [], orgCodes: [], orgCode: '', orgName: '',
    parentOrgCode: '', sourceOrgCode: '', targetOrgCode: '', siteIp: '', siteName: '',
    channelId: '', channelName: '', channelType: '', channelSubtype: '', cameraType: ''
  },
  'account.favorite.organization.share': {
    ...OK_BASE, failedInfo: [], failedReason: '', orgCode: '', shareOrgCode: '',
    sharedUserIds: [], username: ''
  },
  'account.favorite.organization.share.ack': {
    ...OK_BASE, failedInfo: [], failedReason: '', orgCode: '', shareOrgCode: '',
    sharedUserIds: [], username: ''
  },
  // ===== map/radar =====
  'map.radar': {
    ...LIST_BASE, results: [], channelId: '', deviceCode: '', deviceName: '',
    deviceIp: '', devicePort: '0', orgCode: ''
  },
  // ===== server/video/list =====
  'server.video.list': { ...LIST_BASE, servers: [], serverCode: '', serverName: '', locale: '', uiBufLen: '0' },
  // ===== realmonitor/snapshot =====
  'realmonitor.snapshot': { channelId: '', content: '', rtsp: '', time: '', optional: '' },
  // ===== BRM/Config/GetEmapInfo =====
  'BRM.Config.GetEmapInfo': { ...LIST_BASE, emapInfo: {}, addr: '', enable: '0', maps: [], optional: '' },
  // ===== BRM/Linked/GetLinkedChannels =====
  'BRM.Linked.GetLinkedChannels': {
    ...LIST_BASE, channels: [], srcChannelId: '', dstChannelIds: [], location: '',
    mainList: [], mainType: '0', subList: [], linkedChannels: [], optional: ''
  },
  // ===== BRM/TvWall tareas =====
  'BRM.TvWall.SaveUserTvWallTask': {
    ...OK_BASE, pTaskInfo: {}, pTaskBaseInfo: {}, pTaskXmlData: '', data: {},
    tvWallId: '', taskId: '', taskName: '', taskDesc: '', optional: ''
  },
  'BRM.TvWall.DeleteUserTvWallTask': {
    ...OK_BASE, pTaskInfo: {}, pTaskBaseInfo: {}, pTaskXmlData: '', data: {},
    tvWallId: '', taskId: '', taskName: '', taskDesc: '', optional: ''
  },
  // ===== BRM/User =====
  'BRM.User.GetRightUsers': {
    ...LIST_BASE, users: [], pUserList: [], resourceId: '', pResourceId: '', fileName: '', optional: ''
  },
  'BRM.User.DeleteUserData': {
    ...OK_BASE, resourceId: '', pResourceId: '', users: [], pUserList: [], fileName: '', optional: ''
  },
  // ===== BRM/Device =====
  'BRM.Device.GetLocalLogs': {
    ...LIST_BASE, pSession: '', pParam: '', deviceCode: '', startTime: '', endTime: '',
    session: '', optional: ''
  },
  'BRM.Device.GetMediaVKs': {
    ...LIST_BASE, vks: [], vkId: '', vkValue: '', algorithm: 'MD5', createDate: '',
    startDate: '', endDate: ''
  },
  // ===== BRM/Mail =====
  'BRM.Mail.SendMessage': {
    ...OK_BASE, recipient: [], ccRecipient: [], bccRecipient: [], subject: '',
    message: '', attachmentPaths: [], name: ''
  },
  // ===== BRM/Heatmap =====
  'BRM.Heatmap.GetHeatmap': {
    ...LIST_BASE, records: [], deviceCode: '', channelId: '', startTime: '', endTime: '',
    heatmapType: '0', width: '0', height: '0', average: '0', picData: '', picDataLen: '0',
    binData: '', binDataLen: '0', token: '', unitSeq: '0', channelSeq: '0', total: '0'
  },
  'BRM.Heatmap.GetHeatmapPreciseAnalysis': {
    ...LIST_BASE, records: [], deviceCode: '', channelId: '', startTime: '', endTime: '',
    heatmapType: '0', width: '0', height: '0', average: '0', picData: '', picDataLen: '0',
    binData: '', binDataLen: '0', token: '', unitSeq: '0', channelSeq: '0', total: '0'
  },
  // ===== BRM/Alarm (lectura; HandleAlarm -> E-136-B) =====
  'BRM.Alarm.GetAlarmProcedures': {
    ...LIST_BASE, procedures: [], pAlarmProcessInfoList: [], pAlarmCode: '', alarmCode: '',
    handleUser: '', handleMessage: '', handleStatus: '0', handleDate: '', optional: ''
  },
  'BRM.Alarm.GetAlarmAccessRecordInfo': {
    ...LIST_BASE, bindChannels: [], linkChannels: [], cardNum: '', idNum: '', personId: '',
    gender: '', tel: '', orgCode: '', orgName: '', roomId: '', unitId: '', departmentName: '',
    faceImageUrl: '', captureImageUrl: '', antiPassType: '0', alarmCode: '', alarmDate: '',
    alarmTime: '', operateType: '0', operateInfo: '', optional: ''
  },
  // ===== BRMS/Config (correo) =====
  'BRMS.Config.GetMailConfig': {
    ...LIST_BASE, smtpServer: '', smtpPort: '0', sender: '', receiver: '', password: '',
    encrypType: '0', enable: '0', receivers: [], title: '', content: '', attachments: [],
    fileName: '', fileData: ''
  },
  'BRMS.Config.UpdateMailConfig': {
    ...OK_BASE, smtpServer: '', smtpPort: '0', sender: '', receiver: '', password: '',
    encrypType: '0', enable: '0', receivers: [], title: '', content: '', attachments: [],
    fileName: '', fileData: ''
  },
  'BRMS.Config.SendMail': {
    ...OK_BASE, smtpServer: '', smtpPort: '0', sender: '', receiver: '', receivers: [],
    password: '', encrypType: '0', enable: '0', title: '', content: '', attachments: [],
    fileName: '', fileData: ''
  },
  'BRMS.Config.TestMailConfig': {
    ...OK_BASE, smtpServer: '', smtpPort: '0', sender: '', receiver: '', receivers: [],
    password: '', encrypType: '0', enable: '0', title: '', content: '', attachments: []
  },
  // ===== BRMS/Map =====
  'BRMS.Map.GetRadarBindCameras': { ...LIST_BASE, channelId: '', channels: [], results: [] },
  // ===== BRMS/Device (paginado) =====
  'BRMS.Device.GetPageDevices': {
    ...LIST_BASE, page: '1', pageSize: '20', keyword: '', orgCode: '', deviceType: '', status: ''
  }
};
// ---------------------------------------------------------------------------
// REGLAS POR PREFIJO (grupos del gap matrix)
// ---------------------------------------------------------------------------
/** alarm/plan/source/* -> 60+ campos + 13 link* (fila 19 de la matriz) */
export const ALARM_PLAN_SOURCE_KEYS = [
  'sourceId', 'sourceCode', 'sourceName', 'alarmTypeId', 'channels', 'channelIds',
  'users', 'recipients', 'emailAddress', 'enableVideo', 'enableRecord', 'duration',
  'prerecordTime', 'status', 'level', 'action', 'method', 'model', 'target', 'url',
  'wallId', 'windowId', 'streamType', 'fileIds', 'content', 'mailTemplateId',
  'vacationTemplateId', 'timeTemplateId', 'planTemplateId', 'ignoreTime',
  'executeMode', 'seq',
  'linkAccess', 'linkAudio', 'linkAudioLight', 'linkGate', 'linkMail', 'linkOutput',
  'linkPtz', 'linkQuickCommand', 'linkRecord', 'linkSnapshot', 'linkUser',
  'linkVoicePrompt', 'linkWall'
];

const ALARM_PLAN_SOURCE_DEFAULTS = (() => {
  const p = { channels: [], channelIds: [], users: [], recipients: [], fileIds: [], ignoreTime: [] };
  for (const k of ALARM_PLAN_SOURCE_KEYS) {
    if (k in p) continue;
    p[k] = /^(?:enableVideo|enableRecord|duration|prerecordTime|status|level|seq|streamType|alarmTypeId)$/.test(k) ? '0' : '';
  }
  return p;
})();

/** BRMS.Storage.* (30 metodos) - filas 45 */
const STORAGE_KEYS = [
  'serverCode', 'paths', 'path', 'diskType', 'diskUuid', 'raidId', 'raidPath',
  'hotStandbyType', 'mode', 'username', 'password', 'groupName',
  'bindingDiskUuids', 'bindingChannelIds'
];
const STORAGE_LIST_EXTRA = {
  GetLocalDisks: { localDisks: [], disks: [] },
  GetNetDisks: { netDisks: [] },
  GetDiskGroups: { diskGroups: [] },
  GetDiskGroup: { diskGroup: {} },
  GetRaidDetail: { raid: {}, raidInfo: {} },
  GetRaidTypes: { raidTypes: [] },
  GetLocalDiskTypes: { diskTypes: [] },
  GetNetDiskTypes: { diskTypes: [] },
  GetUnboundDisks: { disks: [] },
  GetAvailableRaidDisks: { disks: [] },
  GetDiskStatistics: { statistics: [] }
};

/** BRMS.Favorite.* (9-12 metodos) - fila 46 */
const FAVORITE_KEYS = [
  'orgCode', 'orgName', 'parentOrgCode', 'sourceOrgCode', 'targetOrgCode',
  'sharedUserIds', 'sharedOrgCode', 'channelId', 'channelName', 'channelType',
  'channelSubtype', 'cameraType', 'siteIp', 'siteName', 'channels', 'orgCodes'
];

/** BRMS.Monitor.* (12-16 metodos) - fila 47 */
const MONITOR_KEYS = [
  'viewCode', 'viewName', 'viewDirCode', 'viewDirName', 'viewType', 'griddingEnable',
  'griddingRows', 'griddingCols', 'griddingCombine', 'windowData', 'windowLayout',
  'windowTotal', 'windowNo', 'windowFromX', 'windowFromY', 'windowToX', 'windowToY',
  'griddingIndex', 'customSplit', 'resourceCode', 'resourceName', 'resourceType',
  'alarmWindow', 'streamType', 'siteIp', 'roleIds', 'sharedUserId', 'shareViewCode',
  'remark'
];

/** BRM.App.* - fila 30 */
const APP_KEYS = [
  'userId', 'userName', 'personName', 'personId', 'sip', 'status', 'keyword',
  'pageNo', 'pageSize', 'totalCount', 'appUsers', 'searchInfo', 'houseHolder',
  'lastLoginDate', 'lastUpdatePasswordDate', 'password', 'userIds'
];

/** BRM.Alarm.GetAlarmCar* - fila 28 */
const CAR_KEYS = [
  'carNum', 'carColor', 'carType', 'carImgUrl', 'blacklistType', 'carWayCode',
  'peccancyType', 'carSpeed', 'personId', 'personName', 'similarity', 'nationality',
  'birthday', 'repositoryName', 'detectionImageUrl', 'faceImageUrl', 'captureImageUrl'
];

/** BRM.Alarm.GetAlarmFace* - rostro */
const FACE_KEYS = [
  'personId', 'personName', 'similarity', 'nationality', 'birthday', 'repositoryName',
  'detectionImageUrl', 'faceImageUrl', 'captureImageUrl', 'groupId', 'repositoryId'
];

function defaultsFrom(keys, list = true, arr = {}) {
  const p = list ? { ...LIST_BASE } : { ...OK_BASE };
  for (const k of keys) {
    if (k in p) continue;
    p[k] = k in arr ? arr[k] : (/(?:Enable|Rows|Cols|Total|No|Index|Type|Code|Status)$/.test(k) ? '0' : '');
  }
  return p;
}

/** Reglas por prefijo, evaluadas en orden (la primera que casa gana) */
export const P0_PREFIX_RULES = [
  {
    id: 'BRMS.Storage',
    match: (c) => c.startsWith('BRMS.Storage.'),
    build: (c) => {
      const leaf = c.split('.').pop();
      const p = defaultsFrom(STORAGE_KEYS, familyOf(c) === 'list');
      p.paths = [];
      p.bindingDiskUuids = [];
      p.bindingChannelIds = [];
      p.diskUuid = '';
      if (STORAGE_LIST_EXTRA[leaf]) Object.assign(p, STORAGE_LIST_EXTRA[leaf]);
      if (familyOf(c) === 'write' || familyOf(c) === 'del') p.success = true;
      return p;
    }
  },
  {
    id: 'BRMS.Favorite',
    match: (c) => c.startsWith('BRMS.Favorite.'),
    build: (c) => {
      const p = defaultsFrom(FAVORITE_KEYS, familyOf(c) === 'list');
      p.channels = [];
      p.orgCodes = [];
      p.sharedUserIds = [];
      p.sharedOrgCode = '';
      if (familyOf(c) === 'write' || familyOf(c) === 'del') p.success = true;
      return p;
    }
  },
  {
    id: 'BRMS.Monitor',
    match: (c) => c.startsWith('BRMS.Monitor.'),
    build: (c) => {
      const p = defaultsFrom(MONITOR_KEYS, familyOf(c) === 'list');
      p.windowLayout = [];
      p.windowData = [];
      p.roleIds = [];
      p.griddingRows = '0';
      p.griddingCols = '0';
      p.windowTotal = '0';
      if (familyOf(c) === 'write' || familyOf(c) === 'del') p.success = true;
      return p;
    }
  },
  {
    id: 'BRM.App',
    match: (c) => c.startsWith('BRM.App.'),
    build: (c) => {
      const p = defaultsFrom(APP_KEYS, familyOf(c) === 'list');
      p.appUsers = [];
      p.userIds = [];
      p.pageNo = '1';
      p.pageSize = '20';
      p.totalCount = '0';
      if (familyOf(c) === 'write' || familyOf(c) === 'del') p.success = true;
      return p;
    }
  },
  {
    id: 'BRM.Alarm.GetAlarmCar',
    match: (c) => /^BRM\.Alarm\.GetAlarmCar/.test(c),
    build: () => {
      const p = defaultsFrom(CAR_KEYS, true);
      p.personId = '';
      p.personName = '';
      p.similarity = '0';
      return p;
    }
  },
  {
    id: 'BRM.Alarm.GetAlarmFace',
    match: (c) => /^BRM\.Alarm\.GetAlarmFace/.test(c),
    build: () => {
      const p = defaultsFrom(FACE_KEYS, true);
      p.similarity = '0';
      return p;
    }
  },
  {
    id: 'alarm.plan.source',
    match: (c) => c.startsWith('alarm.plan.source'),
    build: () => ({ ...OK_BASE, ...ALARM_PLAN_SOURCE_DEFAULTS })
  },
  {
    id: 'alarm.plan.alarm-type',
    match: (c) => c.startsWith('alarm.plan.alarm-type'),
    build: (c) => {
      if (/transparence/.test(c)) {
        return {
          ...LIST_BASE, alarmTypeCode: '', alarmStatus: '0', alarmTypeName: '',
          subscribePicture: '0', siaSupportMode: '0', sourceTypeId: ''
        };
      }
      return {
        ...LIST_BASE, pricePeriods: [], alarmTypeId: '', alarmTypeName: '',
        minAmount: '0', maxAmount: '0', icon: '', mode: ''
      };
    }
  },
  {
    id: 'tvwall.wall',
    match: (c) => c.startsWith('tvwall.wall'),
    build: () => ({ ...P0_EXACT['tvwall.wall'] })
  },
  {
    id: 'account.favorite',
    match: (c) => c.startsWith('account.favorite'),
    build: (c) => {
      if (/organization\.share/.test(c)) {
        return { ...OK_BASE, failedInfo: [], failedReason: '', orgCode: '', shareOrgCode: '', sharedUserIds: [], username: '' };
      }
      if (/organization/.test(c)) return { ...P0_EXACT['account.favorite.organization'] };
      return { ...P0_EXACT['account.favorite.channel'] };
    }
  },
  {
    id: 'server.video.list',
    match: (c) => c.startsWith('server.video.list'),
    build: () => ({ ...P0_EXACT['server.video.list'] })
  },
  {
    id: 'realmonitor.snapshot',
    match: (c) => c.startsWith('realmonitor.snapshot'),
    build: () => ({ ...P0_EXACT['realmonitor.snapshot'] })
  },
  {
    id: 'map.radar',
    match: (c) => c.startsWith('map.radar'),
    build: () => ({ ...P0_EXACT['map.radar'] })
  },
  {
    id: 'user.self.password',
    match: (c) => /^(?:user\.self\.password|accounts\.users\.password)/.test(c),
    build: () => ({ ...P0_EXACT['user.self.password'] })
  }
];
// ---------------------------------------------------------------------------
// MOTOR: resolucion de metodo + payload
// ---------------------------------------------------------------------------
/**
 * Candidatos de nombre de metodo para un camino de URL.
 * Prioriza el alias de la raiz (arms -> arms.label.addLabel @0xc74a90),
 * luego la forma dotted (SS.Record.QueryRecords) y la slashed.
 */
export function methodCandidates(segments, alias = '') {
  const segs = (Array.isArray(segments) ? segments : []).map((s) => String(s ?? '').trim()).filter(Boolean);
  const dotted = segs.join('.');
  const slashed = segs.join('/');
  const out = [];
  const push = (v) => { if (v && !out.includes(v)) out.push(v); };
  if (alias) {
    if (segs.length > 1) push(`${alias}.${segs.slice(1).join('.')}`);
    push(`${alias}.${dotted}`);
  }
  push(dotted);
  push(slashed);
  if (segs.length > 1) push(segs.slice(1).join('.'));
  return out;
}

/** Devuelve el primer candidato que existe en el catalogo; si ninguno, el dotted. */
export function resolveKnown(segments, alias = '') {
  const cands = methodCandidates(segments, alias);
  for (const c of cands) if (catalogKnown(c)) return c;
  return cands.find((c) => c.includes('.')) || cands[0] || '';
}

/** Defaults P0 (exactos o por prefijo) de un metodo canonico; null si no aplica. */
export function p0Defaults(canonical) {
  const c = canonicalMethod(canonical);
  if (!c) return null;
  if (P0_EXACT[c]) return { ...P0_EXACT[c] };
  for (const rule of P0_PREFIX_RULES) {
    if (rule.match(c)) return { ...rule.build(c) };
  }
  return null;
}

/** true si el metodo tiene payload P0 propio */
export function isP0(method) {
  return p0Defaults(method) !== null;
}

/**
 * Payload final de un metodo:
 *   1) P0 real (claves obligatorias del gap matrix) + eco del body
 *   2) familia heuristica (Get/Query/List/Page | Add/Update/Save/Create | Delete/Batch)
 *   3) {} -> pero SIEMPRE envuelto en envelope code 0 (nunca 40B)
 */
export function buildRpcPayload(method, body) {
  const canon = canonicalMethod(method);
  const p0 = p0Defaults(canon);
  if (p0) {
    const merged = echoBody(body, p0);
    merged.code = RPC_CODE_OK;
    return merged;
  }
  const fam = familyPayload(canon || method, body);
  fam.code = RPC_CODE_OK;
  return fam;
}

/** Envelope completo (code 0 + info/data + claves de familia en la raiz). */
export function buildRpcEnvelope(method, body) {
  return rpcEnvelope(method, buildRpcPayload(method, body));
}

/**
 * Resuelve el metodo de una peticion RPC: body.method gana (FUN_18066e570),
 * si no se deduce de los parametros de ruta.
 */
export function resolveRequestMethod(req, alias = '') {
  const b = (req && req.body) || {};
  if (b.method && String(b.method).trim()) return canonicalMethod(b.method);
  const p = (req && req.params) || {};
  const segs = [p.sub, p.cls, p.fn].filter((x) => x !== undefined && x !== null && x !== '');
  if (segs.length) return resolveKnown(segs, alias);
  const url = String((req && req.url) || '');
  const parts = url.split('/').filter(Boolean);
  if (parts.length) return resolveKnown(parts.slice(-3), alias);
  return '';
}

/** Handler RPC generico: SIEMPRE responde envelope code 0. */
export async function handleRpcRequest(req, alias = '') {
  const method = resolveRequestMethod(req, alias);
  const payload = buildRpcPayload(method, requestBody(req));
  return rpcEnvelope(method, payload);
}

// ---------------------------------------------------------------------------
// REGISTRO EN FASTIFY
// ---------------------------------------------------------------------------
/** Rutas RPC que el motor registra (las duplicadas con index.js se saltan). */
export const RPC_ROUTES = [
  '/admin/API/BRMS/:ns/:fn', '/admin/api/BRMS/:ns/:fn',
  '/admin/API/BRMS/:ns/:cls/:fn', '/admin/api/BRMS/:ns/:cls/:fn',
  '/brms/api/BRMS/:ns/:fn', '/brms/api/BRMS/:ns/:cls/:fn',
  '/brms/api/v1.0/BRMS/:ns/:fn', '/brms/api/v1.0/BRMS/:ns/:cls/:fn',
  '/brms/api/v1.1/BRMS/:ns/:fn', '/brms/api/v1.1/BRMS/:ns/:cls/:fn'
];

/**
 * register(app, ctx)
 *  - registra las rutas RPC BRMS (familia de 520 metodos del catalogo) que
 *    index.js NO cubre;
 *  - deja el motor accesible en ctx.e135 (para que el supervisor lo enganche
 *    al brmRpcHandler existente sin editarlo aqui).
 */
export function register(app, ctx = {}) {
  let added = 0;
  let skipped = 0;
  for (const url of RPC_ROUTES) {
    for (const verb of ['get', 'post']) {
      try {
        app[verb](url, async (req) => handleRpcRequest(req, 'BRMS'));
        added++;
      } catch {
        skipped++;
      }
    }
  }
  if (ctx && typeof ctx === 'object') {
    ctx.e135 = {
      handleRpcRequest,
      buildRpcPayload,
      buildRpcEnvelope,
      catalogKnown,
      familyPayload,
      rpcEnvelope,
      resolveRequestMethod,
      isP0,
      p0Defaults
    };
    if (typeof ctx.e135RpcHandler !== 'function') ctx.e135RpcHandler = (req) => handleRpcRequest(req);
  }
  console.log(`[E135-RPC] routes registered=${added} skipped(dup)=${skipped} catalog=${RPC_METHODS.size} methods`);
  return { added, skipped, methods: RPC_METHODS.size };
}

export default { register, catalogKnown, familyPayload, rpcEnvelope, buildRpcPayload, handleRpcRequest };