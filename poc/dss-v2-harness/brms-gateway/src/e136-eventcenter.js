// ===== E-136: backend del Event Center (RPC BRMS.* + REST pull-queue) ========
//
// Que resuelve: el Event Center del cliente DSS 8.006 (WINPC_V2) es un
// BACKEND, no un stub. La matriz de gaps (rea-gap-client.md filas 25/37/38/
// 39/40/41/42/43/44/50/51 y TOP20 #13-#20) lista exactamente lo que falta:
//
//   BRM/Alarm/HandleAlarm            -> handleStatus/comment/mailReceivers[]
//   BRMS.Alarm.BatchHandleAlarms     -> alarms[] + 8 campos por alarma
//   BRMS.Alarm.GetPageAlarmRecords   -> paginado + 16 filtros
//   BRMS.Alarm.ExportAlarmRecords    -> customColumns[]/exportType
//   BRMS.Alarm.DisarmAlarm           -> duration/unit/abortTime
//   BRMS.AlarmPlan.Add|Update        -> 62 campos + 13 link*
//   BRMS.AlarmPlan.GetPage|BatchDelete
//   BRMS.User.GetPage|Add|Update|Delete
//   BRMS.Role.GetPage|Add|Update|Delete
//   BRMS.Account.ChangePassword
//   BRMS.AlarmOverview.GetSummary
//   Rights/Nodes                      -> menuNodes[]/functionNodes[]
//   alarmBusiness/pendAlarmList|alarmList|exportAlarmList
//   eventCenter/messages/subscribe   -> pull-queue real
//
// MECANISMO DE INTEGRACION (sin tocar index.js): un hook `preHandler` de
// Fastify. Fastify 4.29.1 engancha los hooks de instancia a las rutas YA
// registradas (verificado con sonda: `app.addHook('preHandler')` DESPUES de
// `app.post(...)` se ejecuta y `reply.send()` cortocircuita el handler de la
// ruta). Por eso E-136 puede SOBRESCRIBIR los stubs de index.js/e127
// (catch-all RPC de index.js:1111 y la lista P0 de e127) sin editar un solo
// fichero existente: el hook se adelanta al handler y devuelve el envelope.
//
// Contrato de transporte:
//   - RPC  -> {code:1000, desc:'Success', method, info, data} (mismo
//             rpcEnvelope de index.js:897)
//   - REST -> {code:1000, desc:'Success', data} (mismo envelope de index.js:537)
import path from 'node:path';
import {
  createAlarmStore, normalizeAlarm, str, toArray, DATA_DIR
} from './e136-alarm-store.js';
import {
  createAlarmPlanStore, createUserStore, createRoleStore,
  ALARM_PLAN_FIELDS, ALARM_PLAN_LINK_FIELDS
} from './e136-admin-store.js';

// ---------------------------------------------------------------------------
// helpers de contrato
// ---------------------------------------------------------------------------
/** Envelope RPC identico al rpcEnvelope de index.js:897. */
export function rpcEnvelope(method, data = {}) {
  return { code: 1000, desc: 'Success', method: String(method ?? ''), info: data, data };
}

/** Envelope REST identico al envelope de index.js:537. */
export function defaultEnvelope(data = {}, code = 1000, desc = 'Success') {
  return { code, desc, data };
}

/** Extrae el bloque util de un body RPC {method, data:{...}}. */
export function bodyData(body) {
  if (!body || typeof body !== 'object') return {};
  if (body.data && typeof body.data === 'object' && !Array.isArray(body.data)) return body.data;
  if (body.info && typeof body.info === 'object' && !Array.isArray(body.info)) return body.info;
  return body;
}

/**
 * Clave canonica de un metodo RPC: quita versionado, slashes y hasta dos
 * prefijos BRM./BRMS. -> "Alarm.GetPageAlarmRecords".
 * Asi el mismo handler sirve para:
 *   POST /admin/API/BRM/BRMS/Alarm/GetPageAlarmRecords
 *   POST /admin/API/BRM/Alarm/GetPageAlarmRecords
 *   body.method = "BRMS.Alarm.GetPageAlarmRecords"
 */
export function canonicalRpcKey(method) {
  let m = str(method).trim().replace(/^\/+/, '');
  if (!m) return '';
  m = m.replace(/^v\d+\.\d+\//i, '').replace(/\//g, '.');
  for (let i = 0; i < 2; i++) {
    const n = m.replace(/^BRMS?\./i, '');
    if (n === m) break;
    m = n;
  }
  return m;
}

/** Eco de los campos de entrada que el cliente espera ver devueltos. */
export function echo(data, keys) {
  const out = {};
  for (const k of keys) {
    if (data && Object.prototype.hasOwnProperty.call(data, k)) out[k] = data[k];
  }
  return out;
}

// ---------------------------------------------------------------------------
// PULL-QUEUE del Event Center
// ---------------------------------------------------------------------------
/**
 * Cola de mensajes del pull-queue. El cliente abre la cola con
 * `initMessageId` y va pasando el `msgId` recibido; cada respuesta devuelve
 * los mensajes nuevos + el `msgId`/`next` siguiente.
 */
export function createEventCenterQueue({ limit = 500 } = {}) {
  let seq = 0;
  const pending = [];
  function push(message) {
    seq += 1;
    const rec = { id: String(seq), seq, message, timestamp: new Date().toISOString() };
    pending.push(rec);
    while (pending.length > limit) pending.shift();
    return rec;
  }
  function pull(sinceId = '0') {
    const from = parseInt(sinceId, 10) || 0;
    const out = pending.filter((r) => r.seq > from).map((r) => r.message);
    return { messages: out, msgId: String(seq), next: String(seq), count: out.length };
  }
  return {
    push,
    pull,
    latestId: () => String(seq),
    clear: () => { pending.length = 0; },
    size: () => pending.length
  };
}

/**
 * ACK de suscripcion del pull-queue. Mantiene msgId + subscribeId (contrato
 * del cliente, fila E-118 de brms.test.js) y anade messages/next.
 */
export function buildEventCenterSubscribePayload(queue, body = {}) {
  const b = body && typeof body === 'object' ? body : {};
  const initMessageId = str(b.initMessageId ?? b.msgId ?? '0');
  const pulled = queue.pull(initMessageId);
  // E-142 P0 (rea-flows-v3 §1): data.results must be ARRAY-OF-STRING and
  // data must carry totalCount INT + nextMsgId STRING or the native cursor
  // becomes -1 and the alarm polling loop stalls.
  const results = pulled.messages.map((m) => (typeof m === 'string' ? m : JSON.stringify(m)));
  return {
    totalCount: pulled.count,
    results,
    nextMsgId: pulled.next,
    msgId: pulled.msgId,
    next: pulled.next,
    count: pulled.count,
    subscribeId: `sub-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`,
    subscribeAddress: str(b.subscribeAddress),
    subscribeAddrType: str(b.subscribeAddrType ?? b.AddrType ?? 'http'),
    subscribeUser: str(b.subscribeUser ?? b.User ?? ''),
    subscribePassword: str(b.subscribePassword ?? b.Password ?? ''),
    initMessageId: String(initMessageId),
    interval: '1000',
    status: '1',
    success: true,
    messages: pulled.messages,
    list: pulled.messages,
    items: pulled.messages
  };
}

// ---------------------------------------------------------------------------
// Rights/Nodes (fila 24 de la matriz)
// ---------------------------------------------------------------------------
// Codigos de menu reales observados en el seed del servidor DSS (index.js
// E-035: 158 codigos cosechados del leveldb) y codigos de funcion del
// Super Administrator (FunctionType enum: 1 record, 2 ptz, 3 talk, 5 lock,
// 6 tips, 8 liveView, 9 playback, 10 download, 11 privacyMasking).
export const DSS_FUNCTION_CODES = [
  '1', '2', '3', '5', '6', '8', '9', '10', '11'
];

export const DSS_MENU_NODES = [
  { menuId: '001', menuName: 'Monitor Center', parentId: '0', url: '', menuType: '1', function: '' },
  { menuId: '002', menuName: 'Management', parentId: '0', url: '', menuType: '1', function: '' },
  { menuId: '002001', menuName: 'Device Manager', parentId: '002', url: '', menuType: '1', function: '' },
  { menuId: '002005', menuName: 'Alarm Management', parentId: '002', url: '', menuType: '1', function: '' },
  { menuId: '002005004', menuName: 'Alarm Plan', parentId: '002005', url: '', menuType: '1', function: '' },
  { menuId: '002007', menuName: 'User Management', parentId: '002', url: '', menuType: '1', function: '' },
  { menuId: '002007002', menuName: 'User', parentId: '002007', url: '', menuType: '1', function: '' },
  { menuId: '002007003', menuName: 'Role', parentId: '002007', url: '', menuType: '1', function: '' },
  { menuId: '002007004', menuName: 'Organization', parentId: '002007', url: '', menuType: '1', function: '' },
  { menuId: '003', menuName: 'Storage', parentId: '0', url: '', menuType: '1', function: '' },
  { menuId: '003001002', menuName: 'Record Plan', parentId: '003001', url: '', menuType: '1', function: '' },
  { menuId: '004', menuName: 'System', parentId: '0', url: '', menuType: '1', function: '' },
  { menuId: '004002003', menuName: 'Network', parentId: '004002', url: '', menuType: '1', function: '' },
  { menuId: '004003002', menuName: 'Time', parentId: '004003', url: '', menuType: '1', function: '' },
  { menuId: '004004004', menuName: 'Maintenance', parentId: '004004', url: '', menuType: '1', function: '' },
  { menuId: '004004005', menuName: 'Backup', parentId: '004004', url: '', menuType: '1', function: '' }
];

/** Payload de Rights/Nodes: pUserRightList/function/menuId/menuNodes/functionNodes. */
export function buildRightsNodesPayload(body = {}) {
  const b = body && typeof body === 'object' ? body : {};
  const menuId = str(b.menuId ?? '001');
  const menuNodes = DSS_MENU_NODES.map((n) => ({ ...n }));
  const functionNodes = DSS_FUNCTION_CODES.map((f) => ({ function: f, functionCode: f, functionName: f, enabled: '1' }));
  const pUserRightList = menuNodes.map((n) => ({
    menuId: n.menuId, menuName: n.menuName, parentId: n.parentId,
    function: '', functionCodes: DSS_FUNCTION_CODES.slice(), enabled: '1'
  }));
  return {
    pUserRightList,
    function: DSS_FUNCTION_CODES.slice(),
    functions: DSS_FUNCTION_CODES.slice(),
    functionCodes: DSS_FUNCTION_CODES.slice(),
    menuId,
    menuNodes,
    functionNodes,
    list: menuNodes, results: menuNodes, items: menuNodes,
    total: menuNodes.length, totalCount: menuNodes.length
  };
}

// ---------------------------------------------------------------------------
// HANDLERS RPC
// ---------------------------------------------------------------------------
/** Cada handler recibe (stores, body, rawMethod) y devuelve el payload `data`. */
export const RPC_HANDLERS = {
  // --- BRMS.Alarm.* -------------------------------------------------------
  'Alarm.GetPageAlarmRecords': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page(d);
    return {
      ...page,
      ...echo(d, ['page', 'pageSize', 'currentPage', 'splitId', 'splitTime',
        'startAlarmTime', 'endAlarmTime', 'alarmTypes', 'alarmGrade',
        'handleStatus', 'handleUser', 'handleMessage', 'deviceCodes',
        'channelIds', 'orderType', 'orderDirection'])
    };
  },

  'Alarm.ExportAlarmRecords': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page(d);
    const fileName = `alarm_records_${Date.now()}.xlsx`;
    return {
      success: true,
      exportType: str(d.exportType ?? '1'),
      exportRange: str(d.exportRange ?? ''),
      customColumns: toArray(d.customColumns),
      selectIds: toArray(d.selectIds),
      credence: str(d.credence ?? '0'),
      encryptPass: str(d.encryptPass ?? ''),
      siteName: str(d.siteName ?? ''),
      fileName,
      fileUrl: '',
      fileSize: '0',
      exportFileVo: { fileName, fileUrl: '', fileSize: '0' },
      records: page.records, list: page.records, results: page.records,
      total: page.total, totalCount: page.totalCount,
      ...echo(d, ['alarmTypes', 'alarmGrade', 'handleStatus', 'handleUser',
        'startAlarmTime', 'endAlarmTime', 'deviceCodes', 'channelIds',
        'orderType', 'orderDirection'])
    };
  },

  'Alarm.DisarmAlarm': (s, body) => {
    const d = bodyData(body);
    const res = s.alarms.disarm(d);
    return {
      ...res,
      ...echo(d, ['alarmTypeId', 'alarmSourceCode', 'disarmType', 'mode',
        'duration', 'unit', 'abortTime', 'remark'])
    };
  },

  'Alarm.BatchHandleAlarms': (s, body) => {
    const d = bodyData(body);
    const res = s.alarms.handle(d);
    return {
      ...res,
      ...echo(d, ['alarms', 'handleUser', 'handleMessage', 'handleStatus',
        'comment', 'deviceCode', 'alarmCode', 'alarmDate'])
    };
  },

  'Alarm.HandleAlarm': (s, body) => {
    const d = bodyData(body);
    const res = s.alarms.handle(d);
    return {
      ...res,
      ...echo(d, ['handleUser', 'handleMessage', 'mailReceivers', 'handleStatus',
        'optional', 'comment', 'deviceCode', 'alarmCode', 'alarmDate'])
    };
  },

  'Alarm.GetAlarmProcedures': (s, body) => {
    const d = bodyData(body);
    const handled = s.alarms.all()
      .filter((a) => str(a.handleStatus) === '1')
      .filter((a) => !d.alarmCode || str(a.alarmCode) === str(d.alarmCode))
      .map((a) => ({
        alarmCode: a.alarmCode, alarmDate: a.alarmDate, alarmTime: a.alarmTime,
        handleUser: a.handleUser, handleMessage: a.handleMessage,
        handleStatus: a.handleStatus, handleDate: a.handleDate,
        deviceCode: a.deviceCode, channelId: a.channelId,
        pAlarmCode: a.alarmCode, comment: a.comment
      }));
    return {
      procedures: handled, pAlarmProcessInfoList: handled,
      list: handled, results: handled, items: handled,
      total: handled.length, totalCount: handled.length,
      handleUser: str(d.handleUser ?? ''), handleMessage: str(d.handleMessage ?? ''),
      handleStatus: str(d.handleStatus ?? ''), handleDate: str(d.handleDate ?? ''),
      pAlarmCode: str(d.pAlarmCode ?? d.alarmCode ?? ''), alarmCode: str(d.alarmCode ?? ''),
      optional: str(d.optional ?? '')
    };
  },

  'AlarmOverview.GetSummary': (s, body) => {
    const d = bodyData(body);
    return { ...s.alarms.stats(d), ...echo(d, ['mode', 'orgCode', 'startTime', 'endTime']) };
  },

  // --- BRMS.AlarmPlan.* ---------------------------------------------------
  'AlarmPlan.AddAlarmPlan': (s, body) => {
    const d = bodyData(body);
    const plan = s.plans.add(d);
    return { success: true, planId: plan.planId, planCode: plan.planCode, plan, ...plan };
  },

  'AlarmPlan.UpdateAlarmPlan': (s, body) => {
    const d = bodyData(body);
    const planId = str(d.planId ?? d.id ?? d.planCode ?? '');
    const plan = s.plans.update(planId, d);
    if (!plan) {
      return { success: false, errorCode: '1', errorMsg: 'alarm plan not found', planId };
    }
    return { success: true, planId: plan.planId, planCode: plan.planCode, plan, ...plan };
  },

  'AlarmPlan.GetPageAlarmPlans': (s, body) => {
    const d = bodyData(body);
    const page = s.plans.page(d);
    return {
      ...page,
      ...echo(d, ['orgCodes', 'planName', 'alarmTypeIds', 'sourceCodes', 'page', 'pageSize', 'ids'])
    };
  },

  'AlarmPlan.BatchDeleteAlarmPlans': (s, body) => {
    const d = bodyData(body);
    const res = s.plans.batchDelete(d.ids ?? d.planIds ?? []);
    return { ...res, ...echo(d, ['ids']) };
  },

  // --- BRMS.User.* --------------------------------------------------------
  'User.GetPageUsers': (s, body) => {
    const d = bodyData(body);
    const page = s.users.page(d);
    return {
      ...page,
      ...echo(d, ['page', 'pageSize', 'keyword', 'roleIds', 'status', 'ids'])
    };
  },

  'User.AddUser': (s, body) => {
    const d = bodyData(body);
    const user = s.users.add(d);
    return { success: true, userId: user.userId, username: user.username, user, ...user };
  },

  'User.UpdateUser': (s, body) => {
    const d = bodyData(body);
    const key = str(d.userId ?? d.username ?? d.id ?? '');
    const user = s.users.update(key, d);
    if (!user) return { success: false, errorCode: '1', errorMsg: 'user not found', userId: key };
    return { success: true, userId: user.userId, username: user.username, user, ...user };
  },

  'User.DeleteUsers': (s, body) => {
    const d = bodyData(body);
    const res = s.users.remove(d.ids ?? d.userIds ?? []);
    return { ...res, ...echo(d, ['ids']) };
  },

  'User.GetRightUsers': (s, body) => {
    const d = bodyData(body);
    const users = s.users.all().map((u) => ({
      userId: u.userId, username: u.username, name: u.name, roleIds: u.roleIds,
      groupId: u.groupId, orgCode: u.orgCode, status: u.status
    }));
    return {
      users, pUserList: users, list: users, results: users, items: users,
      resourceId: str(d.resourceId ?? ''), pResourceId: str(d.pResourceId ?? d.resourceId ?? ''),
      fileName: str(d.fileName ?? ''), optional: str(d.optional ?? ''),
      total: users.length, totalCount: users.length
    };
  },

  'User.DeleteUserData': (s, body) => {
    const d = bodyData(body);
    return {
      success: true,
      resourceId: str(d.resourceId ?? ''), pResourceId: str(d.pResourceId ?? ''),
      users: [], pUserList: [], fileName: str(d.fileName ?? ''),
      optional: str(d.optional ?? '')
    };
  },

  // --- BRMS.Role.* --------------------------------------------------------
  'Role.GetPageRoles': (s, body) => {
    const d = bodyData(body);
    const page = s.roles.page(d);
    return {
      ...page,
      ...echo(d, ['roleName', 'roleType', 'orgCode', 'orgCodes', 'page', 'pageSize', 'ids'])
    };
  },

  'Role.AddRole': (s, body) => {
    const d = bodyData(body);
    const role = s.roles.add(d);
    return { success: true, roleId: role.roleId, roleName: role.roleName, role, ...role };
  },

  'Role.UpdateRole': (s, body) => {
    const d = bodyData(body);
    const key = str(d.roleId ?? d.id ?? d.roleName ?? '');
    const role = s.roles.update(key, d);
    if (!role) return { success: false, errorCode: '1', errorMsg: 'role not found', roleId: key };
    return { success: true, roleId: role.roleId, roleName: role.roleName, role, ...role };
  },

  'Role.DeleteRoles': (s, body) => {
    const d = bodyData(body);
    const res = s.roles.remove(d.ids ?? d.roleIds ?? []);
    return { ...res, ...echo(d, ['ids']) };
  },

  // --- BRMS.Account.ChangePassword ---------------------------------------
  'Account.ChangePassword': (s, body) => {
    const d = bodyData(body);
    const username = str(d.username ?? d.userName ?? '');
    const res = s.users.changePassword(username, d.newPassword, {
      oldPassword: str(d.oldPassword ?? ''),
      digestPassword: str(d.digestPassword ?? '')
    });
    return {
      ...res,
      ...echo(d, ['oldPassword', 'newPassword', 'digestPassword', 'username', 'verification']),
      unlockRemainTime: '0', unlockRemainTimes: '0'
    };
  },

  // --- Rights/Nodes (tambien llega como RPC) ------------------------------
  'Rights.Nodes': (s, body) => buildRightsNodesPayload(bodyData(body))
};

// ---------------------------------------------------------------------------
// HANDLERS REST (rutas ya registradas por index.js/e127 -> se interceptan)
// ---------------------------------------------------------------------------
export const REST_HANDLERS = {
  'eventCenter/messages/subscribe': (s, body) => buildEventCenterSubscribePayload(s.queue, body),

  'eventCenter/messages/subscribeAddress': (s, body) => {
    // E-142 (rea-flows-v3 §4, FUN_18068b720): full VSL GetMQConfig shape.
    // subscribeAddrType is INT and initMessageId is an ARRAY of
    // {msgId STRING, type INT} (type 1 = alarm, 2 = other).
    const b = bodyData(body);
    const msgId = str(b.msgId ?? b.initMessageId ?? '0') || '0';
    return {
      success: true,
      subscribeAddress: str(b.subscribeAddress ?? ''),
      publishAddress: str(b.publishAddress ?? ''),
      topic: 'brms.notify',
      subscribeTopics: [],
      subscribeUser: str(b.subscribeUser ?? b.User ?? ''),
      subscribePassword: str(b.subscribePassword ?? b.Password ?? ''),
      subscribeAddrType: Number(b.subscribeAddrType ?? b.AddrType ?? 1) || 0,
      initMessageId: [
        { msgId, type: 1 },
        { msgId, type: 2 }
      ]
    };
  },

  'alarmBusiness/pendAlarmList': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page({ ...d, handleStatus: d.handleStatus ?? '0' });
    return { ...page, alarms: page.records, dutyList: [], pending: page.records };
  },

  'alarmBusiness/alarmList': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page(d);
    return { ...page, alarms: page.records };
  },

  'alarmBusiness/processdAlarmList': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page({ ...d, handleStatus: d.handleStatus ?? '1' });
    return { ...page, alarms: page.records, processed: page.records };
  },

  'alarmBusiness/exportAlarmList': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page(d);
    const fileName = `alarm_records_${Date.now()}.xlsx`;
    return {
      success: true, fileName, fileUrl: '', fileSize: '0',
      exportFileVo: { fileName, fileUrl: '', fileSize: '0' },
      records: page.records, list: page.records, results: page.records,
      total: page.total, totalCount: page.totalCount
    };
  },

  'alarmBusiness/onfile': (s, body) => {
    const d = bodyData(body);
    const page = s.alarms.page(d);
    return { ...page, alarms: page.records };
  },

  'alarmBusiness/askForHandle': (s, body) => {
    const d = bodyData(body);
    const res = s.alarms.handle(d);
    return { ...res, handled: '1', cancel: '1' };
  },

  'alarm/handle/batch': (s, body) => {
    const d = bodyData(body);
    const res = s.alarms.handle(d);
    return { ...res, handled: '1', handledIds: res.handled, cancel: '1' };
  },

  'alarm/disarm': (s, body) => {
    const d = bodyData(body);
    return s.alarms.disarm(d);
  },

  'accounts/users/password': (s, body) => {
    const d = bodyData(body);
    const username = str(d.username ?? d.userName ?? '');
    const res = s.users.changePassword(username, d.newPassword, {
      oldPassword: str(d.oldPassword ?? ''),
      digestPassword: str(d.digestPassword ?? '')
    });
    return {
      ...res,
      ...echo(d, ['oldPassword', 'newPassword', 'digestPassword', 'username']),
      unlockRemainTime: '0', unlockRemainTimes: '0', handled: '1', cancel: '1'
    };
  },

  'account/authorize/password/change': (s, body) => {
    const d = bodyData(body);
    const username = str(d.username ?? d.userName ?? '');
    const res = s.users.changePassword(username, d.newPassword, {
      oldPassword: str(d.oldPassword ?? ''),
      digestPassword: str(d.digestPassword ?? '')
    });
    return {
      ...res,
      ...echo(d, ['oldPassword', 'newPassword', 'digestPassword', 'username', 'verification']),
      unlockRemainTime: '0', unlockRemainTimes: '0'
    };
  },

  'user/self/password': (s, body) => {
    const d = bodyData(body);
    const username = str(d.username ?? d.userName ?? 'admin');
    const res = s.users.changePassword(username, d.newPassword, {
      oldPassword: str(d.oldPassword ?? ''),
      digestPassword: str(d.digestPassword ?? '')
    });
    return {
      ...res,
      ...echo(d, ['oldPassword', 'newPassword', 'digestPassword', 'username']),
      unlockRemainTime: '0', unlockRemainTimes: '0'
    };
  },

  'Rights/Nodes': (s, body) => buildRightsNodesPayload(bodyData(body))
};

// Prefijos REST que se consideran "raiz" conocida (se recorta para comparar).
const REST_HOSTS = [
  '/brms/api/v1.1', '/brms/api/v1.0', '/brms/api', '/videoService',
  '/admin/API', '/admin/api', '/admin'
];

/**
 * Recorta la URL REST a su clave relativa.
 *   /brms/api/v1.1/alarmBusiness/alarmList -> "alarmBusiness/alarmList"
 *   /admin/API/Rights/Nodes                 -> "Rights/Nodes"
 */
export function restKey(url) {
  let u = str(url).split('?')[0].replace(/\/+$/, '');
  let rest = u;
  for (const h of REST_HOSTS) {
    if (u.toLowerCase().startsWith(h.toLowerCase())) {
      rest = u.slice(h.length);
      break;
    }
  }
  rest = rest.replace(/^\//, '').replace(/\/+$/, '');
  rest = rest.replace(/^v\d+\.\d+\//i, '');
  return rest;
}

// ---------------------------------------------------------------------------
// STORES + REGISTRO
// ---------------------------------------------------------------------------
/** Crea el juego completo de stores de E-136 (inyectables para tests). */
export function createE136Stores({ dataDir = DATA_DIR, persist = true, overrides = {} } = {}) {
  const stores = {
    alarms: createAlarmStore({ filePath: path.join(dataDir, 'alarms.json'), persist }),
    plans: createAlarmPlanStore({ filePath: path.join(dataDir, 'alarm-plans.json'), persist }),
    users: createUserStore({ filePath: path.join(dataDir, 'users.json'), persist }),
    roles: createRoleStore({ filePath: path.join(dataDir, 'roles.json'), persist }),
    queue: createEventCenterQueue()
  };
  return { ...stores, ...(overrides || {}) };
}

const INSTALLED = Symbol.for('e136.eventcenter.installed');

/**
 * register(app, ctx)
 *
 * @param {object} app    instancia Fastify
 * @param {object|Function} ctx  contexto del supervisor. Acepta:
 *        - una funcion `envelope` (mismo contrato que registerP0Coverage)
 *        - un objeto { envelope, stores, dataDir, persist }
 */
export function register(app, ctx = {}) {
  const isFn = typeof ctx === 'function';
  const obj = isFn ? {} : (ctx && typeof ctx === 'object' ? ctx : {});
  const envelope = isFn ? ctx
    : (typeof obj.envelope === 'function' ? obj.envelope : defaultEnvelope);
  const stores = obj.stores && obj.stores.alarms ? obj.stores
    : createE136Stores({ dataDir: obj.dataDir || DATA_DIR, persist: obj.persist !== false });

  if (app && app[INSTALLED]) {
    return { ...app[INSTALLED], installed: false, stores };
  }

  /** Resuelve el metodo RPC de una peticion (body.method gana). */
  function rpcMethodOf(req) {
    const b = (req && req.body) || {};
    if (b && typeof b.method === 'string' && b.method.trim()) return b.method.trim();
    const p = (req && req.params) || {};
    if (p.cls) return `BRM.${p.ns}.${p.cls}.${p.fn}`;
    if (p.ns && p.fn) return `BRM.${p.ns}.${p.fn}`;
    return '';
  }

  /** Metodos que producen un ACK/notify de alarma (flujo async #3). */
  const NOTIFY_METHODS = new Set([
    'Alarm.HandleAlarm', 'Alarm.BatchHandleAlarms', 'Alarm.DisarmAlarm'
  ]);

  /** Cortocircuita la peticion si E-136 es duena de ella. */
  async function intercept(req, reply) {
    const method = rpcMethodOf(req);
    if (method) {
      const key = canonicalRpcKey(method);
      const handler = RPC_HANDLERS[key];
      if (handler) {
        const payload = handler(stores, (req && req.body) || {}, method);
        if (NOTIFY_METHODS.has(key)) notifyAlarmFlow(key, payload);
        return reply.send(rpcEnvelope(method, payload));
      }
    }
    const key = restKey((req && req.url) || '');
    const restHandler = REST_HANDLERS[key];
    if (restHandler) {
      const body = { ...((req && req.query) || {}), ...((req && req.body) || {}) };
      const payload = restHandler(stores, body);
      if (/handle|disarm|askForHandle/i.test(key)) notifyAlarmFlow(key, payload);
      return reply.send(envelope(payload));
    }
    // Prefijos con parametro (accounts/users/password/<userName>).
    const m = str((req && req.url) || '').match(/accounts\/users\/password\/([^/?#]+)/i);
    if (m) {
      const body = { ...((req && req.query) || {}), ...((req && req.body) || {}), username: decodeURIComponent(m[1]) };
      const payload = REST_HANDLERS['accounts/users/password'](stores, body);
      return reply.send(envelope(payload));
    }
    return undefined;
  }

  /**
   * Flujo async de confirmacion: la alarma confirmada entra en la cola del
   * pull-queue del Event Center y (si el supervisor cablea un notificador)
   * se publica por WS/MQ. `handlesAlarm`/`disarmAlarm` son los metodos WS
   * que MSG.exe suscribe (mismo nombre que el RPC).
   */
  function notifyAlarmFlow(key, payload) {
    const records = Array.isArray(payload && payload.records) ? payload.records : [];
    for (const rec of records) {
      stores.queue.push(rec);
      try {
        if (typeof obj.notify === 'function') obj.notify(rec);
        else if (obj.notifyHub && typeof obj.notifyHub.alarmEvent === 'function') obj.notifyHub.alarmEvent(rec);
      } catch (err) {
        console.error('[E136-EVENTCENTER] notify failed:', err.message);
      }
    }
    try {
      if (obj.wsHub && typeof obj.wsHub.publishNotify === 'function') {
        obj.wsHub.publishNotify(key, payload);
      }
    } catch (err) {
      console.error('[E136-EVENTCENTER] ws notify failed:', err.message);
    }
    return records.length;
  }

  if (app && typeof app.addHook === 'function') {
    app.addHook('preHandler', intercept);
  }

  // Rutas NUEVAS que index.js/e127 no registran (no hay conflicto).
  let added = 0;
  let skipped = 0;
  const NEW_ROUTES = [
    ['/admin/API/Rights/Nodes', REST_HANDLERS['Rights/Nodes']],
    ['/admin/api/Rights/Nodes', REST_HANDLERS['Rights/Nodes']],
    ['/brms/api/v1.1/Rights/Nodes', REST_HANDLERS['Rights/Nodes']],
    ['/brms/api/v1.0/Rights/Nodes', REST_HANDLERS['Rights/Nodes']],
    ['/brms/api/v1.1/user/self/password', REST_HANDLERS['user/self/password']],
    ['/brms/api/v1.0/user/self/password', REST_HANDLERS['user/self/password']],
    ['/admin/API/user/self/password', REST_HANDLERS['user/self/password']]
  ];
  for (const [url, handler] of NEW_ROUTES) {
    for (const verb of ['get', 'post']) {
      try {
        app[verb](url, async (req) => envelope(handler(stores, { ...(req.query || {}), ...(req.body || {}) })));
        added++;
      } catch {
        skipped++;
      }
    }
  }

  const api = {
    stores,
    envelope,
    rpcEnvelope,
    intercept,
    RPC_HANDLERS,
    REST_HANDLERS,
    createE136Stores,
    buildEventCenterSubscribePayload,
    buildRightsNodesPayload,
    /** Publica una alarma en la cola del pull-queue y devuelve el envelope. */
    publishAlarm(alarm) {
      const rec = stores.alarms.add(alarm);
      const native = normalizeAlarm(rec);
      stores.queue.push(native);
      return rec;
    },
    added,
    skipped
  };
  if (app) app[INSTALLED] = api;
  if (obj && typeof obj === 'object') {
    obj.e136 = { ...(obj.e136 || {}), stores, eventCenter: api };
    if (!obj.e136Stores) obj.e136Stores = stores;
  }
  console.log(`[E136-EVENTCENTER] rpc=${Object.keys(RPC_HANDLERS).length} rest=${Object.keys(REST_HANDLERS).length} routes added=${added} skipped(dup)=${skipped}`);
  return { ...api, installed: true };
}

export default {
  register, createE136Stores, createEventCenterQueue,
  buildEventCenterSubscribePayload, buildRightsNodesPayload,
  canonicalRpcKey, bodyData, rpcEnvelope, defaultEnvelope,
  RPC_HANDLERS, REST_HANDLERS, restKey,
  ALARM_PLAN_FIELDS, ALARM_PLAN_LINK_FIELDS
};
