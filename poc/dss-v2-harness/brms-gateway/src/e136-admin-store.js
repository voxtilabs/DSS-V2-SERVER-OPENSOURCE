// ===== E-136: store de planes de alarma + usuarios + roles ===================
//
// Segunda parte de la capa de datos de E-136 (ver e136-alarm-store.js).
//
// Contratos que implementa (matriz de gaps rea-gap-client.md):
//   fila 41  BRMS.AlarmPlan.AddAlarmPlan / UpdateAlarmPlan
//            -> 62 campos + 13 variantes `link*` (Gate/Ptz/Wall/Access/Mail/
//               Output/Record/Snapshot/User/VoicePrompt/Audio/AudioLight/
//               QuickCommand)
//   fila 42  BRMS.AlarmPlan.GetPageAlarmPlans / BatchDeleteAlarmPlans
//   fila 43  BRMS.User.GetPageUsers / AddUser / UpdateUser / DeleteUsers
//            -> digestPassword, roleIds[], macAddresses[], enableMPT, ...
//   fila 44  BRMS.Role.GetPageRoles / AddRole / UpdateRole / DeleteRoles
//            -> menuCodes[], functionCodes[], subsystemCodes[], channelIds[]
//   fila 50  BRMS.Account.ChangePassword (oldPassword/newPassword/
//            digestPassword/username/verification)
//
// Persistencia JSON atomica en data/ (ruta inyectable: los tests nunca tocan
// los ficheros compartidos con brms.test.js).
import { writeJson, readJson, str, toArray, nextId } from './e136-alarm-store.js';
import {
  ALARM_PLAN_STORE_PATH, USER_STORE_PATH, ROLE_STORE_PATH
} from './e136-alarm-store.js';

export { ALARM_PLAN_STORE_PATH, USER_STORE_PATH, ROLE_STORE_PATH };

// ---------------------------------------------------------------------------
// PLAN DE ALARMA - 62 campos + 13 `link*`
// ---------------------------------------------------------------------------
/** Campos base del plan (fila 41 de la matriz + campos de la fila 19). */
export const ALARM_PLAN_FIELDS = [
  // fila 41 - contrato Add/UpdateAlarmPlan
  'planName', 'alarmTypeId', 'mode', 'level', 'action', 'method', 'model',
  'target', 'url', 'httpUrls', 'status', 'remark', 'duration', 'prerecordTime',
  'enableRecord', 'enableVideo', 'enableIgnoreTime', 'enableShortcutKeys',
  'sendSnapshot', 'content', 'executeMode', 'seq', 'sourceCodes', 'channels',
  'channelIds', 'userIds', 'userGroupIds', 'recipients', 'emailAddress',
  'mailTemplateId', 'vacationTemplateId', 'timeTemplateId', 'planTemplateId',
  'ignoreTime', 'fileIds', 'wallId', 'windowId', 'videoStreamType',
  'recordStreamType', 'customWindow', 'quickCommands', 'shortcutKeys',
  // fila 19 - contrato alarm/plan/source
  'sourceId', 'sourceCode', 'sourceName', 'users', 'streamType',
  // 13 variantes link*
  'linkGate', 'linkPtz', 'linkWall', 'linkAccess', 'linkMail', 'linkOutput',
  'linkRecord', 'linkSnapshot', 'linkUser', 'linkVoicePrompt', 'linkAudio',
  'linkAudioLight', 'linkQuickCommand',
  // identidad propia del store
  'planId', 'planCode', 'orgCode', 'createTime', 'updateTime'
];

/** Los 13 `link*` (verificables por el cliente nativo). */
export const ALARM_PLAN_LINK_FIELDS = ALARM_PLAN_FIELDS.filter((f) => f.startsWith('link'));

const PLAN_ARRAY_FIELDS = new Set([
  'httpUrls', 'sourceCodes', 'channels', 'channelIds', 'userIds', 'userGroupIds',
  'recipients', 'ignoreTime', 'fileIds', 'quickCommands', 'shortcutKeys', 'users'
]);
const PLAN_NUMERIC_FIELDS = new Set([
  'duration', 'prerecordTime', 'seq', 'level', 'mode', 'status', 'executeMode',
  'videoStreamType', 'recordStreamType', 'streamType', 'alarmTypeId'
]);

/** Normaliza/camella cualquier plan con los 62+ campos del contrato. */
export function normalizeAlarmPlan(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const f of ALARM_PLAN_FIELDS) {
    if (f === 'planId' || f === 'planCode' || f === 'createTime' || f === 'updateTime') continue;
    let v = src[f];
    if (v === undefined || v === null) {
      if (PLAN_ARRAY_FIELDS.has(f)) v = [];
      else if (PLAN_NUMERIC_FIELDS.has(f)) v = '0';
      else v = '';
    }
    if (PLAN_ARRAY_FIELDS.has(f)) v = toArray(v);
    else if (typeof v === 'boolean') v = v ? '1' : '0';
    else v = str(v);
    out[f] = v;
  }
  const planId = str(src.planId || src.id || '') || nextId('PLAN');
  out.planId = planId;
  out.planCode = str(src.planCode || planId);
  out.createTime = str(src.createTime || new Date().toISOString());
  out.updateTime = str(src.updateTime || out.createTime);
  return out;
}

// ---------------------------------------------------------------------------
// STORE DE PLANES
// ---------------------------------------------------------------------------
export function createAlarmPlanStore({ filePath = ALARM_PLAN_STORE_PATH, persist = true, seed = [] } = {}) {
  const target = filePath;
  let plans = null;

  function ensure() {
    if (plans) return plans;
    const loaded = readJson(target);
    plans = Array.isArray(loaded) ? loaded.map((p) => normalizeAlarmPlan(p)) : [];
    if (!plans.length && Array.isArray(seed) && seed.length) plans = seed.map((p) => normalizeAlarmPlan(p));
    return plans;
  }
  function save() { return persist ? writeJson(target, ensure()) : false; }

  function add(input = {}) {
    const plan = normalizeAlarmPlan(input);
    ensure().push(plan);
    save();
    return plan;
  }

  function update(planId, patch = {}) {
    const id = str(planId);
    const list = ensure();
    const idx = list.findIndex((p) => p.planId === id || p.planCode === id);
    if (idx < 0) return null;
    const merged = normalizeAlarmPlan({ ...list[idx], ...patch, planId: list[idx].planId });
    merged.createTime = list[idx].createTime;
    merged.updateTime = new Date().toISOString();
    list[idx] = merged;
    save();
    return merged;
  }

  function get(planId) {
    const id = str(planId);
    return ensure().find((p) => p.planId === id || p.planCode === id) || null;
  }

  function all() { return ensure().slice(); }

  function page(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    let rows = ensure();
    const orgCodes = toArray(q.orgCodes);
    if (orgCodes.length) rows = rows.filter((p) => orgCodes.includes(str(p.orgCode)));
    if (q.planName) rows = rows.filter((p) => str(p.planName).includes(str(q.planName)));
    const alarmTypeIds = toArray(q.alarmTypeIds);
    if (alarmTypeIds.length) rows = rows.filter((p) => alarmTypeIds.includes(str(p.alarmTypeId)));
    const sourceCodes = toArray(q.sourceCodes);
    if (sourceCodes.length) rows = rows.filter((p) => sourceCodes.includes(str(p.sourceCode)));
    const pageNo = Math.max(1, parseInt(q.page || q.currentPage || q.pageNo || '1', 10) || 1);
    const pageSize = Math.max(1, parseInt(q.pageSize || '20', 10) || 20);
    const startIdx = (pageNo - 1) * pageSize;
    const slice = rows.slice(startIdx, startIdx + pageSize);
    const total = rows.length;
    return {
      plans: slice, list: slice, results: slice, items: slice, records: slice, pageData: slice,
      total, totalCount: total, count: slice.length,
      page: pageNo, currentPage: pageNo, pageNo, pageSize,
      pageCount: Math.ceil(total / pageSize) || 0
    };
  }

  function batchDelete(ids = []) {
    const list = ensure();
    const wanted = new Set(toArray(ids).map((v) => str(v)));
    const removed = [];
    for (let i = list.length - 1; i >= 0; i--) {
      if (wanted.has(str(list[i].planId)) || wanted.has(str(list[i].planCode))) {
        removed.unshift(list.splice(i, 1)[0]);
      }
    }
    save();
    return { success: true, deleted: removed.map((p) => p.planId), deletedCount: removed.length, count: removed.length };
  }

  function clear() { plans = []; save(); return true; }

  return { add, update, get, all, page, batchDelete, clear, save, filePath: target };
}

// ---------------------------------------------------------------------------
// STORE DE USUARIOS
// ---------------------------------------------------------------------------
export const USER_FIELDS = [
  'userId', 'username', 'name', 'password', 'digestPassword', 'roleIds',
  'groupId', 'userType', 'online', 'enableMPT', 'enableMacAddresses',
  'macAddresses', 'ptzLevel', 'policeCode', 'policeType', 'tel', 'email',
  'memo', 'status', 'enableExpireDate', 'expireDate', 'enablePasswordValidity',
  'passwordValidity', 'forceResetPassword', 'reuse', 'personName', 'personId',
  'sip', 'keyword', 'searchInfo', 'houseHolder', 'lastLoginDate',
  'lastUpdatePasswordDate', 'orgCode', 'createTime', 'updateTime'
];

export function normalizeUser(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const f of USER_FIELDS) {
    if (f === 'userId' || f === 'createTime' || f === 'updateTime') continue;
    let v = src[f];
    if (v === undefined || v === null) {
      if (f === 'roleIds' || f === 'macAddresses') v = [];
      else if (['online', 'enableMPT', 'enableMacAddresses', 'enableExpireDate',
        'enablePasswordValidity', 'forceResetPassword', 'reuse', 'status'].includes(f)) v = '0';
      else v = '';
    }
    if (f === 'roleIds' || f === 'macAddresses') v = toArray(v);
    else if (typeof v === 'boolean') v = v ? '1' : '0';
    else v = str(v);
    out[f] = v;
  }
  const username = str(src.username || src.name || '');
  out.username = username;
  out.name = str(src.name || username);
  out.userId = str(src.userId || src.id || '') || nextId('USR');
  out.createTime = str(src.createTime || new Date().toISOString());
  out.updateTime = str(src.updateTime || out.createTime);
  return out;
}

export function createUserStore({ filePath = USER_STORE_PATH, persist = true, seed = [] } = {}) {
  const target = filePath;
  let users = null;

  function ensure() {
    if (users) return users;
    const loaded = readJson(target);
    users = Array.isArray(loaded) ? loaded.map((u) => normalizeUser(u)) : [];
    if (!users.length && Array.isArray(seed) && seed.length) users = seed.map((u) => normalizeUser(u));
    return users;
  }
  function save() { return persist ? writeJson(target, ensure()) : false; }

  function add(input = {}) {
    const user = normalizeUser(input);
    ensure().push(user);
    save();
    return user;
  }
  function update(id, patch = {}) {
    const key = str(id);
    const list = ensure();
    const idx = list.findIndex((u) => u.userId === key || u.username === key);
    if (idx < 0) return null;
    const merged = normalizeUser({ ...list[idx], ...patch, userId: list[idx].userId, username: list[idx].username });
    merged.createTime = list[idx].createTime;
    merged.updateTime = new Date().toISOString();
    list[idx] = merged;
    save();
    return merged;
  }
  function get(id) {
    const key = str(id);
    return ensure().find((u) => u.userId === key || u.username === key) || null;
  }
  function remove(ids = []) {
    const list = ensure();
    const wanted = new Set(toArray(ids).map((v) => str(v)));
    let n = 0;
    for (let i = list.length - 1; i >= 0; i--) {
      if (wanted.has(str(list[i].userId)) || wanted.has(str(list[i].username))) { list.splice(i, 1); n++; }
    }
    save();
    return { success: true, deleted: n, count: n };
  }
  function page(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    let rows = ensure();
    if (q.keyword) {
      const k = str(q.keyword).toLowerCase();
      rows = rows.filter((u) => `${u.username} ${u.name} ${u.email} ${u.tel}`.toLowerCase().includes(k));
    }
    if (q.roleIds) {
      const roles = toArray(q.roleIds);
      rows = rows.filter((u) => u.roleIds.some((r) => roles.includes(str(r))));
    }
    if (q.status !== undefined && q.status !== '') rows = rows.filter((u) => str(u.status) === str(q.status));
    const pageNo = Math.max(1, parseInt(q.page || q.currentPage || q.pageNo || '1', 10) || 1);
    const pageSize = Math.max(1, parseInt(q.pageSize || '20', 10) || 20);
    const slice = rows.slice((pageNo - 1) * pageSize, (pageNo - 1) * pageSize + pageSize);
    const total = rows.length;
    return {
      users: slice, list: slice, results: slice, items: slice, records: slice, pageData: slice,
      total, totalCount: total, count: slice.length,
      page: pageNo, currentPage: pageNo, pageNo, pageSize,
      pageCount: Math.ceil(total / pageSize) || 0
    };
  }
  /** Cambio de clave: valida la antigua y guarda digest + validity. */
  function changePassword(username, newPassword, { oldPassword = '', digestPassword = '' } = {}) {
    const user = get(username);
    if (!user) return { success: false, errorCode: '1', errorMsg: 'user not found', userName: str(username) };
    if (oldPassword && user.password && user.password !== oldPassword) {
      return { success: false, errorCode: '2', errorMsg: 'old password mismatch', userName: user.username };
    }
    user.password = str(newPassword);
    if (digestPassword) user.digestPassword = str(digestPassword);
    user.lastUpdatePasswordDate = new Date().toISOString();
    user.updateTime = user.lastUpdatePasswordDate;
    save();
    return {
      success: true, userName: user.username, userId: user.userId,
      lastUpdatePasswordDate: user.lastUpdatePasswordDate
    };
  }
  function all() { return ensure().slice(); }
  function clear() { users = []; save(); return true; }
  return { add, update, get, remove, page, changePassword, all, clear, save, filePath: target };
}

// ---------------------------------------------------------------------------
// STORE DE ROLES
// ---------------------------------------------------------------------------
export const ROLE_FIELDS = [
  'roleId', 'roleName', 'roleType', 'memo', 'orgCode', 'orgCodes', 'menuCodes',
  'functionCodes', 'subsystemCodes', 'channelIds', 'deviceCodes', 'autoAuthorize',
  'addChannelIds', 'deleteChannelIds', 'changeChannelIds', 'addDeviceCodes',
  'deleteDeviceCodes', 'changeDeviceCodes', 'addOrgCodes', 'deleteOrgCodes',
  'changeOrgCodes', 'createTime', 'updateTime'
];

export function normalizeRole(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const out = {};
  const arrays = new Set([
    'orgCodes', 'menuCodes', 'functionCodes', 'subsystemCodes', 'channelIds',
    'deviceCodes', 'addChannelIds', 'deleteChannelIds', 'changeChannelIds',
    'addDeviceCodes', 'deleteDeviceCodes', 'changeDeviceCodes', 'addOrgCodes',
    'deleteOrgCodes', 'changeOrgCodes'
  ]);
  for (const f of ROLE_FIELDS) {
    if (f === 'roleId' || f === 'createTime' || f === 'updateTime') continue;
    let v = src[f];
    if (v === undefined || v === null) {
      if (arrays.has(f)) v = [];
      else if (f === 'autoAuthorize' || f === 'roleType') v = '0';
      else v = '';
    }
    if (arrays.has(f)) v = toArray(v);
    else if (typeof v === 'boolean') v = v ? '1' : '0';
    else v = str(v);
    out[f] = v;
  }
  out.roleId = str(src.roleId || src.id || '') || nextId('ROL');
  out.roleName = str(src.roleName || src.name || '');
  out.createTime = str(src.createTime || new Date().toISOString());
  out.updateTime = str(src.updateTime || out.createTime);
  return out;
}

export function createRoleStore({ filePath = ROLE_STORE_PATH, persist = true, seed = [] } = {}) {
  const target = filePath;
  let roles = null;

  function ensure() {
    if (roles) return roles;
    const loaded = readJson(target);
    roles = Array.isArray(loaded) ? loaded.map((r) => normalizeRole(r)) : [];
    if (!roles.length && Array.isArray(seed) && seed.length) roles = seed.map((r) => normalizeRole(r));
    return roles;
  }
  function save() { return persist ? writeJson(target, ensure()) : false; }

  function add(input = {}) {
    const role = normalizeRole(input);
    ensure().push(role);
    save();
    return role;
  }
  function update(id, patch = {}) {
    const key = str(id);
    const list = ensure();
    const idx = list.findIndex((r) => r.roleId === key || r.roleName === key);
    if (idx < 0) return null;
    const merged = normalizeRole({ ...list[idx], ...patch, roleId: list[idx].roleId });
    merged.createTime = list[idx].createTime;
    merged.updateTime = new Date().toISOString();
    list[idx] = merged;
    save();
    return merged;
  }
  function get(id) {
    const key = str(id);
    return ensure().find((r) => r.roleId === key || r.roleName === key) || null;
  }
  function remove(ids = []) {
    const list = ensure();
    const wanted = new Set(toArray(ids).map((v) => str(v)));
    let n = 0;
    for (let i = list.length - 1; i >= 0; i--) {
      if (wanted.has(str(list[i].roleId)) || wanted.has(str(list[i].roleName))) { list.splice(i, 1); n++; }
    }
    save();
    return { success: true, deleted: n, count: n };
  }
  function page(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    let rows = ensure();
    if (q.roleName) rows = rows.filter((r) => str(r.roleName).includes(str(q.roleName)));
    if (q.roleType !== undefined && q.roleType !== '') rows = rows.filter((r) => str(r.roleType) === str(q.roleType));
    if (q.orgCode) rows = rows.filter((r) => str(r.orgCode) === str(q.orgCode));
    const pageNo = Math.max(1, parseInt(q.page || q.currentPage || q.pageNo || '1', 10) || 1);
    const pageSize = Math.max(1, parseInt(q.pageSize || '20', 10) || 20);
    const slice = rows.slice((pageNo - 1) * pageSize, (pageNo - 1) * pageSize + pageSize);
    const total = rows.length;
    return {
      roles: slice, list: slice, results: slice, items: slice, records: slice, pageData: slice,
      total, totalCount: total, count: slice.length,
      page: pageNo, currentPage: pageNo, pageNo, pageSize,
      pageCount: Math.ceil(total / pageSize) || 0
    };
  }
  function all() { return ensure().slice(); }
  function clear() { roles = []; save(); return true; }
  return { add, update, get, remove, page, all, clear, save, filePath: target };
}

export default {
  createAlarmPlanStore, createUserStore, createRoleStore,
  ALARM_PLAN_FIELDS, ALARM_PLAN_LINK_FIELDS, USER_FIELDS, ROLE_FIELDS,
  normalizeAlarmPlan, normalizeUser, normalizeRole
};
