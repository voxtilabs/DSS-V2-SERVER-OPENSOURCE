// ===== E-180: autorizacion por ambito (sitio / dispositivo / canal) =========
//
// El cliente nativo pregunta los derechos ANTES de pintar: el arbol de
// recursos, device/page, channel/page y account/function/channel/check. Hasta
// ahora el gateway devolvia TODO a cualquiera, asi que un usuario "restringido"
// veia y reproducia todas las camaras (research/E-162 §2.4 del informe de
// permisos).
//
// Modelo (el mismo del servidor real, ver e136-admin-store.ROLE_FIELDS):
//   usuario -> roleIds[] -> rol{orgCodes[], deviceCodes[], channelIds[]}
//   usuario -> ambito propio (override) en data/authz-scopes.json
// Reglas:
//   - admin (userType '1' o adminFlag '1') => sin restriccion (dataScope 'all')
//   - si el usuario o cualquiera de sus roles declara ambito => solo eso
//   - si no declara nada => sin restriccion (compatibilidad con las cuentas
//     que ya existian)
import { createUserStore, createRoleStore } from './e136-admin-store.js';
import { USER_STORE_PATH, ROLE_STORE_PATH } from './e136-admin-store.js';
import { readJson, writeJson, str, toArray } from './e136-alarm-store.js';

export const SCOPE_STORE_PATH = String(USER_STORE_PATH).replace(/users\.json$/i, 'authz-scopes.json');

let _users = null;
let _roles = null;
let _scopes = null;

export function usersStore() {
  if (!_users) {
    _users = createUserStore({
      seed: [{
        userId: '1', username: 'admin', name: 'admin', userType: '1',
        roleIds: ['1'], status: '1', enableMPT: '0', online: '0', orgCode: '001'
      }]
    });
    // E-180b: guarantee the built-in administrator always exists and always
    // carries full rights (an earlier AddUser could rewrite it).
    const admin = _users.get('admin');
    if (!admin) {
      _users.add({ userId: '1', username: 'admin', name: 'admin', userType: '1', roleIds: ['1'], status: '1' });
    } else if (str(admin.userType) !== '1' || !toArray(admin.roleIds).includes('1')) {
      _users.update(admin.userId, { userType: '1', roleIds: ['1'], status: '1' });
    }
  }
  return _users;
}

export function rolesStore() {
  if (!_roles) {
    _roles = createRoleStore({
      seed: [
        { roleId: '1', roleName: 'Admin', roleType: '1', memo: 'super admin', orgCode: '001' },
        { roleId: '2', roleName: 'Operator', roleType: '2', memo: 'default operator', orgCode: '001' }
      ]
    });
  }
  return _roles;
}

function scopes() {
  if (_scopes) return _scopes;
  const loaded = readJson(SCOPE_STORE_PATH);
  _scopes = loaded && typeof loaded === 'object' && !Array.isArray(loaded) ? loaded : {};
  if (!_scopes.users) _scopes.users = {};
  if (!_scopes.resources) _scopes.resources = {};
  return _scopes;
}

function saveScopes() { return writeJson(SCOPE_STORE_PATH, scopes()); }

function uniq(list) { return [...new Set(list.filter(Boolean).map((v) => String(v)))]; }

// user record + own override
export function getUser(username) {
  const key = str(username);
  if (!key) return null;
  const u = usersStore().get(key);
  if (!u) return null;
  const own = scopes().users[u.username] || {};
  return {
    ...u,
    orgCodes: uniq([...(toArray(own.orgCodes)), ...(toArray(u.orgCodes))]),
    deviceCodes: uniq([...(toArray(own.deviceCodes)), ...(toArray(u.deviceCodes))]),
    channelIds: uniq([...(toArray(own.channelIds)), ...(toArray(u.channelIds))]),
    dataScope: str(own.dataScope || u.dataScope || '')
  };
}

export function setUserScope(username, scope = {}) {
  const key = str(username);
  if (!key) return null;
  scopes().users[key] = {
    orgCodes: uniq(toArray(scope.orgCodes)),
    deviceCodes: uniq(toArray(scope.deviceCodes)),
    channelIds: uniq(toArray(scope.channelIds)),
    dataScope: str(scope.dataScope || '')
  };
  saveScopes();
  return scopes().users[key];
}

export function setRoleGrants(roleId, grants = {}) {
  const rec = rolesStore().update(roleId, {
    orgCodes: toArray(grants.orgCodes),
    deviceCodes: toArray(grants.deviceCodes),
    channelIds: toArray(grants.channelIds),
    menuCodes: toArray(grants.menuCodes),
    functionCodes: toArray(grants.functionCodes)
  });
  return rec;
}

export function setResourceRoles(resourceId, roleIds) {
  const key = str(resourceId);
  if (!key) return null;
  scopes().resources[key] = uniq(toArray(roleIds));
  saveScopes();
  return scopes().resources[key];
}

export function getResourceRoles(resourceId) {
  return scopes().resources[str(resourceId)] || [];
}

export function isAdminUser(u) {
  if (!u) return true;
  return str(u.userType) === '1' || str(u.adminFlag) === '1' ||
    str(u.isAdmin) === '1' || str(u.username) === 'admin' ||
    (toArray(u.roleIds).includes('1') && str(u.roleType) !== '2');
}

// Union of the user's own override and every role it carries. A declaration
// (non-empty list anywhere) means "restricted"; nothing declared means "all".
export function grantsFor(u) {
  if (!u || isAdminUser(u)) return { all: true, orgCodes: [], deviceCodes: [], channelIds: [], functionCodes: [] };
  const out = { all: false, orgCodes: [], deviceCodes: [], channelIds: [], functionCodes: [] };
  let declared = false;
  const roleIds = toArray(u.roleIds);
  for (const rid of roleIds) {
    const role = rolesStore().get(rid);
    if (!role) continue;
    const orgs = toArray(role.orgCodes);
    const devs = toArray(role.deviceCodes);
    const chans = toArray(role.channelIds);
    if (orgs.length || devs.length || chans.length) declared = true;
    out.orgCodes.push(...orgs);
    out.deviceCodes.push(...devs);
    out.channelIds.push(...chans);
    out.functionCodes.push(...toArray(role.functionCodes));
  }
  if (toArray(u.orgCodes).length || toArray(u.deviceCodes).length || toArray(u.channelIds).length) declared = true;
  out.orgCodes = uniq([...out.orgCodes, ...toArray(u.orgCodes)]);
  out.deviceCodes = uniq([...out.deviceCodes, ...toArray(u.deviceCodes)]);
  out.channelIds = uniq([...out.channelIds, ...toArray(u.channelIds)]);
  out.functionCodes = uniq(out.functionCodes);
  // channels are the finest grain: derive their device + org when only the
  // channel list was granted.
  for (const ch of out.channelIds) {
    const dev = String(ch).split('$')[0];
    if (dev) out.deviceCodes.push(dev);
  }
  out.deviceCodes = uniq(out.deviceCodes);
  if (!declared) return { all: true, orgCodes: [], deviceCodes: [], channelIds: [], functionCodes: [] };
  return out;
}

export function channelAllowed(grants, channelId) {
  if (!grants || grants.all) return true;
  const key = str(channelId);
  if (!key) return false;
  if (grants.channelIds.includes(key)) return true;
  if (grants.deviceCodes.length) return grants.deviceCodes.includes(key.split('$')[0]);
  return false;
}

export function deviceAllowed(grants, deviceCode) {
  if (!grants || grants.all) return true;
  const key = str(deviceCode);
  if (!key) return false;
  if (grants.deviceCodes.includes(key)) return true;
  return grants.channelIds.some((ch) => String(ch).split('$')[0] === key);
}

export function orgAllowed(grants, orgCode) {
  if (!grants || grants.all) return true;
  const key = str(orgCode);
  if (!key) return true;
  return grants.orgCodes.includes(key);
}

export function scopeSummary(grants) {
  return {
    dataScope: !grants || grants.all ? 'all' : 'restricted',
    orgCodes: (grants && grants.orgCodes) || [],
    deviceCodes: (grants && grants.deviceCodes) || [],
    channelIds: (grants && grants.channelIds) || []
  };
}

// used by tests
export function _resetForTests() { _users = null; _roles = null; _scopes = null; }
