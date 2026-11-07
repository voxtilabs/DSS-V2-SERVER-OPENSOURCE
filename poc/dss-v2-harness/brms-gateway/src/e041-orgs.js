// ===== E-041: persistent organization store (data/orgs.json) =====
//
// The operator asked for the organization "VIGILAB" to exist and stay
// persisted so the org field of a new device is never empty (attempt-2 log
// showed orgCode "" in every join/batch body). The store lives next to
// devices.json in the already bind-mounted ./brms-gateway/data volume, so it
// survives container recreation exactly like the device registry (E-032).
//
// Seeds (real DSS shapes, sys_organization row 1 of the server package is
// code '001' name 'root' parent '0'; VIGILAB is the site org under it):
//   { code:'001',     name:'root',    parentCode:'0',    orgType:'1', domainId:'0' }
//   { code:'VIGILAB', name:'VIGILAB', parentCode:'001',  orgType:'1', domainId:'0' }
//
// This module imports NOTHING local (no circular imports: e025, e029 and
// e037 all import from here).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const ORG_STORE_PATH = path.join(__dirname, '..', 'data', 'orgs.json');

// The root organization of the real DSS seed (sys_organization row 1).
export const ROOT_ORG = { code: '001', name: 'root', parentCode: '0', orgType: '1', domainId: '0' };

// Default org assigned to every device whose add body carries an empty
// orgCode (observed live: the native add dialog sends orgCode "").
export const DEFAULT_ORG_CODE = 'VIGILAB';
export const DEFAULT_ORG = { code: DEFAULT_ORG_CODE, name: 'VIGILAB', parentCode: ROOT_ORG.code, orgType: '1', domainId: '0' };

let ORGS = null;

export function saveOrgsToDisk() {
  try {
    fs.mkdirSync(path.dirname(ORG_STORE_PATH), { recursive: true });
    fs.writeFileSync(ORG_STORE_PATH, JSON.stringify(ORGS || [], null, 2));
  } catch (err) {
    console.error('[E041-ORGS] Failed to persist orgs:', err.message);
  }
}

export function loadOrgsFromDisk() {
  try {
    const raw = fs.readFileSync(ORG_STORE_PATH, 'utf8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr) && arr.length) {
      ORGS = arr;
      console.log(`[E041-ORGS] Loaded ${arr.length} org(s) from ${ORG_STORE_PATH}`);
      ensureSeed();
      return ORGS;
    }
  } catch { /* no store yet -> seed below */ }
  ORGS = [{ ...ROOT_ORG }, { ...DEFAULT_ORG }];
  saveOrgsToDisk();
  console.log(`[E041-ORGS] Seeded org store: ${ORGS.map((o) => o.code).join(', ')}`);
  return ORGS;
}

// Root + VIGILAB must ALWAYS exist (an operator could delete them via the
// store file); re-add and persist if missing.
function ensureSeed() {
  let changed = false;
  for (const seed of [ROOT_ORG, DEFAULT_ORG]) {
    if (!ORGS.some((o) => o.code === seed.code)) { ORGS.push({ ...seed }); changed = true; }
  }
  if (changed) saveOrgsToDisk();
}

export function listOrgs() {
  if (!ORGS) loadOrgsFromDisk();
  ensureSeed();
  return ORGS;
}

export function getOrg(code) {
  const c = String(code ?? '');
  return listOrgs().find((o) => o.code === c) || null;
}

export function orgName(code) {
  return getOrg(code)?.name || String(code ?? '');
}

// E-087: BRMS.Organization.GetOrganizations (DPSDK.dll descriptor
// FUN_1806c97f0, xref 0x1806c996e - the RPC that fills the native Management
// Sites tree, CMenuTreeWidget). Real response VO (server package javap):
// GetOrganizationsVo{orgName, orgCode, parentOrgCode, sourceType, sourceId,
// associateId, remark, authority} - every field a STRING. The client parser
// binds string keys, so hasChild is served as "1"/"0" (not a JSON boolean).
export function buildGetOrganizationsPayload() {
  const orgs = listOrgs().map((o) => {
    const hasSub = listOrgs().some((x) => x.parentCode === o.code && x.code !== o.code);
    return {
      orgCode: o.code,
      orgName: o.name,
      parentOrgCode: o.parentCode || '0',
      sourceType: '',
      sourceId: '',
      associateId: '',
      remark: '',
      authority: '',
      // aliases the DPSDK tree parser also binds
      id: o.code,
      code: o.code,
      name: o.name,
      hasChild: hasSub ? '1' : '0',
      checked: '0'
    };
  });
  return {
    organizations: orgs,
    list: orgs,
    results: orgs,
    departments: orgs,
    items: orgs,
    pageData: orgs,
    total: String(orgs.length),      // E-100: string counters (E-095 lesson)
    count: String(orgs.length),
    totalCount: String(orgs.length)
  };
}

// E-093: HTTP list contract for GET /ipms/api/v1.1/organization/list. The
// native client fetches it via DPSDK CRestLogical::GetOrgList (FUN_1802af3d0,
// URL "v1.1/organization/list"; response parsed in CDpsdkManager::GetOrgList
// FUN_1804c5f00) to fill the CDevAdd Organization combo (cmbGroupName,
// PluginFactory.dll). The REST layer unwraps `data` and reads the row array
// + count, so BOTH spellings are served (list/results, total/count). Item
// keys follow RE-SCHEMA-DPSDK.md §5.2 (vms.LogicOrg org object: orgCode,
// orgName, id, parentCode, sort, domainId, modifyTime, channels,
// deparmentsCount [sic - typo in the DPSDK.dll string pool]) merged with the
// E-087 GetOrganizationsVo descriptor keys and the native-tree aliases
// (hasChild/checked served as "1"/"0" strings, the client binds strings).
export function buildOrganizationListPayload() {
  const orgs = listOrgs();
  const items = orgs.map((o) => {
    const children = orgs.filter((x) => x.parentCode === o.code && x.code !== o.code);
    return {
      // RE-SCHEMA-DPSDK.md §5.2 - vms.LogicOrg org object keys
      orgCode: o.code,
      orgName: o.name,
      id: o.code,
      parentCode: o.parentCode || '0',
      sort: '0',
      domainId: String(o.domainId ?? '0'),
      modifyTime: o.modifyTime || '',
      channels: [],
      deparmentsCount: String(children.length), // sic - binary typo, keep it
      // E-087 GetOrganizationsVo descriptor + tree aliases
      parentOrgCode: o.parentCode || '0',
      orgType: String(o.orgType ?? '1'),
      hasAuthority: '1', authority: '1', // E-112: ipms organization/list key check
      sourceType: '',
      sourceId: '',
      associateId: '',
      remark: '',
      authority: '',
      code: o.code,
      name: o.name,
      hasChild: children.length ? '1' : '0',
      checked: '0'
    };
  });
  return {
    list: items,
    results: items,
    organizations: items,
    items,
    pageData: items,
    total: String(items.length),      // E-100: string counters (E-095 lesson)
    count: String(items.length),
    totalCount: String(items.length)
  };
}

export function addOrg({ code, name, parentCode, orgType = '1', domainId = '0' }) {
  const c = String(code ?? '').trim();
  if (!c) return { error: 'code is required' };
  if (getOrg(c)) return { error: `org ${c} already exists`, org: getOrg(c) };
  const org = { code: c, name: String(name ?? c), parentCode: String(parentCode ?? ROOT_ORG.code), orgType: String(orgType), domainId: String(domainId) };
  ORGS.push(org);
  saveOrgsToDisk();
  return { org };
}

// Effective org of a device record: never empty (empty orgCode was the
// attempt-2 bug - the client sent orgCode "" and the tree filter dropped
// the device when queried by org).
export function deviceOrgCode(d) {
  return String(d?.orgCode ?? '').trim() || DEFAULT_ORG_CODE;
}
