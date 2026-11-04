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
