// ===== E-033: real monitor/view contract (saved layouts = "views") =====
//
// Sources (authoritative, no invention):
//   * DSS SERVER package V8.008 (outer-db data area, decoded with the E-009
//     pipeline: outer-db.bin + LZMA blocks + javap):
//       - ViewController.getViewTree(Integer) -> ResponseInfo<ViewTreeVo>
//       - ViewTreeVo          { List<ViewDataTreeVo> viewInfos }
//       - ViewDataTreeVo      { String viewType; List<ViewDirTreeVo> viewDirs }
//       - ViewDirTreeVo       { String viewDirCode; String rootDir;
//                               String viewDirName; List<ViewVo> views }
//       - ViewVo              { viewCode, viewName, viewShared, viewShareable,
//                               viewReaded, windowTotal, griddingRows,
//                               griddingCols, List<WindowLayoutVo> windowLayout,
//                               List<WindowDataVo> windowData }
//       - WindowLayoutVo      { griddingIndex, griddingEnable, griddingCombine,
//                               windowFromX, windowToX, windowFromY, windowToY }
//       - WindowDataVo        { windowNo, resourceType, resourceCode,
//                               resourceName, streamType, alarmWindow, siteIp }
//       - UnreadViewVo        { viewCode, viewName }
//       - ViewShareRecordVo   { sharedViewCode, shareUserName, shareTime, remark }
//       - ResultsVo<T>        { List<T> results }
//       - ViewDirVo           { viewDirCode, viewDirName }
//   * DSS CLIENT 8.006 DPSDK.dll string pool (what the client parses):
//       "viewInfos", "viewDirs", "rootDir", "griddingCombine",
//       "Dpsdk::CRestLogical::GetViewTree" -> "monitor/view/view-tree".
//
// Semantics taken from the server bytecode (ViewTreeVo.generateViewDirs /
// generateViews):
//   * viewInfos ALWAYS has TWO entries: public dirs then private dirs; both
//     carry the viewType that was requested.
//   * rootDir = "1" when the dir is a ROOT dir (viewDirLevel == 1), else "0".
//   * viewShareable = "0" for the public tree (viewType 1) and "1" for the
//     private tree (viewType 2).
//   * windowTotal/griddingRows/griddingCols are STRINGS ("1", "2", ...).
//
// Paths served by the client SDK (DPSDK string pool 0x180ca2568..):
//   GET  monitor/view/view-tree?viewType=N
//   POST monitor/view/view-dir              GET/PUT monitor/view/view-dir/{code}
//   POST monitor/view/view-dir/delete/batch
//   POST monitor/view                        PUT  monitor/view/{code}
//   PUT  monitor/view/{code}/rename          POST monitor/view/delete/batch
//   POST monitor/view/share                  POST monitor/view/share/ack
//   GET  monitor/view/share/{code}           GET  monitor/view/share/unread/list

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const VIEW_STORE_PATH = path.join(__dirname, '..', 'data', 'views.json');

// ViewDirModeEnum: PUBLIC_DIR_MODE / PRIVATE_DIR_MODE
export const VIEW_TYPE_PUBLIC = 1;
export const VIEW_TYPE_PRIVATE = 2;

const VIEW_DIRS = new Map(); // viewDirCode -> dir record
const VIEWS = new Map();     // viewCode -> view record
const SHARES = new Map();    // shareId -> share record
let viewSeq = 0;

function ensureDataDir() {
  try { fs.mkdirSync(path.dirname(VIEW_STORE_PATH), { recursive: true }); } catch { /* exists */ }
}

export function loadViewsFromDisk() {
  try {
    ensureDataDir();
    const arr = JSON.parse(fs.readFileSync(VIEW_STORE_PATH, 'utf8'));
    if (arr && Array.isArray(arr.dirs)) for (const d of arr.dirs) VIEW_DIRS.set(d.viewDirCode, d);
    if (arr && Array.isArray(arr.views)) for (const v of arr.views) VIEWS.set(v.viewCode, v);
    if (arr && Array.isArray(arr.shares)) for (const s of arr.shares) SHARES.set(s.shareId, s);
    const total = VIEW_DIRS.size + VIEWS.size + SHARES.size;
    if (total) console.log(`[E033-VIEWS] Loaded ${VIEW_DIRS.size} dirs / ${VIEWS.size} views from ${VIEW_STORE_PATH}`);
    if (arr && Number(arr.seq) > viewSeq) viewSeq = Number(arr.seq);
  } catch (err) {
    console.log(`[E033-VIEWS] No view store (${VIEW_STORE_PATH}), starting fresh`);
  }
}

export function saveViewsToDisk() {
  try {
    ensureDataDir();
    fs.writeFileSync(VIEW_STORE_PATH, JSON.stringify({
      seq: viewSeq,
      dirs: [...VIEW_DIRS.values()],
      views: [...VIEWS.values()],
      shares: [...SHARES.values()]
    }, null, 2));
  } catch (err) {
    console.error('[E033-VIEWS] Failed to persist views:', err.message);
  }
}

function nextCode(prefix) {
  viewSeq += 1;
  return `${prefix}${Date.now().toString(36).toUpperCase()}${String(viewSeq).padStart(4, '0')}`;
}

const str = (v) => (v === null || v === undefined ? '' : String(v));
const strOrNull = (v) => (v === null || v === undefined ? null : String(v));

// ---------------------------------------------------------------------------
// Payload builders (mirror the server DTOs exactly)
// ---------------------------------------------------------------------------

function windowLayoutVo(l) {
  return {
    griddingIndex: strOrNull(l.griddingIndex),
    griddingEnable: strOrNull(l.griddingEnable),
    griddingCombine: strOrNull(l.griddingCombine),
    windowFromX: strOrNull(l.windowFromX),
    windowToX: strOrNull(l.windowToX),
    windowFromY: strOrNull(l.windowFromY),
    windowToY: strOrNull(l.windowToY)
  };
}

function windowDataVo(d) {
  return {
    windowNo: str(d.windowNo),
    resourceType: str(d.resourceType),
    resourceCode: str(d.resourceCode),
    resourceName: str(d.resourceName),
    streamType: str(d.streamType),
    alarmWindow: str(d.alarmWindow),
    siteIp: str(d.siteIp)
  };
}

function viewVo(v, isPublicTree) {
  return {
    viewCode: v.viewCode,
    viewName: v.viewName,
    // server: shareable = isRoot ? "0" : "1" (isRoot == public tree)
    viewShareable: isPublicTree ? '0' : '1',
    viewShared: str(v.viewShared ?? 0),
    viewReaded: str(v.viewReaded ?? 0),
    windowTotal: str(v.windowTotal ?? 0),
    griddingRows: strOrNull(v.griddingRows),
    griddingCols: strOrNull(v.griddingCols),
    windowLayout: (v.windowLayout || []).map(windowLayoutVo),
    windowData: (v.windowData || []).map(windowDataVo)
  };
}

function viewDirTreeVo(dir, isPublicTree) {
  const views = (dir.viewCodes || []).map((code) => VIEWS.get(code)).filter(Boolean);
  return {
    viewDirCode: dir.viewDirCode,
    rootDir: Number(dir.viewDirLevel) === 1 ? '1' : '0',
    viewDirName: dir.viewDirName,
    views: views.map((v) => viewVo(v, isPublicTree))
  };
}

// E-120: Monitoring Center seed. The operator's org gets a root dir + a view
// with the operator camera, so the module opens populated (and the user can
// then create more dirs/views from the UI - the CRUD above is complete).
export function seedMonitoringCenter(opts = {}) {
  const orgCode = String(opts.orgCode || 'VIGILAB');
  const channel = String(opts.channelId || 'D0238JDG3016$1$0$0');
  const deviceCode = String(opts.deviceCode || 'D0238JDG3016');
  const cameraName = String(opts.cameraName || 'Camara Principal');
  if (VIEW_DIRS.size) return { seeded: false, reason: 'store not empty' };
  const dirCode = 'VD' + orgCode.toUpperCase().replace(/[^A-Z0-9]/g, '');
  VIEW_DIRS.set(dirCode, {
    viewDirCode: dirCode, viewDirName: orgCode, viewDirType: VIEW_TYPE_PUBLIC, viewDirLevel: 1,
    roleIds: [], remark: 'Organizacion ' + orgCode, viewCodes: []
  });
  const viewCode = nextCode('VW');
  VIEWS.set(viewCode, {
    viewCode, viewName: cameraName, viewDirCode: dirCode,
    viewShared: 0, viewReaded: 0, windowTotal: '1',
    griddingRows: '1', griddingCols: '1',
    windowLayout: [{ griddingIndex: '1', griddingEnable: '1', griddingCombine: '0', windowFromX: '0', windowToX: '1', windowFromY: '0', windowToY: '1' }],
    windowData: [{ windowNo: '1', resourceType: '1', resourceCode: channel, resourceName: cameraName, streamType: '0', alarmWindow: '0', siteIp: '' }],
    orgCode, deviceCode
  });
  VIEW_DIRS.get(dirCode).viewCodes.push(viewCode);
  saveViewsToDisk();
  return { seeded: true, viewDirCode: dirCode, viewCode };
}

// GET monitor/view/view-tree?viewType=N
// -> { viewInfos: [ {viewType, viewDirs:[public]}, {viewType, viewDirs:[private]} ] }
export function buildViewTreePayload(viewType = VIEW_TYPE_PUBLIC) {
  const type = Number(viewType) === VIEW_TYPE_PRIVATE ? VIEW_TYPE_PRIVATE : VIEW_TYPE_PUBLIC;
  const isPublicTree = type === VIEW_TYPE_PUBLIC;
  const dirs = [...VIEW_DIRS.values()];
  const publicDirs = dirs.filter((d) => Number(d.viewDirType) === VIEW_TYPE_PUBLIC);
  const privateDirs = dirs.filter((d) => Number(d.viewDirType) === VIEW_TYPE_PRIVATE);
  const tree = (list) => ({
    viewType: String(type),
    viewDirs: list.map((d) => viewDirTreeVo(d, isPublicTree))
  });
  return { viewInfos: [tree(publicDirs), tree(privateDirs)] };
}

// GET monitor/view/view-dir/{code} -> ViewDirVo
export function buildViewDirPayload(code) {
  const dir = VIEW_DIRS.get(String(code));
  if (!dir) return null;
  return { viewDirCode: dir.viewDirCode, viewDirName: dir.viewDirName };
}

// POST monitor/view/view-dir -> AddViewDirXo
export function addViewDir(body = {}) {
  const name = String(body.viewDirName || '').trim();
  if (!name) return { error: 'viewDirName is required' };
  const code = String(body.viewDirCode || nextCode('VD'));
  const dir = {
    viewDirCode: code,
    viewDirName: name,
    viewDirType: Number(body.viewType) === VIEW_TYPE_PRIVATE ? VIEW_TYPE_PRIVATE : VIEW_TYPE_PUBLIC,
    viewDirLevel: Number(body.viewDirLevel) === 2 ? 2 : 1,
    roleIds: Array.isArray(body.roleIds) ? body.roleIds.map(String) : [],
    remark: String(body.remark || ''),
    viewCodes: []
  };
  VIEW_DIRS.set(code, dir);
  saveViewsToDisk();
  return { viewDirCode: code, viewDirName: name };
}

// PUT monitor/view/view-dir/{code} -> UpdateViewDirXo
export function updateViewDir(code, body = {}) {
  const dir = VIEW_DIRS.get(String(code));
  if (!dir) return null;
  if (body.viewDirName !== undefined) dir.viewDirName = String(body.viewDirName);
  if (Array.isArray(body.roleIds)) dir.roleIds = body.roleIds.map(String);
  if (body.remark !== undefined) dir.remark = String(body.remark);
  saveViewsToDisk();
  return { viewDirCode: dir.viewDirCode, viewDirName: dir.viewDirName };
}

// POST monitor/view/view-dir/delete/batch -> DeleteViewDirXo {viewDirCodes}
export function batchDeleteViewDir(body = {}) {
  const codes = [].concat(body.viewDirCodes || body.codes || []).filter(Boolean).map(String);
  let removed = 0;
  for (const code of codes) {
    const dir = VIEW_DIRS.get(code);
    if (!dir) continue;
    for (const vc of dir.viewCodes || []) VIEWS.delete(vc);
    VIEW_DIRS.delete(code);
    removed += 1;
  }
  if (removed) saveViewsToDisk();
  return { success: true, removed, total: removed, results: [] };
}

// POST monitor/view -> AddViewXo
export function addView(body = {}) {
  const name = String(body.viewName || '').trim();
  if (!name) return { error: 'viewName is required' };
  const code = String(body.viewCode || nextCode('V'));
  const dirCode = String(body.viewDirCode || '');
  const dir = VIEW_DIRS.get(dirCode);
  const view = {
    viewCode: code,
    viewName: name,
    viewType: Number(body.viewType) === VIEW_TYPE_PRIVATE ? VIEW_TYPE_PRIVATE : VIEW_TYPE_PUBLIC,
    viewDirCode: dirCode,
    windowTotal: Number(body.windowTotal) || (Array.isArray(body.windowData) ? body.windowData.length : 0),
    griddingRows: strOrNull(body.griddingRows),
    griddingCols: strOrNull(body.griddingCols),
    customSplit: body.customSplit === undefined ? null : Number(body.customSplit),
    viewShared: 0,
    viewReaded: 0,
    windowLayout: Array.isArray(body.windowLayout) ? body.windowLayout : [],
    windowData: Array.isArray(body.windowData) ? body.windowData : []
  };
  VIEWS.set(code, view);
  if (dir) {
    dir.viewCodes = dir.viewCodes || [];
    if (!dir.viewCodes.includes(code)) dir.viewCodes.push(code);
  }
  saveViewsToDisk();
  return { viewCode: code, viewName: name, viewDirCode: dirCode };
}

// PUT monitor/view/{code} -> UpdateViewXo
export function updateView(code, body = {}) {
  const view = VIEWS.get(String(code));
  if (!view) return null;
  if (body.windowTotal !== undefined) view.windowTotal = Number(body.windowTotal) || 0;
  if (body.griddingRows !== undefined) view.griddingRows = strOrNull(body.griddingRows);
  if (body.griddingCols !== undefined) view.griddingCols = strOrNull(body.griddingCols);
  if (body.customSplit !== undefined) view.customSplit = Number(body.customSplit);
  if (Array.isArray(body.windowLayout)) view.windowLayout = body.windowLayout;
  if (Array.isArray(body.windowData)) view.windowData = body.windowData;
  saveViewsToDisk();
  return { viewCode: view.viewCode, viewName: view.viewName };
}

// PUT monitor/view/{code}/rename -> RenameViewXo {viewName}
export function renameView(code, body = {}) {
  const view = VIEWS.get(String(code));
  if (!view) return null;
  if (body.viewName !== undefined) view.viewName = String(body.viewName);
  saveViewsToDisk();
  return { viewCode: view.viewCode, viewName: view.viewName };
}

// POST monitor/view/delete/batch -> DeleteViewXo {viewCodes}
export function batchDeleteView(body = {}) {
  const codes = [].concat(body.viewCodes || body.codes || []).filter(Boolean).map(String);
  let removed = 0;
  for (const code of codes) {
    if (!VIEWS.has(code)) continue;
    VIEWS.delete(code);
    for (const dir of VIEW_DIRS.values()) {
      dir.viewCodes = (dir.viewCodes || []).filter((c) => c !== code);
    }
    removed += 1;
  }
  if (removed) saveViewsToDisk();
  return { success: true, removed, total: removed, results: [] };
}

// POST monitor/view/share -> ShareViewXo {shareViewCode, sharedUserId, remark}
export function shareView(body = {}) {
  const code = String(body.shareViewCode || '');
  const view = VIEWS.get(code);
  if (!view) return { error: 'shareViewCode not found' };
  const shareId = nextCode('SH');
  const record = {
    shareId,
    sharedViewCode: code,
    shareUserName: String(body.sharedUserName || body.sharedUserId || ''),
    shareTime: new Date().toISOString(),
    remark: String(body.remark || '')
  };
  SHARES.set(shareId, record);
  saveViewsToDisk();
  return record;
}

// POST monitor/view/share/ack
export function ackShareView(body = {}) {
  const code = String(body.sharedViewCode || body.shareViewCode || '');
  let acked = 0;
  for (const rec of SHARES.values()) {
    if (!code || rec.sharedViewCode === code) { rec.acked = true; acked += 1; }
  }
  if (acked) saveViewsToDisk();
  return { success: true, acked, total: acked };
}

// GET monitor/view/share/{code} -> ViewShareRecordVo
export function buildShareViewPayload(code) {
  const rec = [...SHARES.values()].find((r) => r.sharedViewCode === String(code));
  if (!rec) return null;
  return {
    sharedViewCode: rec.sharedViewCode,
    shareUserName: rec.shareUserName,
    shareTime: rec.shareTime,
    remark: rec.remark
  };
}

// GET monitor/view/share/unread/list -> ResultsVo<UnreadViewVo>
export function buildUnreadShareViewsPayload() {
  const results = [];
  for (const rec of SHARES.values()) {
    if (rec.acked) continue;
    const view = VIEWS.get(rec.sharedViewCode);
    if (!view) continue;
    results.push({ viewCode: view.viewCode, viewName: view.viewName });
  }
  return {
    results,
    list: results,
    items: results,
    pUnreadShareViewInfo: results,
    total: results.length,
    totalCount: results.length
  };
}
