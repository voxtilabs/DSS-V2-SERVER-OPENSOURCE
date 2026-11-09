// ===== E-135: RAICES DE SUBSISTEMA FALTANTES (capa 4) ====================
//
// Evidencia (rea-gap-server.md CAPA 2, PROLogic.dll @0x722618-0x722720):
//   /faceService /OBMS /admin/API /emap/api /otms/api /OTMS/API /ecos/api
//   /alarmProcess /brms/api /vehicleServer /emapService /psib /iams/api
//   /erms/api /omms/api /cfgs/api /obms/api /ipms/api + /IPMS/API/ @0x722b88
// El gateway solo cubria /brms/api, /admin/API, /emap/api y /omms/api; el
// resto caia en el catch-all [FALLBACK] (40B) -> el cliente native reporting
// "data abnormal".
//
// Este modulo REGISTRA esas raices con un dispatcher GENERICO al catalogo RPC
// (capa 3, e135-rpc-catalog.js): GET + POST, 2 y 3 segmentos, y las rutas
// versionadas /brms/api/v1.0|v1.1/:sub/:cls/:fn y /brms/api/v1.x/:sub/:fn.
//
// REGLA DURA: toda ruta registrada responde HTTP 200 con envelope
// {code:1000, desc, method, info, data} - nunca 404, nunca el catch-all 40B.
import { handleRpcRequest, resolveRequestMethod, buildRpcPayload, rpcEnvelope, catalogKnown, requestBody } from './e135-rpc-catalog.js';

/**
 * Raices reales del DSS Server V8 (PROLogic.dll pool) + alias de namespace
 * usado para resolver el metodo canonico del catalogo.
 */
export const ROOTS = [
  { path: '/obms/api', alias: 'OBMS', label: 'OBMS access-control/ACS/person/door/lift/alarmhost' },
  { path: '/ipms/api', alias: 'IPMS', label: 'IPMS vehicle/parking/entrance/UVSS/layer' },
  { path: '/omms/api', alias: 'OMMS', label: 'OMMS device/alert/net-switch' },
  { path: '/emap/api', alias: 'EMAP', label: 'EMAP raster/vector' },
  { path: '/emapService', alias: 'emap', label: 'EMAP service' },
  { path: '/arms/api', alias: 'arms', label: 'ARMS = AI label/model (arms.label.addLabel @0xc74a90)' },
  { path: '/otms/api', alias: 'OTMS', label: 'OTMS' },
  { path: '/OTMS/API', alias: 'OTMS', label: 'OTMS (upper)' },
  { path: '/iams/api', alias: 'IAMS', label: 'IAMS' },
  { path: '/erms/api', alias: 'ERMS', label: 'ERMS' },
  { path: '/ecos/api', alias: 'ECOS', label: 'ECOS' },
  { path: '/vehicleServer', alias: 'vehicle', label: 'vehicleServer' },
  { path: '/psib', alias: 'psib', label: 'PSIB' },
  { path: '/faceService', alias: 'face', label: 'faceService' },
  { path: '/alarmProcess', alias: 'aps', label: 'alarmProcess' },
  { path: '/cfgs/api', alias: 'CFGS', label: 'CFGS runtime check' }
];

/** Raices versionadas bajo /brms/api (BRM/BRMS/<ns>/<fn> 2 y 3 segmentos) */
export const VERSIONED_ROOTS = [
  { path: '/brms/api/v1.0', alias: 'BRMS', label: 'BRMS v1.0' },
  { path: '/brms/api/v1.1', alias: 'BRMS', label: 'BRMS v1.1' }
];

/** Todas las rutas (raiz + versionadas) que registra el dispatcher generico. */
export function rootRoutes() {
  const out = [];
  for (const root of [...ROOTS, ...VERSIONED_ROOTS]) {
    out.push({ url: `${root.path}/:sub/:fn`, root, segments: 2, label: root.label });
    out.push({ url: `${root.path}/:sub/:cls/:fn`, root, segments: 3, label: root.label });
  }
  return out;
}

/**
 * Handler generico de una raiz: resuelve el metodo (body.method o URL) y
 * devuelve SIEMPRE un envelope code 1000 con las claves de familia/P0.
 */
export function makeRootHandler(root) {
  const alias = (root && root.alias) || '';
  return async function rootHandler(req) {
    const method = resolveRequestMethod(req, alias);
    const payload = buildRpcPayload(method, requestBody(req));
    return rpcEnvelope(method, payload);
  };
}

/**
 * register(app, ctx)
 * Registra todas las raices faltantes (GET + POST, 2 y 3 segmentos).
 * Las duplicadas con index.js se saltan sin abortar el boot.
 */
export function register(app, ctx = {}) {
  let added = 0;
  let skipped = 0;
  const routes = rootRoutes();
  for (const r of routes) {
    const handler = makeRootHandler(r.root);
    for (const verb of ['get', 'post']) {
      try {
        app[verb](r.url, handler);
        added++;
      } catch {
        skipped++;
      }
    }
  }
  if (ctx && typeof ctx === 'object') {
    ctx.e135Roots = { roots: ROOTS, versioned: VERSIONED_ROOTS, routes, makeRootHandler };
    if (typeof ctx.e135RpcHandler !== 'function') {
      ctx.e135RpcHandler = (req) => handleRpcRequest(req);
    }
  }
  console.log(`[E135-ROOTS] roots=${ROOTS.length + VERSIONED_ROOTS.length} routes registered=${added} skipped(dup)=${skipped}`);
  return { added, skipped, roots: ROOTS.length + VERSIONED_ROOTS.length };
}

export default { register, ROOTS, VERSIONED_ROOTS, rootRoutes, makeRootHandler };
