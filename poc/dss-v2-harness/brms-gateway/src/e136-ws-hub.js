// ===== E-136: hub WebSocket MSG.exe (subscribe/unsubscribe por methods[]) ===
//
// Que resuelve: MSG.exe (el cliente de notificaciones del DSS 8.006) habla
// WebSocket CON un hub de suscripciones por METODO. El gateway solo
// respondia `{type:'WELCOME'}` (index.js:3197) y registraba los frames
// entrantes en el log -> el cliente native nunca recibia notify y el Event
// Center se quedaba vacio.
//
// Evidencia (MSG.exe, pool de strings):
//   'subscribe'    @0x1f8978
//   'unsubscribe'  @0x1f8988
//   'methods'      @0x1f89b8  (error real: "'methods' value is not a array")
//   'siteSessionId'@0x1f8bd8
//   'NotifyNormalMsg' @0x1f8b80
//   'NotifyFrequentMsg' @0x1f8be8
//   frames SOLO texto (Text @0x1f8338; Binary -> "Unsupport!!!" @0x1f8350)
//
// Formas de frame admitidas (las dos observadas):
//   A) {"subscribe":{"methods":[{"method":"x","name":"x"}]},"siteSessionId":"s1"}
//   B) {"hub":"methods","method":"subscribe","methods":[...],"siteSessionId":"s1"}
//
// INTEGRACION SIN TOCAR index.js: se parchea `WebSocketServer.prototype.on`
// para que, cuando index.js registra su listener de 'connection', tambien se
// registre el de E-136 (antes). `ws` es una dependencia del proyecto, asi que
// ambos modulos comparten la MISMA clase y el parche es efectivo.
import { EventEmitter } from 'node:events';
import { WebSocketServer } from 'ws';

const str = (v) => (v === undefined || v === null ? '' : String(v));

// ---------------------------------------------------------------------------
// PARSER DE FRAMES
// ---------------------------------------------------------------------------
/** Normaliza una entrada de `methods[]` a {method, name}. */
export function normalizeMethodItem(item) {
  if (typeof item === 'string') return item ? { method: item, name: item } : null;
  if (!item || typeof item !== 'object') return null;
  const method = str(item.method ?? item.name ?? item.methodName ?? item.type);
  if (!method) return null;
  return { method, name: str(item.name ?? item.methodName ?? method) };
}

/**
 * Parsea un frame entrante de MSG.exe.
 * @returns {{ok:boolean, kind:string, methods:Array, siteSessionId:string, error?:string}}
 */
export function parseWsFrame(raw) {
  const bad = (error, extra = {}) => ({
    ok: false, error, kind: 'unknown', methods: [], siteSessionId: '', ...extra
  });
  let msg;
  try {
    const text = typeof raw === 'string' ? raw : Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw);
    msg = JSON.parse(text);
  } catch {
    return bad('invalid json frame');
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return bad('invalid frame');

  const siteSessionId = str(msg.siteSessionId ?? msg.site_session_id ?? msg.sessionId ?? '');
  let kind = '';
  let rawMethods = msg.methods;

  if (msg.subscribe && typeof msg.subscribe === 'object') {
    kind = 'subscribe';
    rawMethods = msg.subscribe.methods ?? rawMethods;
  } else if (msg.unsubscribe && typeof msg.unsubscribe === 'object') {
    kind = 'unsubscribe';
    rawMethods = msg.unsubscribe.methods ?? rawMethods;
  } else if (str(msg.hub).toLowerCase() === 'methods') {
    kind = str(msg.method).toLowerCase();
    rawMethods = msg.methods;
  } else {
    const m = str(msg.method).toLowerCase();
    if (m === 'subscribe' || m === 'unsubscribe') {
      kind = m;
      rawMethods = msg.methods;
    }
  }
  if (kind !== 'subscribe' && kind !== 'unsubscribe') return bad('unknown frame', { siteSessionId });

  // Contrato real de MSG.exe: methods DEBE ser un array.
  if (rawMethods !== undefined && rawMethods !== null && !Array.isArray(rawMethods)) {
    return bad("'methods' value is not a array", { kind, siteSessionId });
  }
  const methods = (Array.isArray(rawMethods) ? rawMethods : [])
    .map(normalizeMethodItem)
    .filter(Boolean);
  return { ok: true, kind, methods, siteSessionId, hub: str(msg.hub ?? 'methods') };
}

// ---------------------------------------------------------------------------
// HUB
// ---------------------------------------------------------------------------
/**
 * Hub de suscripciones WS.
 * @param {object} opts
 * @param {Set} [opts.wsClients]  sockets legacy (e039 los publica a pelo)
 * @param {Function} [opts.publish]  callback extra al publicar (notify)
 */
export function createWsHub({ wsClients = null, publish = null } = {}) {
  /** @type {Map<object, object>} ws -> sesion */
  const sessions = new Map();
  let sessionSeq = 0;

  function send(ws, frame) {
    if (!ws || ws.readyState !== undefined && ws.readyState !== 1) return false;
    try {
      ws.send(typeof frame === 'string' ? frame : JSON.stringify(frame));
      return true;
    } catch (err) {
      console.error('[E136-WS] send failed:', err.message);
      return false;
    }
  }

  /** Registra una conexion y engancha su listener de 'message'. */
  function attach(ws, req = {}) {
    if (!ws) return null;
    const existing = sessions.get(ws);
    if (existing) return existing;
    sessionSeq += 1;
    const session = {
      id: `sess-${sessionSeq}`,
      ws,
      req,
      siteSessionId: '',
      methods: new Set(),
      subscribedAt: new Date().toISOString()
    };
    sessions.set(ws, session);
    // MSG.exe: solo frames de texto (Binary -> "Unsupport!!!").
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      handleRaw(session, data);
    });
    ws.on('close', () => { sessions.delete(ws); });
    ws.on('error', () => { sessions.delete(ws); });
    return session;
  }

  /** Engancha un WebSocketServer existente (si el supervisor lo pasa). */
  function attachServer(wss) {
    if (!wss || typeof wss.on !== 'function') return false;
    wss.on('connection', (ws, req) => attach(ws, req));
    return true;
  }

  /** Procesa un frame crudo y devuelve el parseo. */
  function handleRaw(session, data) {
    const parsed = parseWsFrame(data);
    if (!parsed.ok) {
      send(session.ws, {
        type: 'ERROR',
        hub: 'methods',
        method: parsed.kind === 'unknown' ? '' : parsed.kind,
        error: parsed.error,
        errorMsg: parsed.error,
        result: '0',
        code: 1,
        success: false,
        siteSessionId: parsed.siteSessionId || session.siteSessionId
      });
      return parsed;
    }
    if (parsed.siteSessionId) session.siteSessionId = parsed.siteSessionId;
    if (parsed.kind === 'subscribe') {
      for (const m of parsed.methods) session.methods.add(m.method);
    } else {
      for (const m of parsed.methods) session.methods.delete(m.method);
    }
    const methods = [...session.methods].map((m) => ({ method: m, name: m }));
    send(session.ws, {
      type: 'ACK',
      hub: parsed.hub || 'methods',
      method: parsed.kind,
      result: '1',
      code: 1000,
      desc: 'Success',
      success: true,
      siteSessionId: session.siteSessionId,
      methods,
      subscribed: methods
    });
    return parsed;
  }

  /** Envia un notify a las sesiones suscritas a ese metodo. */
  function publishNotify(method, info = {}, { frequent = false, siteSessionId = '' } = {}) {
    const frame = {
      type: frequent ? 'NotifyFrequentMsg' : 'NotifyNormalMsg',
      method: str(method),
      info,
      data: info,
      siteSessionId: str(siteSessionId),
      timestamp: new Date().toISOString()
    };
    let sent = 0;
    for (const session of sessions.values()) {
      if (!session.methods.has(frame.method)) continue;
      if (siteSessionId && session.siteSessionId && session.siteSessionId !== siteSessionId) continue;
      if (send(session.ws, frame)) sent += 1;
    }
    if (publish) {
      try { publish(frame); } catch (err) { console.error('[E136-WS] publish hook failed:', err.message); }
    }
    return sent;
  }

  /** Broadcast sin filtro de suscripcion (uso del supervisor). */
  function broadcast(frame) {
    let sent = 0;
    for (const session of sessions.values()) if (send(session.ws, frame)) sent += 1;
    if (wsClients) {
      for (const ws of wsClients) if (send(ws, frame)) sent += 1;
    }
    return sent;
  }

  /** Suscripciones actuales por siteSessionId (introspeccion/tests). */
  function subscriptions() {
    const out = [];
    for (const session of sessions.values()) {
      out.push({
        sessionId: session.id,
        siteSessionId: session.siteSessionId,
        methods: [...session.methods]
      });
    }
    return out;
  }

  function close() {
    sessions.clear();
  }

  return {
    attach, attachServer, handleRaw, publishNotify, broadcast,
    subscriptions, close, send,
    get sessions() { return sessions; },
    get size() { return sessions.size; }
  };
}

// ---------------------------------------------------------------------------
// PARCHE DEL SERVIDOR WS (integracion sin editar index.js)
// ---------------------------------------------------------------------------
let patched = false;
/** Hub al que enruta el listener inyectado (puede cambiar sin re-patchear). */
let patchedHub = null;

/**
 * Parchea `WebSocketServer.prototype.on` para registrar tambien el listener
 * de 'connection' de E-136. Devuelve false si ya estaba parcheado (en ese caso
 * solo se actualiza el hub destino, de modo que un segundo `register()` con
 * otro hub siga funcionando).
 */
export function patchWebSocketServer(hub) {
  if (patched) {
    patchedHub = hub || patchedHub;
    return false;
  }
  const proto = WebSocketServer && WebSocketServer.prototype;
  if (!proto) return false;
  patchedHub = hub || null;
  const originalOn = EventEmitter.prototype.on;
  Object.defineProperty(proto, 'on', {
    configurable: true,
    writable: true,
    enumerable: false,
    value(event, listener) {
      if (event === 'connection') {
        // Se registra ANTES del listener de index.js: asi el hub ve el frame
        // de subscribe aunque el cliente lo envie de inmediato.
        originalOn.call(this, 'connection', (ws, req) => {
          try {
            if (patchedHub) patchedHub.attach(ws, req);
          } catch (err) {
            console.error('[E136-WS] attach failed:', err.message);
          }
        });
      }
      return originalOn.call(this, event, listener);
    }
  });
  patched = true;
  return true;
}

/** Restaura el metodo original (solo para tests). */
export function unpatchWebSocketServer() {
  if (!patched) return false;
  delete WebSocketServer.prototype.on;
  patched = false;
  patchedHub = null;
  return true;
}

// ---------------------------------------------------------------------------
// REGISTRO
// ---------------------------------------------------------------------------
const INSTALLED = Symbol.for('e136.wshub.installed');

/**
 * register(app, ctx)
 * @param {object} app
 * @param {object} ctx  { wsClients, wss, e136WsHub, publish }
 */
export function register(app, ctx = {}) {
  const obj = ctx && typeof ctx === 'object' ? ctx : {};
  let hub = obj.e136WsHub;
  if (!hub || typeof hub.publishNotify !== 'function') {
    hub = createWsHub({
      wsClients: obj.wsClients || obj.WS_CLIENTS || null,
      publish: typeof obj.publish === 'function' ? obj.publish : null
    });
  }
  if (obj.wss && typeof obj.wss.on === 'function') hub.attachServer(obj.wss);
  const patched = patchWebSocketServer(hub);
  if (app && !app[INSTALLED]) app[INSTALLED] = hub;
  if (obj && typeof obj === 'object') {
    obj.e136 = { ...(obj.e136 || {}), wsHub: hub };
    if (!obj.e136WsHub) obj.e136WsHub = hub;
  }
  console.log(`[E136-WS] hub listo (ws-patch=${patched}, sesiones=${hub.size})`);
  return hub;
}

export default {
  register, createWsHub, parseWsFrame, normalizeMethodItem,
  patchWebSocketServer, unpatchWebSocketServer
};
