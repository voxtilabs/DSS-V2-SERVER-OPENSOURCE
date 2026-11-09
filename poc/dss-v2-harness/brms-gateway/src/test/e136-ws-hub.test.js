// E-136: hub WebSocket MSG.exe (subscribe/unsubscribe por methods[]).
//
// No abre sockets reales: se usa un doble de WebSocket y, para el parche de
// integracion, una instancia real de `ws` (WebSocketServer) sin escuchar en
// ningun puerto. Ningun proceso toca el puerto 11443 -> no hay carrera con
// brms.test.js.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { WebSocketServer } from 'ws';

import {
  createWsHub, parseWsFrame, normalizeMethodItem,
  patchWebSocketServer, unpatchWebSocketServer, register
} from '../e136-ws-hub.js';

/** Doble de WebSocket: guarda lo enviado y permite emitir 'message'. */
function fakeWs() {
  const sent = [];
  const listeners = new Map();
  return {
    readyState: 1,
    sent,
    on(event, fn) {
      if (!listeners.has(event)) listeners.set(event, []);
      listeners.get(event).push(fn);
      return this;
    },
    emit(event, ...args) {
      for (const fn of listeners.get(event) || []) fn(...args);
      return true;
    },
    send(data) {
      sent.push(typeof data === 'string' ? JSON.parse(data) : data);
    },
    close() { this.readyState = 3; this.emit('close'); }
  };
}

describe('E-136 parseo de frames MSG.exe', () => {
  it('forma A: {"subscribe":{"methods":[...]}}', () => {
    const p = parseWsFrame(JSON.stringify({
      subscribe: { methods: [{ method: 'vms.alarm.msg', name: 'Alarm' }] },
      siteSessionId: 's-1'
    }));
    assert.equal(p.ok, true);
    assert.equal(p.kind, 'subscribe');
    assert.equal(p.siteSessionId, 's-1');
    assert.deepEqual(p.methods, [{ method: 'vms.alarm.msg', name: 'Alarm' }]);
  });

  it('forma B: {"hub":"methods","method":"subscribe","methods":[...]}', () => {
    const p = parseWsFrame(JSON.stringify({
      hub: 'methods', method: 'subscribe',
      methods: [{ method: 'brms.notifyAlarms' }], siteSessionId: 's-2'
    }));
    assert.equal(p.ok, true);
    assert.equal(p.kind, 'subscribe');
    assert.equal(p.hub, 'methods');
    assert.deepEqual(p.methods, [{ method: 'brms.notifyAlarms', name: 'brms.notifyAlarms' }]);
  });

  it('unsubscribe en las dos formas', () => {
    const a = parseWsFrame(JSON.stringify({ unsubscribe: { methods: [{ method: 'x' }] } }));
    assert.equal(a.ok, true);
    assert.equal(a.kind, 'unsubscribe');
    const b = parseWsFrame(JSON.stringify({ hub: 'methods', method: 'unsubscribe', methods: ['x'] }));
    assert.equal(b.ok, true);
    assert.equal(b.kind, 'unsubscribe');
    assert.deepEqual(b.methods, [{ method: 'x', name: 'x' }]);
  });

  it('rechaza methods que no es un array con el texto real de MSG.exe', () => {
    const p = parseWsFrame(JSON.stringify({ subscribe: { methods: 'nope' } }));
    assert.equal(p.ok, false);
    assert.equal(p.error, "'methods' value is not a array");
    assert.equal(p.kind, 'subscribe');
  });

  it('rechaza JSON invalido y frames desconocidos', () => {
    const bad = parseWsFrame('{no-json');
    assert.equal(bad.ok, false);
    assert.equal(bad.error, 'invalid json frame');
    const unknown = parseWsFrame(JSON.stringify({ hello: 'world' }));
    assert.equal(unknown.ok, false);
    assert.equal(unknown.error, 'unknown frame');
  });

  it('normalizeMethodItem acepta string u objeto', () => {
    assert.deepEqual(normalizeMethodItem('a'), { method: 'a', name: 'a' });
    assert.deepEqual(normalizeMethodItem({ method: 'a', name: 'b' }), { method: 'a', name: 'b' });
    assert.equal(normalizeMethodItem({}), null);
    assert.equal(normalizeMethodItem(null), null);
  });
});

describe('E-136 hub WS', () => {
  it('attach + subscribe -> ACK con methods y siteSessionId', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    const session = hub.attach(ws, {});
    assert.ok(session, 'sesion creada');
    assert.equal(hub.size, 1);

    ws.emit('message', Buffer.from(JSON.stringify({
      subscribe: { methods: [{ method: 'vms.alarm.msg', name: 'Alarm' }] },
      siteSessionId: 'sess-abc'
    })), false);

    assert.equal(ws.sent.length, 1);
    const ack = ws.sent[0];
    assert.equal(ack.type, 'ACK');
    assert.equal(ack.method, 'subscribe');
    assert.equal(ack.success, true);
    assert.equal(ack.siteSessionId, 'sess-abc');
    assert.deepEqual(ack.methods, [{ method: 'vms.alarm.msg', name: 'vms.alarm.msg' }]);

    const subs = hub.subscriptions();
    assert.equal(subs.length, 1);
    assert.deepEqual(subs[0].methods, ['vms.alarm.msg']);
  });

  it('los frames BINARIOS se ignoran (MSG.exe: "Unsupport!!!")', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    ws.emit('message', Buffer.from([1, 2, 3]), true);
    assert.equal(ws.sent.length, 0, 'ningun frame binario produce respuesta');
  });

  it('un methods no-array responde ERROR sin romper la sesion', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    ws.emit('message', JSON.stringify({ subscribe: { methods: 42 } }), false);
    assert.equal(ws.sent.length, 1);
    assert.equal(ws.sent[0].type, 'ERROR');
    assert.equal(ws.sent[0].error, "'methods' value is not a array");
    assert.equal(ws.sent[0].success, false);
  });

  it('publishNotify entrega solo a las sesiones suscritas', () => {
    const hub = createWsHub();
    const ws1 = fakeWs();
    const ws2 = fakeWs();
    hub.attach(ws1, {});
    hub.attach(ws2, {});
    ws1.emit('message', JSON.stringify({ hub: 'methods', method: 'subscribe', methods: ['vms.alarm.msg'] }), false);
    ws2.emit('message', JSON.stringify({ hub: 'methods', method: 'subscribe', methods: ['brms.notifyAlarms'] }), false);
    ws1.sent.length = 0;
    ws2.sent.length = 0;

    const sent = hub.publishNotify('vms.alarm.msg', { alarmCode: 'A1' });
    assert.equal(sent, 1, 'solo la sesion suscrita');
    assert.equal(ws1.sent.length, 1);
    assert.equal(ws2.sent.length, 0);
    const frame = ws1.sent[0];
    assert.equal(frame.type, 'NotifyNormalMsg');
    assert.equal(frame.method, 'vms.alarm.msg');
    assert.deepEqual(frame.info, { alarmCode: 'A1' });
  });

  it('NotifyFrequentMsg para el modo frecuente', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    ws.emit('message', JSON.stringify({ method: 'subscribe', methods: ['x'] }), false);
    ws.sent.length = 0;
    hub.publishNotify('x', { a: 1 }, { frequent: true });
    assert.equal(ws.sent[0].type, 'NotifyFrequentMsg');
  });

  it('unsubscribe deja de delivering', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    ws.emit('message', JSON.stringify({ method: 'subscribe', methods: ['m1'] }), false);
    ws.emit('message', JSON.stringify({ method: 'unsubscribe', methods: ['m1'] }), false);
    ws.sent.length = 0;
    assert.equal(hub.publishNotify('m1', {}), 0, 'ya no hay suscriptores');
    assert.equal(hub.subscriptions()[0].methods.length, 0);
  });

  it('siteSessionId enruta el notify a la sesion indicada', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    ws.emit('message', JSON.stringify({ method: 'subscribe', methods: ['m'], siteSessionId: 'S9' }), false);
    ws.sent.length = 0;
    hub.publishNotify('m', { x: 1 }, { siteSessionId: 'S9' });
    assert.equal(ws.sent.length, 1);
    assert.equal(ws.sent[0].siteSessionId, 'S9');
  });

  it('la sesion se borra al cerrar el socket', () => {
    const hub = createWsHub();
    const ws = fakeWs();
    hub.attach(ws, {});
    assert.equal(hub.size, 1);
    ws.close();
    assert.equal(hub.size, 0);
  });
});

describe('E-136 integracion con el servidor WS de index.js', () => {
  after(() => { unpatchWebSocketServer(); });

  it('el parche de WebSocketServer.prototype.on engancha el hub al "connection"', () => {
    const hub = createWsHub();
    const patched = patchWebSocketServer(hub);
    assert.equal(patched, true, 'el parche se aplica una sola vez');

    // index.js hace exactamente esto: new WebSocketServer(...) + wss.on('connection', ...)
    const wss = new WebSocketServer({ noServer: true });
    const seen = [];
    wss.on('connection', (ws) => { seen.push(ws); });
    const ws = fakeWs();
    wss.emit('connection', ws, { url: '/brms/api/v1.0/event/ws' });

    assert.equal(seen.length, 1, 'el listener original de index.js sigue intacto');
    assert.equal(hub.size, 1, 'E-136 tambien recibio la conexion');
    const session = hub.subscriptions()[0];
    assert.ok(session, 'sesion registrada');

    // el frame de subscribe llega al hub
    ws.emit('message', JSON.stringify({ hub: 'methods', method: 'subscribe', methods: ['vms.alarm.msg'] }), false);
    assert.equal(ws.sent.length, 1);
    assert.equal(ws.sent[0].type, 'ACK');
    assert.deepEqual(hub.subscriptions()[0].methods, ['vms.alarm.msg']);

    try { wss.close(); } catch { /* noServer */ }
  });

  it('register(app, ctx) expone el hub en ctx y es idempotente', () => {
    const ctx = {};
    const hub = register({}, ctx);
    assert.ok(hub && typeof hub.publishNotify === 'function');
    assert.equal(ctx.e136WsHub, hub);
    assert.equal(ctx.e136.wsHub, hub);
  });

  it('register(app, ctx) respeta un hub ya existente', () => {
    const mine = createWsHub();
    const ctx = { e136WsHub: mine };
    const hub = register({}, ctx);
    assert.equal(hub, mine);
  });
});

describe('E-136 hub sin patch (EventEmitter puro)', () => {
  it('attachServer registra el listener de connection de un wss existente', () => {
    const hub = createWsHub();
    const wss = new EventEmitter();
    assert.equal(hub.attachServer(wss), true);
    const ws = fakeWs();
    wss.emit('connection', ws, {});
    assert.equal(hub.size, 1);
  });
});
