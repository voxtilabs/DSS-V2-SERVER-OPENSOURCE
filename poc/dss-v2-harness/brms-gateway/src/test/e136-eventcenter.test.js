// E-136: backend del Event Center (RPC BRMS.* + REST pull-queue).
//
// Pure-module + Fastify `app.inject()`: NO se levanta ningun servidor ni se
// escribe en data/*.json (se usa un directorio temporal propio), asi que no
// hay carrera con brms.test.js (que levanta el gateway en el puerto 11443).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify from 'fastify';

import {
  register, createE136Stores, createEventCenterQueue, canonicalRpcKey,
  bodyData, rpcEnvelope, defaultEnvelope, restKey, RPC_HANDLERS, REST_HANDLERS,
  buildEventCenterSubscribePayload, buildRightsNodesPayload
} from '../e136-eventcenter.js';
import { ALARM_PLAN_FIELDS, ALARM_PLAN_LINK_FIELDS } from '../e136-admin-store.js';

const TMP_ROOT = path.join(os.tmpdir(), 'opencode', 'e136-ec-test');
let tmpDir = '';

before(() => {
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  tmpDir = fs.mkdtempSync(path.join(TMP_ROOT, 'run-'));
});

after(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
});

let storeSeq = 0;
function makeStores() {
  // Directorio PROPIO por store: los tests no comparten estado persistido.
  storeSeq += 1;
  const dir = path.join(tmpDir, `stores-${storeSeq}`);
  fs.mkdirSync(dir, { recursive: true });
  return createE136Stores({ dataDir: dir, persist: true });
}

describe('E-136 helpers de contrato', () => {
  it('canonicalRpcKey normaliza BRM./BRMS./slashes', () => {
    assert.equal(canonicalRpcKey('BRMS.Alarm.GetPageAlarmRecords'), 'Alarm.GetPageAlarmRecords');
    assert.equal(canonicalRpcKey('BRM.BRMS.Alarm.GetPageAlarmRecords'), 'Alarm.GetPageAlarmRecords');
    assert.equal(canonicalRpcKey('BRM/Alarm/GetPageAlarmRecords'), 'Alarm.GetPageAlarmRecords');
    assert.equal(canonicalRpcKey('v1.1/BRMS.Alarm.GetPageAlarmRecords'), 'Alarm.GetPageAlarmRecords');
    assert.equal(canonicalRpcKey(''), '');
  });

  it('bodyData extrae data/info del body RPC', () => {
    assert.deepEqual(bodyData({ method: 'X', data: { a: 1 } }), { a: 1 });
    assert.deepEqual(bodyData({ method: 'X', info: { b: 2 } }), { b: 2 });
    assert.deepEqual(bodyData({ method: 'X', c: 3 }), { method: 'X', c: 3 }, 'sin data/info devuelve el body');
    assert.deepEqual(bodyData(null), {});
  });

  it('rpcEnvelope usa la forma de index.js (code 1000 + method/info/data)', () => {
    const env = rpcEnvelope('BRMS.Alarm.GetPageAlarmRecords', { total: 1 });
    assert.equal(env.code, 1000);
    assert.equal(env.desc, 'Success');
    assert.equal(env.method, 'BRMS.Alarm.GetPageAlarmRecords');
    assert.deepEqual(env.info, { total: 1 });
    assert.deepEqual(env.data, { total: 1 });
  });

  it('restKey recorta la raiz REST', () => {
    assert.equal(restKey('/brms/api/v1.1/alarmBusiness/alarmList'), 'alarmBusiness/alarmList');
    assert.equal(restKey('/videoService/eventCenter/messages/subscribe'), 'eventCenter/messages/subscribe');
    assert.equal(restKey('/admin/API/Rights/Nodes'), 'Rights/Nodes');
    assert.equal(restKey('/brms/api/v1.1/v1.1/alarm/handle/batch'), 'alarm/handle/batch');
  });
});

describe('E-136 handlers RPC del Event Center', () => {
  it('BRMS.Alarm.GetPageAlarmRecords pagina y filtra', () => {
    const s = makeStores();
    s.alarms.replaceAll([
      { alarmCode: 'A1', deviceCode: 'D1', alarmTypeId: '2', alarmTime: '2026-11-01T10:00:00.000Z' },
      { alarmCode: 'A2', deviceCode: 'D2', alarmTypeId: '13', alarmTime: '2026-11-02T10:00:00.000Z' }
    ]);
    const p = RPC_HANDLERS['Alarm.GetPageAlarmRecords'](s, { data: { page: 1, pageSize: 10 } });
    assert.equal(p.total, 2);
    assert.equal(p.totalCount, 2);
    assert.equal(p.records.length, 2);
    assert.ok(Array.isArray(p.list) && Array.isArray(p.results));
    const filtered = RPC_HANDLERS['Alarm.GetPageAlarmRecords'](s, { data: { alarmTypes: ['13'] } });
    assert.equal(filtered.total, 1);
    assert.equal(filtered.records[0].alarmCode, 'A2');
  });

  it('BRM/Alarm/HandleAlarm devuelve handleStatus/comment/mailReceivers/alarmDate', () => {
    const s = makeStores();
    s.alarms.replaceAll([{ alarmCode: 'A1', deviceCode: 'D1' }]);
    const p = RPC_HANDLERS['Alarm.HandleAlarm'](s, {
      data: {
        alarmCode: 'A1', deviceCode: 'D1', alarmDate: '2026-11-01 10:00:00',
        handleUser: 'admin', handleMessage: 'ok', comment: 'nota',
        mailReceivers: ['a@b.c'], handleStatus: '1'
      }
    });
    assert.equal(p.success, true);
    assert.equal(p.handleStatus, '1');
    assert.equal(p.comment, 'nota');
    assert.deepEqual(p.mailReceivers, ['a@b.c']);
    assert.equal(p.alarmDate, '2026-11-01 10:00:00');
    assert.equal(p.alarmCode, 'A1');
    assert.equal(s.alarms.get('A1').handleStatus, '1', 'el store se actualiza');
  });

  it('BRMS.Alarm.BatchHandleAlarms devuelve alarms[] y confirma en lote', () => {
    const s = makeStores();
    s.alarms.replaceAll([{ alarmCode: 'A1' }, { alarmCode: 'A2' }]);
    const p = RPC_HANDLERS['Alarm.BatchHandleAlarms'](s, {
      data: { alarms: [{ alarmCode: 'A1' }, { alarmCode: 'A2' }], handleUser: 'admin', handleMessage: 'lote' }
    });
    assert.equal(p.count, 2);
    assert.deepEqual(p.handled, ['A1', 'A2']);
    assert.equal(p.handleUser, 'admin');
    assert.equal(s.alarms.get('A2').handleStatus, '1');
  });

  it('BRMS.Alarm.ExportAlarmRecords devuelve exportType/customColumns', () => {
    const s = makeStores();
    const p = RPC_HANDLERS['Alarm.ExportAlarmRecords'](s, {
      data: { exportType: '1', customColumns: ['alarmCode', 'deviceCode'], credence: '1' }
    });
    assert.equal(p.exportType, '1');
    assert.deepEqual(p.customColumns, ['alarmCode', 'deviceCode']);
    assert.equal(p.credence, '1');
    assert.ok(p.fileName, 'exportFileVo con nombre');
  });

  it('BRMS.Alarm.DisarmAlarm devuelve duration/unit/abortTime/remark', () => {
    const s = makeStores();
    s.alarms.replaceAll([{ alarmCode: 'A1', alarmTypeId: '2' }]);
    const p = RPC_HANDLERS['Alarm.DisarmAlarm'](s, {
      data: { alarmTypeId: '2', duration: '30', unit: '1', abortTime: '2026-11-01T11:00:00.000Z', remark: 'mantenimiento' }
    });
    assert.equal(p.duration, '30');
    assert.equal(p.unit, '1');
    assert.equal(p.abortTime, '2026-11-01T11:00:00.000Z');
    assert.equal(p.remark, 'mantenimiento');
  });

  it('BRMS.AlarmPlan.Add/Update devuelven los 62+ campos y los 13 link*', () => {
    const s = makeStores();
    const p = RPC_HANDLERS['AlarmPlan.AddAlarmPlan'](s, {
      data: { planName: 'P1', alarmTypeId: '2', linkGate: '1', channelIds: ['C1'], sourceCodes: ['S1'] }
    });
    assert.equal(p.success, true);
    for (const f of ALARM_PLAN_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(p, f), `el eco del plan no lleva ${f}`);
    }
    assert.equal(ALARM_PLAN_LINK_FIELDS.length, 13);
    assert.equal(p.linkGate, '1');
    assert.deepEqual(p.channelIds, ['C1']);

    const u = RPC_HANDLERS['AlarmPlan.UpdateAlarmPlan'](s, { data: { planId: p.planId, planName: 'P2' } });
    assert.equal(u.success, true);
    assert.equal(u.planName, 'P2');
    const miss = RPC_HANDLERS['AlarmPlan.UpdateAlarmPlan'](s, { data: { planId: 'nope' } });
    assert.equal(miss.success, false, 'plan inexistente -> success false');
  });

  it('BRMS.AlarmPlan.GetPage/BatchDelete', () => {
    const s = makeStores();
    s.plans.add({ planName: 'A' });
    s.plans.add({ planName: 'B' });
    const page = RPC_HANDLERS['AlarmPlan.GetPageAlarmPlans'](s, { data: { page: 1, pageSize: 10 } });
    assert.equal(page.total, 2);
    const del = RPC_HANDLERS['AlarmPlan.BatchDeleteAlarmPlans'](s, { data: { ids: [page.records[0].planId] } });
    assert.equal(del.deletedCount, 1);
    assert.equal(s.plans.page({}).total, 1);
  });

  it('BRMS.User.* y BRMS.Role.* gestionan usuarios y roles', () => {
    const s = makeStores();
    const u = RPC_HANDLERS['User.AddUser'](s, { data: { username: 'ana', roleIds: ['2'], digestPassword: 'x' } });
    assert.equal(u.success, true);
    assert.equal(u.username, 'ana');
    const up = RPC_HANDLERS['User.UpdateUser'](s, { data: { userId: u.userId, tel: '111' } });
    assert.equal(up.tel, '111');
    const page = RPC_HANDLERS['User.GetPageUsers'](s, { data: { keyword: 'ana' } });
    assert.equal(page.total, 1);
    const r = RPC_HANDLERS['Role.AddRole'](s, { data: { roleName: 'R1', menuCodes: ['001'], functionCodes: ['8'] } });
    assert.equal(r.success, true);
    assert.deepEqual(r.menuCodes, ['001']);
    assert.equal(RPC_HANDLERS['Role.GetPageRoles'](s, { data: {} }).total, 1);
    assert.equal(RPC_HANDLERS['User.DeleteUsers'](s, { data: { ids: [u.userId] } }).deleted, 1);
  });

  it('BRMS.Account.ChangePassword devuelve digestPassword/verification', () => {
    const s = makeStores();
    s.users.add({ username: 'bob', password: 'old' });
    const p = RPC_HANDLERS['Account.ChangePassword'](s, {
      data: { username: 'bob', oldPassword: 'old', newPassword: 'new', digestPassword: 'd', verification: '1' }
    });
    assert.equal(p.success, true);
    assert.equal(p.digestPassword, 'd');
    assert.equal(p.verification, '1');
    assert.equal(s.users.get('bob').password, 'new');
  });

  it('BRMS.AlarmOverview.GetSummary devuelve mode/orgCode/startTime/endTime', () => {
    const s = makeStores();
    s.alarms.replaceAll([{ alarmCode: 'A1', orgCode: '001' }]);
    const p = RPC_HANDLERS['AlarmOverview.GetSummary'](s, {
      data: { mode: '1', orgCode: '001', startTime: '2026-11-01T00:00:00.000Z', endTime: '2026-12-01T00:00:00.000Z' }
    });
    assert.equal(p.mode, '1');
    assert.equal(p.orgCode, '001');
    assert.equal(p.startTime, '2026-11-01T00:00:00.000Z');
    assert.equal(p.endTime, '2026-12-01T00:00:00.000Z');
    assert.equal(p.total, 1);
  });

  it('Rights/Nodes devuelve pUserRightList/menuNodes/functionNodes', () => {
    const p = buildRightsNodesPayload({});
    assert.ok(Array.isArray(p.pUserRightList) && p.pUserRightList.length > 0);
    assert.ok(Array.isArray(p.menuNodes) && p.menuNodes.length > 0);
    assert.ok(Array.isArray(p.functionNodes) && p.functionNodes.length > 0);
    assert.ok(Array.isArray(p.function) && p.function.length > 0);
  });
});

describe('E-136 pull-queue del Event Center', () => {
  it('la cola entrega solo los mensajes nuevos desde initMessageId', () => {
    const q = createEventCenterQueue();
    q.push({ alarmCode: 'A1' });
    q.push({ alarmCode: 'A2' });
    const first = buildEventCenterSubscribePayload(q, { initMessageId: '0', subscribeAddress: 'http://x' });
    assert.equal(first.messages.length, 2);
    assert.equal(first.msgId, '2');
    assert.equal(first.next, '2');
    assert.ok(first.subscribeId, 'subscribeId presente (contrato del cliente)');
    assert.equal(first.subscribeAddress, 'http://x');

    const second = buildEventCenterSubscribePayload(q, { msgId: first.msgId });
    assert.equal(second.messages.length, 0, 'sin mensajes nuevos');
    assert.equal(second.msgId, '2');
  });
});

describe('E-136 integracion Fastify (hook preHandler)', () => {
  /** App que imita las rutas de index.js que E-136 debe SOBRESCRIBIR. */
  async function buildApp() {
    const app = Fastify({ logger: false });
    // catch-all RPC de index.js:1114-1133 (devuelve payload vacio)
    const rpcHandler = async (req) => {
      const b = req.body || {};
      const method = b.method || (req.params.cls
        ? `BRM.${req.params.ns}.${req.params.cls}.${req.params.fn}`
        : `BRM.${req.params.ns}.${req.params.fn}`);
      return { code: 1000, desc: 'Success', method, info: {}, data: {} };
    };
    app.post('/admin/API/BRM/:ns/:fn', rpcHandler);
    app.post('/admin/API/BRM/:ns/:cls/:fn', rpcHandler);
    app.post('/videoService/eventCenter/messages/subscribe', async () => ({ code: 1000, desc: 'Success', data: { stub: true } }));
    app.get('/brms/api/v1.1/alarmBusiness/alarmList', async () => ({ code: 1000, desc: 'Success', data: { stub: true } }));
    app.post('/brms/api/v1.1/alarm/handle/batch', async () => ({ code: 1000, desc: 'Success', data: { stub: true } }));
    app.get('/admin/API/Rights/Nodes', async () => ({ code: 1000, desc: 'Success', data: { stub: true } }));
    const ctx = { stores: makeStores() };
    register(app, ctx);
    return { app, ctx };
  }

  it('intercepta el RPC por URL de 3 segmentos', async () => {
    const { app } = await buildApp();
    const r = await app.inject({
      method: 'POST',
      url: '/admin/API/BRM/BRMS/Alarm/GetPageAlarmRecords',
      payload: { method: 'BRMS.Alarm.GetPageAlarmRecords', data: { page: 1, pageSize: 10 } }
    });
    const j = r.json();
    assert.equal(r.statusCode, 200);
    assert.equal(j.code, 1000);
    assert.equal(j.method, 'BRMS.Alarm.GetPageAlarmRecords');
    assert.ok('total' in j.data, 'payload real, no el catch-all vacio');
    assert.ok('totalCount' in j.data);
    assert.equal(j.data.records.length, 0);
    await app.close();
  });

  it('intercepta el RPC por body.method aunque la URL sea de 2 segmentos', async () => {
    const { app } = await buildApp();
    const r = await app.inject({
      method: 'POST',
      url: '/admin/API/BRM/Alarm/GetPageAlarmRecords',
      payload: { method: 'BRMS.Alarm.GetPageAlarmRecords' }
    });
    const j = r.json();
    assert.ok('total' in j.data);
    assert.equal(j.method, 'BRMS.Alarm.GetPageAlarmRecords');
    await app.close();
  });

  it('NO intercepta metodos ajenos (el handler original sigue mand)', async () => {
    const { app } = await buildApp();
    const r = await app.inject({
      method: 'POST',
      url: '/admin/API/BRM/Config/GetOther',
      payload: { method: 'BRM.Config.GetOther' }
    });
    const j = r.json();
    assert.deepEqual(j.data, {}, 'los metodos no gestionados siguen su camino');
    await app.close();
  });

  it('el pull-queue del Event Center sustituye al stub de index.js', async () => {
    const { app, ctx } = await buildApp();
    const r = await app.inject({
      method: 'POST',
      url: '/videoService/eventCenter/messages/subscribe',
      payload: { subscribeAddress: 'https://h:1443/videoService/eventCenter/messages/subscribe', initMessageId: '0' }
    });
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.ok(j.data.msgId !== undefined, 'msgId presente (contrato brms.test.js)');
    assert.ok(j.data.subscribeId, 'subscribeId presente (contrato brms.test.js)');
    assert.ok(Array.isArray(j.data.messages), 'messages[] de la pull-queue');
    assert.ok('next' in j.data);
    assert.equal(j.data.stub, undefined, 'el stub de index.js fue sustituido');
    await app.close();
  });

  it('alarmBusiness/alarmList y alarm/handle/batch devuelven el store real', async () => {
    const { app, ctx } = await buildApp();
    ctx.e136.stores.alarms.replaceAll([
      { alarmCode: 'A1', deviceCode: 'D1', alarmTypeId: '2', handleStatus: '0' }
    ]);
    const list = await app.inject({ method: 'GET', url: '/brms/api/v1.1/alarmBusiness/alarmList' });
    const lj = list.json();
    assert.equal(lj.data.total, 1);
    assert.equal(lj.data.records[0].alarmCode, 'A1');
    assert.equal(lj.data.stub, undefined, 'el stub de e127 fue sustituido');

    const handle = await app.inject({
      method: 'POST',
      url: '/brms/api/v1.1/alarm/handle/batch',
      payload: { alarms: [{ alarmCode: 'A1' }], handleUser: 'admin', handleMessage: 'ok' }
    });
    const hj = handle.json();
    assert.equal(hj.data.count, 1);
    assert.equal(ctx.e136.stores.alarms.get('A1').handleStatus, '1');
    await app.close();
  });

  it('Rights/Nodes se sirve con menuNodes/functionNodes', async () => {
    const { app } = await buildApp();
    const r = await app.inject({ method: 'GET', url: '/admin/API/Rights/Nodes' });
    const j = r.json();
    assert.ok(Array.isArray(j.data.menuNodes));
    assert.ok(Array.isArray(j.data.functionNodes));
    assert.ok(Array.isArray(j.data.pUserRightList));
    await app.close();
  });

  it('register() es idempotente (no duplica el hook)', async () => {
    const { app } = await buildApp();
    const again = register(app, {});
    assert.equal(again.installed, false, 'la segunda llamada no reinstala el hook');
    await app.close();
  });

  it('acepta ctx como funcion envelope (mismo contrato que e127)', async () => {
    const app = Fastify({ logger: false });
    app.post('/admin/API/BRM/:ns/:fn', async () => ({ code: 1000, desc: 'Success', data: {} }));
    const ctx = { stores: makeStores() };
    const env = (data) => ({ code: 1000, desc: 'Success', data });
    register(app, env);
    const r = await app.inject({
      method: 'POST', url: '/admin/API/BRM/Alarm/GetPageAlarmRecords',
      payload: { method: 'BRMS.Alarm.GetPageAlarmRecords' }
    });
    assert.ok('total' in r.json().data);
    await app.close();
  });
});

describe('E-136 defaultEnvelope', () => {
  it('usa la forma {code, desc, data} de index.js', () => {
    const e = defaultEnvelope({ a: 1 });
    assert.equal(e.code, 1000);
    assert.equal(e.desc, 'Success');
    assert.deepEqual(e.data, { a: 1 });
  });
});
