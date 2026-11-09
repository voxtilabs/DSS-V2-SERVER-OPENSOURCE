// E-136: store persistente de alarmas + planes + usuarios + roles.
//
// IMPORTANTE (igual que e039-notify.test.js): estos tests NUNCA tocan los
// ficheros data/*.json compartidos con el gateway que brms.test.js levanta en
// el puerto 11443. Cada test usa un directorio temporal propio.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  createAlarmStore, normalizeAlarm, ALARM_FIELDS, ALARM_STORE_PATH,
  toArray, toMillis
} from '../e136-alarm-store.js';
import {
  createAlarmPlanStore, createUserStore, createRoleStore,
  ALARM_PLAN_FIELDS, ALARM_PLAN_LINK_FIELDS, USER_FIELDS, ROLE_FIELDS
} from '../e136-admin-store.js';

const TMP_ROOT = path.join(os.tmpdir(), 'opencode', 'e136-store-test');
let tmpDir = '';

function tmpFile(name) {
  return path.join(tmpDir, name);
}

before(() => {
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  tmpDir = fs.mkdtempSync(path.join(TMP_ROOT, 'run-'));
});

after(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
});

function seedAlarms() {
  const store = createAlarmStore({ filePath: tmpFile('alarms.json'), persist: true });
  store.replaceAll([
    {
      alarmCode: 'A1', deviceCode: 'DEV01', channelId: 'DEV01$1$0$0',
      alarmTypeId: '2', alarmType: 'MotionDetection', alarmTime: '2026-11-01T10:00:00.000Z',
      alarmDate: '2026-11-01 10:00:00', orgCode: '001'
    },
    {
      alarmCode: 'A2', deviceCode: 'DEV02', channelId: 'DEV02$1$0$0',
      alarmTypeId: '13', alarmType: 'CrossLineDetection', alarmTime: '2026-11-02T11:00:00.000Z',
      alarmDate: '2026-11-02 11:00:00', orgCode: '001'
    },
    {
      alarmCode: 'A3', deviceCode: 'DEV01', channelId: 'DEV01$1$0$1',
      alarmTypeId: '2', alarmType: 'MotionDetection', alarmTime: '2026-11-03T12:00:00.000Z',
      alarmDate: '2026-11-03 12:00:00', orgCode: 'VIGILAB', handleStatus: '1',
      handleUser: 'admin', handleMessage: 'revisado', handleDate: '2026-11-03T12:30:00.000Z'
    }
  ]);
  return store;
}

describe('E-136 store de alarmas', () => {
  it('normalizeAlarm rellena TODOS los campos del esquema nativo', () => {
    const rec = normalizeAlarm({ alarmCode: 'X', deviceCode: 'D', channelId: 'C' });
    for (const f of ALARM_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(rec, f), `falta el campo ${f}`);
    }
    assert.equal(rec.alarmCode, 'X');
    assert.equal(rec.handleStatus, '0', 'una alarma nueva nace sin confirmar');
    assert.deepEqual(rec.mailReceivers, []);
    assert.ok(rec.alarmTime, 'alarmTime por defecto');
  });

  it('add + page: paginado, orden y total', () => {
    const store = seedAlarms();
    const all = store.page({});
    assert.equal(all.total, 3);
    assert.equal(all.totalCount, 3);
    assert.equal(all.records.length, 3);
    assert.equal(all.records[0].alarmCode, 'A3', 'orden descendente por alarmTime');

    const p1 = store.page({ page: 1, pageSize: 2 });
    assert.equal(p1.records.length, 2);
    assert.equal(p1.total, 3, 'el total es del filtro, no de la pagina');
    assert.equal(p1.pageCount, 2);

    const p2 = store.page({ page: 2, pageSize: 2 });
    assert.equal(p2.records.length, 1);
    assert.equal(p2.records[0].alarmCode, 'A1');
  });

  it('page filtra por alarmTypes/handleStatus/deviceCodes/channelIds/rango', () => {
    const store = seedAlarms();
    assert.equal(store.page({ alarmTypes: ['2'] }).total, 2, 'filtro por tipo');
    assert.equal(store.page({ alarmTypes: '13' }).total, 1, 'filtro por tipo (string CSV)');
    assert.equal(store.page({ handleStatus: '1' }).total, 1, 'filtro por confirmacion');
    assert.equal(store.page({ handleStatus: '0' }).total, 2);
    assert.equal(store.page({ deviceCodes: ['DEV01'] }).total, 2);
    assert.equal(store.page({ channelIds: ['DEV01$1$0$1'] }).total, 1);
    const ranged = store.page({
      startAlarmTime: '2026-11-02T00:00:00.000Z',
      endAlarmTime: '2026-11-02T23:59:59.000Z'
    });
    assert.equal(ranged.total, 1, 'filtro por rango temporal');
    assert.equal(ranged.records[0].alarmCode, 'A2');
  });

  it('handle confirma la alarma y deja handleStatus/handleUser/comment/mailReceivers', () => {
    const store = seedAlarms();
    const res = store.handle({
      alarmCode: 'A1', handleUser: 'admin', handleMessage: 'revisado',
      comment: 'falsa alarma', mailReceivers: ['a@b.c', 'd@e.f'], handleStatus: '1'
    });
    assert.equal(res.success, true);
    assert.equal(res.count, 1);
    assert.deepEqual(res.handled, ['A1']);
    const rec = store.get('A1');
    assert.equal(rec.handleStatus, '1');
    assert.equal(rec.handleUser, 'admin');
    assert.equal(rec.handleMessage, 'revisado');
    assert.equal(rec.comment, 'falsa alarma');
    assert.deepEqual(rec.mailReceivers, ['a@b.c', 'd@e.f']);
    assert.ok(rec.handleDate, 'handleDate registrado');
  });

  it('handle en lote (BRMS.Alarm.BatchHandleAlarms) confirma varias', () => {
    const store = seedAlarms();
    const res = store.handle({
      alarms: [{ alarmCode: 'A1' }, { alarmCode: 'A2' }],
      handleUser: 'admin', handleMessage: 'lote', handleStatus: '1'
    });
    assert.equal(res.count, 2);
    assert.equal(store.get('A1').handleStatus, '1');
    assert.equal(store.get('A2').handleStatus, '1');
  });

  it('stats devuelve el resumen del panel (AlarmOverview.GetSummary)', () => {
    const store = seedAlarms();
    const s = store.stats({});
    assert.equal(s.total, 3);
    assert.equal(s.handledCount, 1);
    assert.equal(s.unhandledCount, 2);
    assert.ok(s.alarmTypeCounts.length >= 1);
  });

  it('persiste en disco y recarga (data/alarms.json shape)', () => {
    const file = tmpFile('persist.json');
    const a = createAlarmStore({ filePath: file, persist: true });
    a.add({ alarmCode: 'P1', deviceCode: 'D9' });
    assert.ok(fs.existsSync(file), 'el fichero se crea');
    const b = createAlarmStore({ filePath: file, persist: true });
    assert.equal(b.size(), 1);
    assert.equal(b.get('P1').deviceCode, 'D9');
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.ok(Array.isArray(raw) && raw.length === 1);
  });

  it('la ruta por defecto es data/alarms.json', () => {
    assert.equal(path.basename(ALARM_STORE_PATH), 'alarms.json');
    assert.ok(ALARM_STORE_PATH.endsWith(path.join('data', 'alarms.json')));
  });
});

describe('E-136 store de planes de alarma (62 campos + 13 link*)', () => {
  it('el contrato de campos cubre 62+ campos y los 13 link*', () => {
    assert.ok(ALARM_PLAN_FIELDS.length >= 62, `solo ${ALARM_PLAN_FIELDS.length} campos`);
    const links = ALARM_PLAN_LINK_FIELDS;
    assert.equal(links.length, 13, '13 variantes link*');
    for (const name of ['Gate', 'Ptz', 'Wall', 'Access', 'Mail', 'Output', 'Record',
      'Snapshot', 'User', 'VoicePrompt', 'Audio', 'AudioLight', 'QuickCommand']) {
      assert.ok(links.includes(`link${name}`), `falta link${name}`);
    }
  });

  it('Add/Update/Paginado/BatchDelete sobre un plan persistido', () => {
    const store = createAlarmPlanStore({ filePath: tmpFile('plans.json'), persist: true });
    const created = store.add({ planName: 'Plan Motion', alarmTypeId: '2', linkGate: '1', channelIds: ['C1'] });
    assert.ok(created.planId);
    assert.equal(created.planName, 'Plan Motion');
    assert.equal(created.linkGate, '1');
    assert.deepEqual(created.channelIds, ['C1']);
    assert.equal(created.linkWall, '', 'los link* no informados quedan vacios (no undefined)');

    const upd = store.update(created.planId, { planName: 'Plan Motion v2', linkPtz: '1' });
    assert.equal(upd.planName, 'Plan Motion v2');
    assert.equal(upd.linkPtz, '1');
    assert.equal(upd.planId, created.planId, 'el id no cambia');

    const page = store.page({ planName: 'Plan Motion' });
    assert.equal(page.total, 1);
    assert.equal(page.records[0].planName, 'Plan Motion v2');

    const del = store.batchDelete([created.planId]);
    assert.equal(del.deletedCount, 1);
    assert.equal(store.page({}).total, 0);
  });
});

describe('E-136 store de usuarios y roles', () => {
  it('usuarios: add/update/page/delete + cambio de clave', () => {
    const store = createUserStore({ filePath: tmpFile('users.json'), persist: true });
    const u = store.add({ username: 'juan', name: 'Juan', roleIds: ['1'], password: 'old' });
    assert.equal(u.username, 'juan');
    assert.deepEqual(u.roleIds, ['1']);

    const page = store.page({ keyword: 'juan' });
    assert.equal(page.total, 1);
    assert.equal(page.users[0].name, 'Juan');

    const upd = store.update('juan', { tel: '600' });
    assert.equal(upd.tel, '600');

    const ch = store.changePassword('juan', 'new', { oldPassword: 'old' });
    assert.equal(ch.success, true);
    assert.equal(store.get('juan').password, 'new');

    const bad = store.changePassword('juan', 'x', { oldPassword: 'WRONG' });
    assert.equal(bad.success, false, 'la clave antigua se valida');

    const del = store.remove(['juan']);
    assert.equal(del.deleted, 1);
    assert.equal(store.page({}).total, 0);
  });

  it('roles: add/update/page/delete con menuCodes/functionCodes', () => {
    const store = createRoleStore({ filePath: tmpFile('roles.json'), persist: true });
    const r = store.add({ roleName: 'Operador', menuCodes: ['001'], functionCodes: ['8', '9'] });
    assert.equal(r.roleName, 'Operador');
    assert.deepEqual(r.menuCodes, ['001']);
    assert.deepEqual(r.functionCodes, ['8', '9']);
    assert.equal(store.page({ roleName: 'Oper' }).total, 1);
    assert.equal(store.update(r.roleId, { memo: 'turno' }).memo, 'turno');
    assert.equal(store.remove([r.roleId]).deleted, 1);
  });

  it('los contratos de usuario/rol exponen los campos de la matriz de gaps', () => {
    for (const f of ['username', 'digestPassword', 'roleIds', 'enableMPT', 'macAddresses',
      'enableExpireDate', 'passwordValidity', 'forceResetPassword', 'reuse']) {
      assert.ok(USER_FIELDS.includes(f), `falta usuario.${f}`);
    }
    for (const f of ['roleName', 'roleType', 'orgCodes', 'menuCodes', 'functionCodes',
      'subsystemCodes', 'channelIds', 'deviceCodes', 'autoAuthorize']) {
      assert.ok(ROLE_FIELDS.includes(f), `falta rol.${f}`);
    }
  });
});

describe('E-136 helpers', () => {
  it('toArray normaliza array/CSV/vacio', () => {
    assert.deepEqual(toArray(['a', 'b']), ['a', 'b']);
    assert.deepEqual(toArray('a, b ,c'), ['a', 'b', 'c']);
    assert.deepEqual(toArray(''), []);
    assert.deepEqual(toArray(null), []);
  });

  it('toMillis parsea ISO y "YYYY-MM-DD HH:mm:ss"', () => {
    assert.equal(toMillis('2026-11-01T10:00:00.000Z'), Date.parse('2026-11-01T10:00:00.000Z'));
    assert.ok(!Number.isNaN(toMillis('2026-11-01 10:00:00')));
    assert.ok(Number.isNaN(toMillis('no-es-fecha')));
  });
});
