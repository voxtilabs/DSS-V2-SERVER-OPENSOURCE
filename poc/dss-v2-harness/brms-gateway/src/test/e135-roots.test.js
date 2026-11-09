// ===== E-135: tests de las RAICES de subsistema (capa 4) ==================
// Fastify `inject()` sobre una instancia propia: NO se abre ningun puerto,
// asi que no choca con brms.test.js (que spawnea el gateway en 11443).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { register, ROOTS, VERSIONED_ROOTS, rootRoutes } from '../e135-roots.js';
import { register as registerRpc, RPC_METHODS } from '../e135-rpc-catalog.js';

const ALL_ROOTS = [...ROOTS, ...VERSIONED_ROOTS];

describe('E-135 raices de subsistema', { timeout: 20000 }, () => {
  let app;
  before(async () => {
    app = Fastify({ logger: false });
    register(app, {});
    registerRpc(app, {});
    await app.ready();
  });
  after(async () => { if (app) await app.close(); });

  it('registra las 16 raices reales del server + 2 versionadas', () => {
    const paths = ROOTS.map((r) => r.path);
    for (const p of ['/obms/api', '/ipms/api', '/omms/api', '/emap/api', '/emapService', '/arms/api',
      '/otms/api', '/OTMS/API', '/iams/api', '/erms/api', '/ecos/api', '/vehicleServer',
      '/psib', '/faceService', '/alarmProcess', '/cfgs/api']) {
      assert.ok(paths.includes(p), `falta la raiz ${p}`);
    }
    assert.equal(ROOTS.length, 16);
    assert.equal(VERSIONED_ROOTS.length, 2);
    // 2 y 3 segmentos por raiz, GET + POST
    assert.equal(rootRoutes().length, (ROOTS.length + VERSIONED_ROOTS.length) * 2);
  });

  it('/arms/api/BRM/label/addLabel responde 200 con envelope', async () => {
    const r = await app.inject({ method: 'GET', url: '/arms/api/BRM/label/addLabel' });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.equal(j.desc, 'Success');
    assert.equal(j.method, 'arms.label.addLabel');
    assert.ok(j.data && typeof j.data === 'object');
    assert.equal(j.data.code, 1000);
    assert.equal(j.data.success, true); // familia write (add*)
  });

  it('/arms/api/BRM/label/addLabel por POST con body.method', async () => {
    const r = await app.inject({
      method: 'POST',
      url: '/arms/api/BRM/label/addLabel',
      payload: { method: 'arms.label.addLabel', data: { labelName: 'persona' } }
    });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.equal(j.method, 'arms.label.addLabel');
    assert.equal(j.data.labelName, 'persona');
  });

  it('toda raiz registrada responde 200 con envelope code 1000 (GET y POST)', async () => {
    for (const root of ALL_ROOTS) {
      for (const url of [`${root.path}/Algo/Metodo`, `${root.path}/Algo/Sub/Metodo`]) {
        for (const method of ['GET', 'POST']) {
          const r = await app.inject({ method, url, payload: method === 'POST' ? {} : undefined });
          assert.equal(r.statusCode, 200, `${method} ${url} -> ${r.statusCode}`);
          const j = r.json();
          assert.equal(j.code, 1000, `${method} ${url} -> code ${j.code}`);
          assert.equal(j.desc, 'Success');
          assert.ok(j.data && typeof j.data === 'object');
          assert.equal(j.data.code, 1000);
        }
      }
    }
  });

  it('las raices versionadas /brms/api/v1.x sirven el catalogo', async () => {
    const r = await app.inject({
      method: 'POST',
      url: '/brms/api/v1.1/SS/Record/QueryRecords',
      payload: { channelId: 'CH-9', page: 2 }
    });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.equal(j.method, 'SS.Record.QueryRecords');
    assert.equal(j.data.channelId, 'CH-9');
    assert.equal(j.data.page, 2);
    assert.ok(Array.isArray(j.data.records));
    assert.ok(Array.isArray(j.data.results));
    assert.equal(j.data.total, '0');
  });

  it('un metodo DESCONOCIDO en una raiz nueva responde 200 code 0 (no 404, no 40B)', async () => {
    const r = await app.inject({ method: 'GET', url: '/vehicleServer/NoSuch/Thing' });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.equal(j.desc, 'Success');
    assert.ok(JSON.stringify(j).length > 40);
  });

  it('las familias BRMS quedan alcanzables por el motor RPC', async () => {
    const r = await app.inject({
      method: 'POST',
      url: '/admin/API/BRMS/Storage/GetLocalDisks',
      payload: { method: 'BRMS.Storage.GetLocalDisks', data: { serverCode: 'S1' } }
    });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.equal(j.method, 'BRMS.Storage.GetLocalDisks');
    assert.ok(Array.isArray(j.data.results));
    assert.equal(j.data.serverCode, 'S1');
    assert.equal(j.data.paths.length, 0);
    assert.ok('bindingDiskUuids' in j.data);
  });

  it('BRMS.Monitor.* sirve windowLayout[]/gridding* (motor de vistas)', async () => {
    const r = await app.inject({
      method: 'POST',
      url: '/admin/API/BRMS/Monitor/AddView',
      payload: { method: 'BRMS.Monitor.AddView', data: { viewName: 'v1', griddingRows: 4 } }
    });
    assert.equal(r.statusCode, 200);
    const j = r.json();
    assert.equal(j.code, 1000);
    assert.ok(Array.isArray(j.data.windowLayout));
    assert.ok('griddingEnable' in j.data);
    assert.ok('griddingCols' in j.data);
    assert.equal(j.data.viewName, 'v1');
    assert.equal(j.data.griddingRows, 4);
  });

  it('el catalogo completo (2024 metodos) es alcanzable por el motor', () => {
    assert.equal(RPC_METHODS.size, 2024);
  });
});
