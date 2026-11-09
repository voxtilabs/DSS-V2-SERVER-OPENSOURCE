// E-136: los 5 topics de notify que faltaban en GetMqConfig + el routing
// `mq.*.msg.topic.<UserId>` que consume el cliente native (MSG.exe).
//
// Evidencia (matriz de gaps rea-gap-server.md linea 49/71-72):
// - DPSDK pool 0xc71228-0xc749b8 = 91 topics; el gateway servia 88 -> faltan
//   5: aps.notifyAlarmProcessRecord, erms.inspectPlan.notifyRunningStatus,
//   face.event.notify, omms.alert.notifyAlerts, schoolattendance.event.notify.
// - El cliente real NO escucha `brms.notify*` (ConsumerCount=0 en vivo,
//   Jolokia): consume `mq.*.msg.topic*` con sufijo <UserId>. Por eso el
//   envelope se publica en AMBOS.
//
// Este fichero es puro modulo: no abre puertos, no escribe data/*.json y no
// toca el 11443 (brms.test.js corre en paralelo).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MQ_TOPICS, ALARM_MQ_TOPIC_PREFIXES, alarmMqTopics, clientMqTopics,
  createNotifyHub, buildMqConfigPayload, buildAlarmEventEnvelope
} from '../e039-mq-notify.js';

const NEW_TOPICS = [
  'aps.notifyAlarmProcessRecord',
  'erms.inspectPlan.notifyRunningStatus',
  'face.event.notify',
  'omms.alert.notifyAlerts',
  'schoolattendance.event.notify'
];

/** Hub con_topic recording (mqtt + amq) sin broker real. */
function recordingHub(opts = {}) {
  const mqtt = [];
  const amq = [];
  const ws = [];
  const hub = createNotifyHub({
    wsClients: new Set([{ readyState: 1, send: (m) => ws.push(m) }]),
    mqttPublish: (t, b) => mqtt.push([t, b]),
    amqPublish: (t, b) => amq.push([t, b]),
    ...opts
  });
  return { hub, mqtt, amq, ws };
}

describe('E-136 topics de notify faltantes en GetMqConfig', () => {
  it('los 5 topics nuevos estan en MQ_TOPICS', () => {
    for (const t of NEW_TOPICS) {
      assert.ok(MQ_TOPICS.includes(t), `topic anunciado en GetMqConfig: ${t}`);
    }
  });

  it('MQ_TOPICS no tiene duplicados y grew >= 86', () => {
    assert.equal(new Set(MQ_TOPICS).size, MQ_TOPICS.length, 'sin topics repetidos');
    assert.ok(MQ_TOPICS.length >= 86, `cobertura del pool DPSDK (${MQ_TOPICS.length})`);
  });

  it('GetMqConfig publica los 5 topics como TopicInfos con IsAccUser string', () => {
    const payload = buildMqConfigPayload({ publicHost: '10.0.0.5', enabled: true });
    const infos = payload.TopicInfos || [];
    assert.ok(infos.length >= 86, `TopicInfos completos (${infos.length})`);
    assert.ok(infos.every((t) => typeof t.IsAccUser === 'string'), 'IsAccUser es STRING');
    for (const t of NEW_TOPICS) {
      const row = infos.find((i) => i.Topic === t);
      assert.ok(row, `TopicInfos incluye ${t}`);
      assert.equal(row.IsAccUser, '1');
    }
    // contrato MQ de MSG.exe intacto
    assert.equal(payload.MQConfig, '10.0.0.5:61616');
    assert.notEqual(payload.MQType, 'mqtt');
    assert.equal(payload.UserId, '1');
    assert.equal(payload.SessionId, 1);
    assert.equal(typeof payload.UseMqFlag, 'number');
    assert.equal(typeof payload.SSLEnable, 'number');
    assert.equal(typeof payload.UnSSLPort, 'number');
    assert.equal(typeof payload.ProtocolVersion, 'number');
  });
});

describe('E-136 routing mq.*.msg.topic.<UserId>', () => {
  it('alarmMqTopics devuelve los 5 prefijos bare + <UserId>', () => {
    const topics = alarmMqTopics('1');
    for (const p of ALARM_MQ_TOPIC_PREFIXES) {
      assert.ok(topics.includes(p), `prefijo bare: ${p}`);
      assert.ok(topics.includes(`${p}1`), `prefijo con UserId: ${p}1`);
    }
    // los topics de alarma/evento son los que consume el cliente native
    assert.ok(topics.includes('mq.alarm.msg.topic.1'));
    assert.ok(topics.includes('mq.event.msg.topic.1'));
    assert.ok(topics.includes('mq.common.msg.topic.1'));
    // `mq.common.msg.topic` no lleva punto final en el pool de MSG.exe: se
    // publican las dos grafias (p+id y p+'.'+id) para no perder ninguna.
    assert.ok(topics.includes('mq.common.msg.topic1'));
    // bare + por-usuario, mas la variante con punto del topic sin punto
    assert.equal(topics.length, ALARM_MQ_TOPIC_PREFIXES.length * 2 + 1);
  });

  it('alarmMqTopics sin UserId devuelve solo los prefijos bare', () => {
    const topics = alarmMqTopics('');
    assert.equal(topics.length, ALARM_MQ_TOPIC_PREFIXES.length);
    assert.ok(topics.includes('mq.alarm.msg.topic.'));
  });

  it('alarmEvent publica el envelope en brms.notify*, vms.alarm.msg y el pool mq.*', () => {
    const { hub, mqtt, amq } = recordingHub();
    hub.alarmEvent({ alarmCode: 'A-1', deviceCode: 'CAM01', description: 'movimiento' });

    const amqTopics = amq.map((p) => p[0]);
    assert.ok(amqTopics.includes('brms.notifyAlarms'));
    assert.ok(amqTopics.includes('vms.alarm.msg'));
    for (const t of alarmMqTopics('1')) {
      assert.ok(amqTopics.includes(t), `alarm publicado en ${t}`);
    }
    // el canal MQTT sigue vivo (E-039 broker en 1883)
    assert.ok(mqtt.map((p) => p[0]).includes('brms.notifyAlarms'));

    // el envelope lleva method + info en la raiz (ParseMQMsg lo exige)
    const envelope = JSON.parse(amq[0][1]);
    assert.equal(envelope.method, 'vms.alarm.msg');
    assert.ok(envelope.info && typeof envelope.info === 'object', 'root.info object');
    assert.ok(!('params' in envelope), 'params nunca se lee en la ruta MQ');
  });

  it('alarmEvent publica tambien aps.notifyAlarmProcessRecord y omms.alert.notifyAlerts', () => {
    const { hub, amq } = recordingHub();
    hub.alarmEvent({ alarmCode: 'A-2', deviceCode: 'CAM02' });
    const amqTopics = amq.map((p) => p[0]);
    assert.ok(amqTopics.includes('aps.notifyAlarmProcessRecord'));
    assert.ok(amqTopics.includes('omms.alert.notifyAlerts'));
    // los dos llevan el mismo sobre {method,info} que el resto
    for (const t of ['aps.notifyAlarmProcessRecord', 'omms.alert.notifyAlerts']) {
      const row = amq.find((p) => p[0] === t);
      const env = JSON.parse(row[1]);
      assert.ok(env.method, `${t}: method en la raiz`);
      assert.ok(env.info && typeof env.info === 'object', `${t}: info en la raiz`);
    }
  });
});

describe('E-136 topicEvent (publish por topic concreto)', () => {
  it('publica {method,info} en el topic y en el pool mq.* del cliente', () => {
    const { hub, mqtt, amq } = recordingHub();
    const raw = hub.topicEvent('face.event.notify', 'face.event.notify', { faceId: 'F-1' });

    const env = JSON.parse(raw);
    assert.equal(env.method, 'face.event.notify');
    assert.deepEqual(env.info, { faceId: 'F-1' });
    assert.ok(!('params' in env), 'params nunca se lee en la ruta MQ');

    assert.ok(mqtt.some((p) => p[0] === 'face.event.notify'), 'tambien en el bus MQTT');
    assert.ok(amq.some((p) => p[0] === 'face.event.notify'), 'en el bus ActiveMQ');
    for (const t of alarmMqTopics('1')) {
      assert.ok(amq.some((p) => p[0] === t), `pool mq.*: ${t}`);
    }
  });

  it('el sobre de topicEvent se puede consumir con el parser nativo', () => {
    const { hub } = recordingHub();
    const env = JSON.parse(hub.topicEvent('schoolattendance.event.notify', 'schoolattendance.event.notify', { a: 1 }));
    // FUN_1800306b0 (ParseMQMsg): sin method O sin info en la raiz se descarta
    assert.ok('method' in env);
    assert.ok('info' in env);
    assert.equal(typeof env.info, 'object');
  });

  it('topicEvent tolera un info no-objeto', () => {
    const { hub } = recordingHub();
    const env = JSON.parse(hub.topicEvent('erms.inspectPlan.notifyRunningStatus', 'erms.inspectPlan.notifyRunningStatus', 'x'));
    assert.equal(env.method, 'erms.inspectPlan.notifyRunningStatus');
    assert.deepEqual(env.info, {});
  });
});

describe('E-136 compatibilidad con el notify existente', () => {
  it('deviceEvent NO cambia: 3 envelopes x topics mq.* (contrato e039)', () => {
    const { hub, amq } = recordingHub();
    hub.deviceEvent('DEVICE_ADDED', { deviceCode: 'D-1', deviceName: 'n' });
    const mqPubs = amq.slice(2);
    assert.equal(mqPubs.length, 3 * clientMqTopics('1').length);
    for (const [, b] of mqPubs) {
      const env = JSON.parse(b);
      assert.ok(env.info && typeof env.info === 'object');
      assert.ok(!('params' in env));
    }
  });

  it('buildAlarmEventEnvelope conserva method + info en la raiz', () => {
    const env = JSON.parse(buildAlarmEventEnvelope({ alarmCode: 'A-3', deviceCode: 'CAM03' }));
    assert.equal(env.method, 'vms.alarm.msg');
    assert.ok(env.info && typeof env.info === 'object');
    assert.ok('disarmUserIds' in env.info);
  });
});
