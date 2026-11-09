// ===== E-135: tests unitarios del MOTOR RPC (capa 3) ======================
// Sin servidor, sin puertos: solo helpers puros de src/e135-rpc-catalog.js.
// La matriz de claves obligatorias es la de %TEMP%/opencode/rea-gap-client.md
// (52 filas) recortada al alcance de E-135-A (las de flujo async E-136-B
// quedan fuera: BRM/Alarm/HandleAlarm, BRMS.Alarm.*, BRMS.AlarmPlan.*,
// BRMS.User.*, BRMS.Role.*, BRMS.Account.ChangePassword, Rights/Nodes...).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  RPC_METHODS,
  NOTIFY_TOPICS,
  catalogKnown,
  canonicalMethod,
  familyOf,
  familyPayload,
  rpcEnvelope,
  buildRpcPayload,
  buildRpcEnvelope,
  p0Defaults,
  isP0,
  methodCandidates,
  resolveKnown
} from '../e135-rpc-catalog.js';

// ruta -> claves obligatorias (gap matrix, filas en alcance E-135-A)
const P0_REQUIRED = {
  'SS/Record/QueryRecords': ['session', 'startTime', 'endTime', 'channelId', 'recordType', 'streamType', 'streamId', 'ssId', 'diskId', 'diskPath', 'planId', 'recordName', 'cardNo', 'page', 'startIndex', 'endIndex', 'fileLength', 'forgotten', 'recordSource', 'optional'],
  'SS/Record/QueryLockInfos': ['channelId', 'startTime', 'endTime', 'userId', 'userName', 'userIp', 'streamIds', 'reason', 'source', 'operateTime', 'lockInfos', 'optional'],
  'SS/Record/GetAlarmRecords': ['channelId', 'startTime', 'endTime', 'alarmCode', 'recordType', 'streamType', 'streamId', 'ssId', 'diskId', 'planId', 'recordName', 'fileLength', 'forgotten', 'recordSource', 'optional'],
  'SS/Record/GetChannelMonthRecordStatus': ['channelId', 'month', 'days', 'recordSource', 'optional'],
  'SS/Tag/SaveRecordTag': ['tagId', 'subject', 'content', 'channelId', 'tagTime', 'beforeTagTime', 'afterTagTime', 'source', 'optional'],
  'SS/Tag/DeleteRecordTag': ['ids', 'optional'],
  'SS/Tag/QueryRecordTags': ['channelId', 'tagId', 'subject', 'content', 'startTime', 'endTime', 'tagTime', 'beforeTagTime', 'afterTagTime', 'keyword', 'source', 'userId', 'username', 'updateTime', 'tags', 'optional'],
  'user/self/password/': ['oldPassword', 'newPassword', 'unlockRemainTime', 'unlockRemainTimes'],
  'tvwall/wall': ['tvWallName', 'tvWallDesc', 'wallScreenList', 'screenName', 'screenType', 'channelId', 'channelName', 'deviceCode', 'deviceName', 'deviceType', 'height', 'width', 'top', 'left', 'previewHeight', 'previewWidth', 'previewTop', 'previewLeft', 'isNewScreen', 'parentId', 'bigScreenList', 'alarmSourceNames', 'wallId', 'screenId'],
  'alarm/plan/template': ['name', 'content', 'results'],
  'alarm/plan/source/': ['sourceId', 'sourceCode', 'sourceName', 'alarmTypeId', 'channels', 'channelIds', 'users', 'recipients', 'emailAddress', 'enableVideo', 'enableRecord', 'duration', 'prerecordTime', 'status', 'level', 'action', 'method', 'model', 'target', 'url', 'wallId', 'windowId', 'streamType', 'fileIds', 'content', 'mailTemplateId', 'vacationTemplateId', 'timeTemplateId', 'planTemplateId', 'ignoreTime', 'executeMode', 'seq',
    'linkAccess', 'linkAudio', 'linkAudioLight', 'linkGate', 'linkMail', 'linkOutput', 'linkPtz', 'linkQuickCommand', 'linkRecord', 'linkSnapshot', 'linkUser', 'linkVoicePrompt', 'linkWall'],
  'alarm/plan/alarm-type/pos': ['alarmTypeId', 'alarmTypeName', 'minAmount', 'maxAmount', 'pricePeriods', 'icon', 'mode'],
  'alarm/plan/alarm-type/transparence': ['alarmTypeCode', 'alarmStatus', 'alarmTypeName', 'subscribePicture', 'siaSupportMode', 'sourceTypeId'],
  'account/favorite/channel': ['channelId', 'channelName', 'channelType', 'channelSubtype', 'cameraType', 'orgCode', 'sourceOrgCode', 'targetOrgCode', 'siteIp', 'siteName', 'channels'],
  'account/favorite/organization': ['orgCode', 'orgName', 'parentOrgCode', 'sourceOrgCode', 'targetOrgCode', 'channels', 'siteIp', 'siteName', 'channelId', 'channelName', 'channelType', 'channelSubtype', 'cameraType', 'orgCodes'],
  'account/favorite/organization/share': ['orgCode', 'shareOrgCode', 'sharedUserIds', 'failedInfo', 'failedReason', 'username'],
  'map/radar/': ['channelId', 'deviceCode', 'deviceName', 'deviceIp', 'devicePort', 'orgCode', 'results'],
  'server/video/list': ['serverCode', 'serverName', 'servers', 'locale', 'uiBufLen'],
  'realmonitor/snapshot/': ['channelId', 'content', 'rtsp', 'time', 'optional'],
  'DMS/Cruise/GetCruises': ['channelId', 'cruiseId', 'cruises', 'data', 'optional'],
  'BRM/Config/GetEmapInfo': ['optional', 'addr'],
  'BRM/Linked/GetLinkedChannels': ['srcChannelId', 'dstChannelIds', 'channels', 'location', 'optional'],
  'BRM/TvWall/SaveUserTvWallTask': ['tvWallId', 'taskId', 'taskName', 'taskDesc', 'pTaskInfo', 'pTaskBaseInfo', 'data', 'pTaskXmlData', 'optional'],
  'BRM/TvWall/DeleteUserTvWallTask': ['tvWallId', 'taskId', 'taskName', 'taskDesc', 'pTaskInfo', 'pTaskBaseInfo', 'data', 'pTaskXmlData', 'optional'],
  'BRM/User/GetRightUsers': ['resourceId', 'pResourceId', 'users', 'pUserList', 'fileName', 'optional'],
  'BRM/User/DeleteUserData': ['resourceId', 'pResourceId', 'users', 'pUserList', 'fileName', 'optional'],
  'BRM/Device/GetLocalLogs': ['deviceCode', 'startTime', 'endTime', 'session', 'pSession', 'pParam'],
  'BRM/Device/GetMediaVKs': ['vkId', 'vkValue', 'algorithm', 'createDate', 'vks', 'startDate', 'endDate'],
  'BRM/App/GetAppUsers': ['userId', 'userName', 'personName', 'personId', 'sip', 'status', 'keyword', 'pageNo', 'pageSize', 'totalCount', 'appUsers', 'searchInfo', 'houseHolder', 'lastLoginDate', 'lastUpdatePasswordDate', 'password', 'userIds'],
  'BRM/App/UpdateAppUser': ['userId', 'userName', 'personName', 'personId', 'sip', 'status', 'password'],
  'BRM/App/DeleteAppUsers': ['userIds'],
  'BRM/Mail/SendMessage': ['recipient', 'ccRecipient', 'bccRecipient', 'subject', 'message', 'attachmentPaths', 'name'],
  'BRM/Heatmap/GetHeatmap': ['deviceCode', 'channelId', 'startTime', 'endTime', 'heatmapType', 'width', 'height', 'records', 'average', 'picData', 'picDataLen', 'binData', 'binDataLen', 'token', 'unitSeq', 'channelSeq', 'total'],
  'BRM/Heatmap/GetHeatmapPreciseAnalysis': ['deviceCode', 'channelId', 'startTime', 'endTime', 'heatmapType', 'width', 'height', 'records', 'average', 'picData', 'picDataLen', 'binData', 'binDataLen', 'token', 'unitSeq', 'channelSeq', 'total'],
  'BRM/Alarm/GetAlarmProcedures': ['pAlarmProcessInfoList', 'handleUser', 'procedures', 'handleMessage', 'handleStatus', 'handleDate', 'optional', 'pAlarmCode', 'alarmCode'],
  'BRM/Alarm/GetAlarmAccessRecordInfo': ['cardNum', 'idNum', 'personId', 'gender', 'tel', 'orgCode', 'orgName', 'roomId', 'unitId', 'departmentName', 'faceImageUrl', 'captureImageUrl', 'antiPassType', 'bindChannels', 'linkChannels', 'alarmCode', 'alarmDate', 'alarmTime', 'operateType', 'operateInfo', 'optional'],
  'BRM/Alarm/GetAlarmCarBlacklistInfo': ['carNum', 'carColor', 'carType', 'carImgUrl', 'blacklistType', 'carWayCode', 'peccancyType', 'carSpeed', 'personId', 'personName', 'similarity', 'nationality', 'birthday', 'repositoryName', 'detectionImageUrl'],
  'BRM/Alarm/GetAlarmCarPeccancyInfo': ['carNum', 'carColor', 'carType', 'carImgUrl', 'blacklistType', 'carWayCode', 'peccancyType', 'carSpeed', 'personId', 'personName', 'similarity', 'nationality', 'birthday', 'repositoryName', 'detectionImageUrl'],
  'BRM/Alarm/GetAlarmFaceRecognitionInfo': ['personId', 'personName', 'similarity', 'nationality', 'birthday', 'repositoryName', 'detectionImageUrl'],
  'BRMS/Config/GetMailConfig': ['smtpServer', 'smtpPort', 'sender', 'receiver', 'password', 'encrypType', 'enable', 'receivers', 'title', 'content', 'attachments', 'fileName', 'fileData'],
  'BRMS/Config/UpdateMailConfig': ['smtpServer', 'smtpPort', 'sender', 'receiver', 'password', 'encrypType', 'enable', 'receivers', 'title', 'content', 'attachments', 'fileName', 'fileData'],
  'BRMS/Config/SendMail': ['smtpServer', 'smtpPort', 'sender', 'receiver', 'password', 'encrypType', 'enable', 'receivers', 'title', 'content', 'attachments', 'fileName', 'fileData'],
  'BRMS/Map/GetRadarBindCameras': ['channelId'],
  'BRMS/Device/GetPageDevices': ['page', 'pageSize', 'keyword', 'orgCode', 'deviceType', 'status']
};

// grupos por prefijo (matriz): metodos representativos + claves comunes
const GROUP_REQUIRED = {
  'BRMS.Storage': ['serverCode', 'paths', 'path', 'diskType', 'diskUuid', 'raidId', 'raidPath', 'hotStandbyType', 'mode', 'username', 'password', 'groupName', 'bindingDiskUuids', 'bindingChannelIds'],
  'BRMS.Favorite': ['orgCode', 'orgName', 'parentOrgCode', 'sourceOrgCode', 'targetOrgCode', 'sharedUserIds', 'sharedOrgCode', 'channelId', 'channelName', 'channelType', 'channelSubtype', 'cameraType', 'siteIp', 'siteName', 'channels', 'orgCodes'],
  'BRMS.Monitor': ['viewCode', 'viewName', 'viewDirCode', 'viewDirName', 'viewType', 'griddingEnable', 'griddingRows', 'griddingCols', 'griddingCombine', 'windowData', 'windowLayout', 'windowTotal', 'windowNo', 'windowFromX', 'windowFromY', 'windowToX', 'windowToY', 'griddingIndex', 'customSplit', 'resourceCode', 'resourceName', 'resourceType', 'alarmWindow', 'streamType', 'siteIp', 'roleIds', 'sharedUserId', 'shareViewCode', 'remark']
};

describe('E-135 motor RPC - catalogo', () => {
  it('carga el catalogo cosechado (2024 metodos) y los topics DPSDK', () => {
    assert.equal(RPC_METHODS.size, 2024);
    assert.ok(RPC_METHODS.has('BRMS.Storage.GetLocalDisks'));
    assert.ok(RPC_METHODS.has('arms.label.addLabel'));
    assert.ok(RPC_METHODS.has('SS.Record.QueryRecords'));
    assert.ok(NOTIFY_TOPICS.length >= 90);
    assert.ok(NOTIFY_TOPICS.includes('brms.notifyAlarms'));
  });

  it('catalogKnown reconoce dotted, slashed y alias plano', () => {
    assert.equal(catalogKnown('BRMS.Storage.GetLocalDisks'), true);
    assert.equal(catalogKnown('SS/Record/QueryRecords'), true);
    assert.equal(catalogKnown('arms.label.addLabel'), true);
    assert.equal(catalogKnown('BRMS.Device.NoSuchMethodXyz'), false);
    assert.equal(catalogKnown(''), false);
  });

  it('canonicalMethod normaliza rutas de cliente a dotted', () => {
    assert.equal(canonicalMethod('SS/Record/QueryRecords'), 'SS.Record.QueryRecords');
    assert.equal(canonicalMethod('/brms/api/v1.1/BRMS/Storage/GetLocalDisks'), 'BRMS.Storage.GetLocalDisks');
    assert.equal(canonicalMethod('admin/API/BRM/Config/GetMqConfig'), 'BRM.Config.GetMqConfig');
  });
});

describe('E-135 motor RPC - familias de payload', () => {
  it('clasifica la familia por sufijo del metodo', () => {
    assert.equal(familyOf('BRMS.Storage.GetLocalDisks'), 'list');
    assert.equal(familyOf('SS.Record.QueryRecords'), 'list');
    assert.equal(familyOf('BRMS.Storage.AddDiskGroup'), 'write');
    assert.equal(familyOf('BRMS.Favorite.BatchDeleteChannels'), 'del');
    assert.equal(familyOf('BRM.TvWall.RobLocalDisk'), 'other');
  });

  it('familia list -> results/list/total/totalCount + eco page/pageSize', () => {
    const p = familyPayload('BRMS.Storage.GetLocalDisks', { page: 3, pageSize: 50 });
    assert.deepEqual(p.results, []);
    assert.deepEqual(p.list, []);
    assert.equal(p.total, '0');
    assert.equal(p.totalCount, '0');
    assert.equal(p.page, 3);
    assert.equal(p.pageSize, 50);
  });

  it('familia write -> success:true + eco', () => {
    const p = familyPayload('BRMS.Storage.AddDiskGroup', { path: '/data/disk1', groupName: 'g1' });
    assert.equal(p.success, true);
    assert.equal(p.path, '/data/disk1');
    assert.equal(p.groupName, 'g1');
  });

  it('familia del -> success:true', () => {
    const p = familyPayload('BRMS.Storage.DeleteRaid', { raidId: 'r1' });
    assert.equal(p.success, true);
    assert.equal(p.raidId, 'r1');
  });

  it('familia default -> objeto vacio (pero envuelto en envelope code 0)', () => {
    const p = familyPayload('BRM.TvWall.RobLocalDisk', {});
    assert.deepEqual(Object.keys(p), []);
    const env = rpcEnvelope('BRM.TvWall.RobLocalDisk', p);
    assert.equal(env.code, 1000);
  });
});

describe('E-135 motor RPC - envelope', () => {
  it('metodo CONOCIDO -> envelope code 0 con claves de familia', () => {
    const env = buildRpcEnvelope('BRMS.Storage.GetLocalDisks', {});
    assert.equal(env.code, 1000);
    assert.equal(env.desc, 'Success');
    assert.equal(env.method, 'BRMS.Storage.GetLocalDisks');
    assert.ok(Array.isArray(env.data.results));
    assert.ok(Array.isArray(env.info.results));
    assert.equal(env.data.total, '0');
    assert.equal(env.data.totalCount, '0');
    assert.equal(env.data.code, 1000);
    // dual-key: las claves de familia tambien en la raiz
    assert.ok(Array.isArray(env.results));
    assert.ok(Array.isArray(env.list));
  });

  it('metodo DESCONOCIDO -> envelope code 0 (no 404, no 40B)', () => {
    const env = buildRpcEnvelope('Totally.Unknown.Method', { foo: 'bar' });
    assert.equal(env.code, 1000);
    assert.equal(env.desc, 'Success');
    assert.equal(env.method, 'Totally.Unknown.Method');
    assert.equal(env.data.code, 1000);
    assert.equal(env.data.foo, 'bar');
    assert.ok(JSON.stringify(env).length > 40, 'no debe ser el catch-all de 40B');
  });

  it('el payload de un metodo conocido nunca queda vacio sin code', () => {
    for (const m of ['BRMS.Storage.RobLocalDisk', 'BRM.App.UpdateAppUser', 'IVS.Foo.Bar']) {
      const env = buildRpcEnvelope(m, {});
      assert.equal(env.code, 1000);
      assert.equal(env.data.code, 1000);
    }
  });
});

describe('E-135 motor RPC - payloads P0 reales', () => {
  for (const [route, keys] of Object.entries(P0_REQUIRED)) {
    it(`${route} -> claves obligatorias presentes`, () => {
      const payload = buildRpcPayload(route, {});
      assert.ok(payload, 'payload no null');
      for (const k of keys) {
        assert.ok(k in payload, `falta la clave obligatoria ${k} en ${route}`);
      }
      assert.equal(payload.code, 1000);
    });
  }

  for (const [prefix, keys] of Object.entries(GROUP_REQUIRED)) {
    const members = [...RPC_METHODS].filter((m) => m.startsWith(prefix + '.'));
    it(`${prefix}.* (${members.length} metodos) -> claves obligatorias presentes`, () => {
      assert.ok(members.length > 0, 'el grupo debe tener metodos en el catalogo');
      for (const m of members) {
        const payload = buildRpcPayload(m, {});
        for (const k of keys) {
          assert.ok(k in payload, `falta ${k} en ${m}`);
        }
        assert.equal(payload.code, 1000);
      }
    });
  }

  it('los metodos P0 son reconocibles y priorizan su payload propio', () => {
    assert.equal(isP0('SS.Record.QueryRecords'), true);
    assert.equal(isP0('BRMS.Storage.GetLocalDisks'), true);
    assert.equal(isP0('BRMS.Monitor.AddView'), true);
    assert.equal(isP0('IVS.SomethingElse'), false);
    assert.ok(p0Defaults('BRMS.Device.GetPageDevices'));
  });

  it('eco del body: las claves que envia el cliente se devuelven', () => {
    const payload = buildRpcPayload('SS.Record.QueryRecords', { channelId: 'CH-1', startTime: '2026-01-01 00:00:00', page: 4 });
    assert.equal(payload.channelId, 'CH-1');
    assert.equal(payload.startTime, '2026-01-01 00:00:00');
    assert.equal(payload.page, 4);
    // y los defaults siguen presentes
    assert.equal(payload.endTime, '');
    assert.ok('diskPath' in payload);
  });

  it('BRM.Alarm.GetAlarmFace* y GetAlarmCar* tienen payload propio', () => {
    const face = buildRpcPayload('BRM.Alarm.GetAlarmFaceRecognitionInfo', {});
    assert.ok('similarity' in face && 'repositoryName' in face && 'detectionImageUrl' in face);
    const car = buildRpcPayload('BRM.Alarm.GetAlarmCarBlacklistInfo', {});
    assert.ok('carNum' in car && 'blacklistType' in car && 'carSpeed' in car);
  });

  it('los flujos async de E-136-B NO se sirven aqui (quedan fuera de alcance)', () => {
    // HandleAlarm / BRMS.Alarm.* / BRMS.User.* / Rights.Nodes quedan para
    // E-136-B: este motor solo garantiza el envelope, sin claves P0 propias.
    assert.equal(isP0('BRM.Alarm.HandleAlarm'), false);
    assert.equal(isP0('BRMS.Alarm.GetPageAlarmRecords'), false);
    assert.equal(isP0('BRMS.User.GetPageUsers'), false);
    assert.equal(isP0('Rights.Nodes'), false);
    const env = buildRpcEnvelope('BRMS.Alarm.GetPageAlarmRecords', {});
    assert.equal(env.code, 1000);
  });
});

describe('E-135 motor RPC - resolucion de metodo desde la URL', () => {
  it('methodCandidates prioriza el alias de la raiz', () => {
    const c = methodCandidates(['BRM', 'label', 'addLabel'], 'arms');
    assert.equal(c[0], 'arms.label.addLabel');
    assert.ok(c.includes('BRM.label.addLabel'));
  });

  it('resolveKnown elige el candidato que esta en el catalogo', () => {
    assert.equal(resolveKnown(['BRM', 'label', 'addLabel'], 'arms'), 'arms.label.addLabel');
    assert.equal(resolveKnown(['SS', 'Record', 'QueryRecords'], 'BRMS'), 'SS.Record.QueryRecords');
    assert.equal(resolveKnown(['BRMS', 'Storage', 'GetLocalDisks'], 'BRMS'), 'BRMS.Storage.GetLocalDisks');
  });
});
