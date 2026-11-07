// ===== E-118: Event Center protocol (DPSDK RE evidence 2026-11-07) ==========
//
// DPSDK.dll string pool:
//   /videoService/eventCenter/messages/subscribe      @0xcbba90
//      (CHttpEventPullQueue::OnHandleRequestAlarmEvent @0xcbba58,
//       HttpEventPullQueue.cpp @0xcbb9e0) + OnHandleRequestOtherEvent
//   eventCenter/messages/subscribeAddress             @0xc96498 (GetMQConfig)
//   eventCenter/alarmTypes                            @0xc97138 (GetAlarmTypeGroupInfo)
//   eventCenter/alarm/messages/count                  @0xc97268 (QueryAlarmCount)
//   subscribe params: subscribeAddress/AddrType/User/Password/initMessageId/msgId
//      @0xcd6628-0xcd6670
//   alarm event schema (CAnalyzeNotify::ParseAlarmEventNotify @0xcacaf0):
//      alarmCode, alarmId, alarmType, alarmTypeId, alarmLevel, alarmGrade,
//      eventTime, eventCode, eventLevel, eventId, eventGrade, eventType,
//      eventSourceType, deviceCode, deviceId, deviceName, channelId,
//      channelCode, channelName, alarmTime, alarmPicture, alarmRecordPosition,
//      recordTime, preRecordTime, linkVideoChannels, linkRecordChannels,
//      mapIds, streamType, nodeCode, strMessage, eventRemark,
//      gpsX/gpsY/height/angle/speed
//   VSL variants (ParseVSLAlarmEventNotify @0xcacd20): faceAlarm,
//      trafficJunction, faceAnalysis, handleMessage
//   Dahua proprietary IVS event names (netsdk): CrossLineDetection (tripwire),
//      CrossRegionDetection, Intrusion, FastMove, AbruptSlowdown,
//      AbruptSpeedup, Freeze - the NUMERIC ids come from the server via
//      eventCenter/alarmTypes (AlarmTypeInfo.xml is a stub in the client).

// Dahua/DSS alarm type catalog (what the Event Center shows). IDs follow the
// DSS server convention: video/device alarms 1xx, IVS/AI 3xx-4xx, custom.
export const DSS_ALARM_TYPE_CATALOG = [
  { alarmTypeId: '1', alarmType: 'VideoLoss', alarmTypeName: 'Video Loss', category: 'video', level: '2', eventSourceType: '1' },
  { alarmTypeId: '2', alarmType: 'MotionDetection', alarmTypeName: 'Motion Detection', category: 'video', level: '1', eventSourceType: '1' },
  { alarmTypeId: '3', alarmType: 'TamperDetection', alarmTypeName: 'Tamper Detection', category: 'video', level: '1', eventSourceType: '1' },
  { alarmTypeId: '6', alarmType: 'DeviceOffline', alarmTypeName: 'Device Offline', category: 'device', level: '2', eventSourceType: '2' },
  { alarmTypeId: '7', alarmType: 'AlarmIn', alarmTypeName: 'Alarm In', category: 'device', level: '1', eventSourceType: '2' },
  { alarmTypeId: '13', alarmType: 'CrossLineDetection', alarmTypeName: 'Tripwire (Cross Line)', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '14', alarmType: 'CrossRegionDetection', alarmTypeName: 'Intrusion (Cross Region)', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '15', alarmType: 'Intrusion', alarmTypeName: 'Intrusion Detection', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '16', alarmType: 'FastMove', alarmTypeName: 'Fast Move', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '17', alarmType: 'AbruptSlowdown', alarmTypeName: 'Abrupt Slowdown', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '18', alarmType: 'AbruptSpeedup', alarmTypeName: 'Abrupt Speedup', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '19', alarmType: 'Freeze', alarmTypeName: 'Video Freeze', category: 'ivs', level: '1', eventSourceType: '3' },
  { alarmTypeId: '20', alarmType: 'FaceDetection', alarmTypeName: 'Face Detection', category: 'ai', level: '1', eventSourceType: '4' },
  { alarmTypeId: '21', alarmType: 'FaceRecognition', alarmTypeName: 'Face Recognition', category: 'ai', level: '1', eventSourceType: '4' },
  { alarmTypeId: '22', alarmType: 'ANPR', alarmTypeName: 'Plate Recognition', category: 'ai', level: '1', eventSourceType: '4' },
  { alarmTypeId: '99', alarmType: 'Generic', alarmTypeName: 'Generic Event', category: 'custom', level: '1', eventSourceType: '9' }
];

export function buildEventCenterAlarmTypesPayload() {
  return {
    list: DSS_ALARM_TYPE_CATALOG, results: DSS_ALARM_TYPE_CATALOG, items: DSS_ALARM_TYPE_CATALOG,
    alarmTypeList: DSS_ALARM_TYPE_CATALOG, groups: DSS_ALARM_TYPE_CATALOG,
    total: String(DSS_ALARM_TYPE_CATALOG.length), totalCount: String(DSS_ALARM_TYPE_CATALOG.length)
  };
}

// query alarm message count for the Event Center badge
export function buildEventCenterAlarmCountPayload() {
  return { count: '0', unhandledCount: '0', handledCount: '0', total: '0', todayCount: '0', status: '1' };
}

// subscription ACK: the client posts subscribeAddress/AddrType/User/Password/
// initMessageId and expects msgId + a polling/push channel back
export function buildEventCenterSubscribePayload(body = {}) {
  const msgId = String(body.initMessageId || '0');
  return {
    msgId: String(Number(msgId) || 0),
    subscribeId: 'sub-' + Date.now(),
    subscribeAddress: String(body.subscribeAddress || ''),
    interval: '1000',
    status: '1', success: true,
    messages: [], list: [], results: [], items: []
  };
}

// E-118: alarm event in the NATIVE schema (ParseAlarmEventNotify field names)
export function toNativeAlarmEvent(ev) {
  const t = String(ev.eventType ?? '99');
  const cat = DSS_ALARM_TYPE_CATALOG.find((a) => a.alarmTypeId === t);
  return {
    alarmCode: t, alarmType: cat?.alarmType || t, alarmTypeId: t,
    alarmTypeName: cat?.alarmTypeName || ev.eventTypeName || 'Generic Event',
    alarmLevel: String(ev.eventLevel ?? cat?.level ?? '1'),
    alarmGrade: '1',
    eventTime: ev.eventTime, eventCode: t, eventLevel: String(ev.eventLevel ?? '1'),
    eventId: ev.eventId, eventGrade: '1', eventType: t,
    eventSourceType: cat?.eventSourceType || '9',
    deviceCode: ev.deviceCode || '', deviceId: ev.deviceId || ev.deviceCode || '',
    deviceName: ev.deviceName || '',
    channelId: ev.channelId || '', channelCode: ev.channelId || '',
    channelName: ev.channelName || '',
    alarmTime: ev.eventTime, alarmId: ev.eventId,
    alarmPicture: '', alarmRecordPosition: '',
    recordTime: '', preRecordTime: '10',
    linkVideoChannels: ev.channelId ? [ev.channelId] : [],
    linkRecordChannels: [],
    mapIds: [], streamType: '0',
    nodeCode: ev.orgCode || '001',
    strMessage: ev.description || '', eventRemark: ev.description || '',
    gpsX: '0', gpsY: '0', height: '0', angle: '0', speed: '0',
    handleStatus: '0', status: '1'
  };
}
