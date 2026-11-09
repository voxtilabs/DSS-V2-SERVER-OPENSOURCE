# Mapa de compatibilidad — DSS Client 8.006 (WINPC_V2) ↔ BRMS Gateway VMS open source

Fuente REA (MCP operativo en esa ronda; offsets VA salvo nota):
- Mapa de exports: `ses_e43246d77ffen5H55I1rNxEW1X` — DPSDK.dll PE x86-64,
  1363 exports / 1360 `DPSDK_*` (sha256 ce43c8b7…ccc0d47).
- Mapa push/playback/contratos: `ses_e43246d72ffeu24WoOOUOjBPHv` (Ghidra sobre
  MSG.exe y UserLogical.dll; VA = offset de archivo + 0x1000 en .rdata).

## 1. Matriz feature → endpoint/protocolo → estado

| Feature | Exports DPSDK clave | Endpoint/protocolo | Estado |
|---|---|---|---|
| login/auth | Login, LoginByToken, ReloginByToken, VerifyUserPassword | authorize RSA 2 pasos + keepalive + updateToken + accounts/current | SERVIDO |
| tree | GetFullGradeDeviceTree, GetDeviceTreeInfo, GetOrgList | v1.0/v1.1 tree/* + full/grade-device-tree (e037/e124) | SERVIDO |
| device | AddDevice, DeleteDevice, GetDevicesByPage, SearchDevices | device/add(+batch), device/page, discover/* + ONVIF e026 | SERVIDO |
| users/roles | AddUser, UpdateRole, GetUserRight, SetResourceRoles | user/role CRUD + authority/resource/*/role | SERVIDO |
| monitor/MTS | StartRealPlay, OperateRealPlay | MTS/Video/{Start,Stop,KeepAlive}Video + relay RTSP 9100 → MediaMTX | PARCIAL (handshake sí; stream nativo ES no — relay+HLS) |
| playback histórico | StartPlaybackByTime, StartPlaybackByFile | SS/Playback/{Start,Stop,Pause,Resume} (E-131, sesión/url) | PARCIAL (sin índice de grabaciones real) |
| record/SS | QueryRecord, LockRecord, DeleteRecord | SS/Record/* espejado en v1.0/v1.1/admin | PARCIAL (stubs de listado) |
| alarm | GetPageAlarmRecords, ConfirmAlarm, GetAlarmTypes | alarm/plan/*, alarm/record/fetch/page, overview | PARCIAL (falta workflow AskForHandle/cuotas) |
| event/MQ | SetEventCallBack, SubscribeMspMessage, SetMQTopic | WS event + MQTT 1883 + STOMP 61613 + GetMqConfig + 88 topics | SERVIDO (fixes E-131) |
| ARS register | SaveUnAuthDevices, BatchAddUnauthorizedDevices | ars/* REST + TCP 9500 DVRIP/DHIP reensamblado (e119/E-128) | SERVIDO |
| p2p | GetP2PConfig, GetP2PConnectType | p2p/status, device/p2p-*, reachability, easy4ip/probe | PARCIAL (sin túnel P2P nativo) |
| upgrade | UpgradeDevice, ExecuteUpgradeTask | upgrade/check/upgradeable + omc/device/upgrade/* (E-127) | PARCIAL (planes/tareas genéricos) |
| license | ActiveLicense, ExportActiveLicenseFile | license/{item,used,detail,components,warning,active,deactivate,export,reactive} (E-131) | SERVIDO (mutaciones acusadas) |
| tvwall | GetTVWallList, AddTVWallTask, TVWallOpenWindows | tvwalls, tvwall/:id, VMS/TvWall/* RPC (E-131) | PARCIAL (sin decoder en wall) |
| map | AddRasterMap, GetVectorMap, ARGetLabel | emap/api map/vector, map/raster/list, map/label/* (E-131) | PARCIAL (sin mapas servidos) |
| config | GetFunctionConfig, GetLdapConfig, SaveMailConfig | config/* + dispatcher BRM/:ns/:fn | SERVIDO |

## 2. Contratos específicos verificados por REA (offsets)

- **MSG.exe WSS local** (no es el WS del gateway): puerto libre, TLS
  `/Cache/cert.pem`, handshake RFC6455 estricto (GET+upgrade+v13+key 16B →
  101 + accept SHA1+GUID), control `{"hub":"methods","method":"subscribe|
  unsubscribe","methods":[...]}`, cola MQ local `mq.*.msg.topic.*`.
- **GetMqConfig (FUN_1401b5f90)**: SessionId/UseMqFlag/SSLEnable/UnSSLPort/
  ProtocolVersion como **int**; TopicInfos `IsAccUser` string `"1"` →
  suscripción `<prefijo>.<Topic>`; 7 prefijos hardcodeados, 2 por GroupId
  (GroupId debe ser no vacío → `'1'`).
- **Envelope de alarma (FUN_1401b2e40)**: raíz exige `method` + `info`
  (`info.disarmUserIds`); el gateway ahora publica ambos (E-131).
- **StartVideo (DPSDK 0xc94088)**: campos reales url/session/token/vkId/trackId/
  port/ip/connectType/stunEnable/stunPort/multicastIp/multicastPort. Nota:
  `hlsUrl/url2/vkValue/fakeSdp/forceSynPlay/keyCode` son campos extra sin
  evidencia literal en DPSDK (se mantienen como cortesía, ignorados).
- **RTSP cliente DPSDK**: `Dahua Rtsp Client/2.0`, SETUP+PLAY en la misma URL,
  `interleaved 0-1↔2-3`, sin DESCRIBE; relay e115 ya resuelve este framing.
- **UserLogical.dll**: wrapper fino (98 imports DPSDK_*); `IsKeyValid` NO está
  aquí — vive en **APIModule.dll 0xa73a98** y **PluginFactory.dll 0x1a7f82f**
  (validación de RPC plugin, no REST).
- **554/37777**: outbound al dispositivo Dahua nativo; el gateway no abre
  listener (cerrado).

## 3. Pendientes aceptados / abiertos (no bloquean el flujo 8.006)

1. Stream nativo DPSDK (ES+frames) → hoy relay RTSP/HLS (por diseño ONVIF).
2. Playback histórico sin índice real de grabaciones.
3. Túnel P2P nativo (CP2PServerManager) para equipos sin internet.
4. Workflow completo de alarmas (AskForHandle, duty, cuotas).
5. Mapas emap servidos (raster/vector) y decoder TVWall.
6. WS-server local de MSG.exe (`siteSessionId`) sin contraparte — el gateway
   cubre push vía MQTT+STOMP+WS propio.
