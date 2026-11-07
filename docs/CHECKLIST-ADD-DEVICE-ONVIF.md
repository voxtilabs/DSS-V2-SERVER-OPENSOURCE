# CHECKLIST — Error de conexión "Add Device ONVIF" (DSS Client 8.006 WINPC_V2 → Gateway DSS V2 lab 10.10.20.120)

> **LEER PRIMERO.** Este archivo es el checkpoint vivo del incidente. Cualquier
> modelo/agente que trabaje este bug debe leerlo antes de proponer soluciones y
> NO repetir las ya descartadas (sección "NO repetir"). Actualizar la sección
> "Checkpoint" al final de cada avance real (commit + deploy + tests verdes).

- **Síntomas del operador**: al agregar la cámara ONVIF 192.168.0.238:8021 el
  diálogo CDevAdd muestra "Operation timed out"; en Discover Device la cámara
  aparece INITIALIZED, join/batch dice "Successfully added" pero el árbol no la
  muestra; Management→Sites muestra "Failed to get organizations or devices.
  Please double-click organization node again."; el combo Organization no lista
  VIGILAB.
- **Lab**: gateway `https://10.10.20.120:1443` (admin/admin123, realm
  DSS-V2-LAB), HTTP interno 11443, RTSP 9100, **OpenWire ssl://61616**,
  STOMP 61613, **MQTT 1883** (broker del gateway, dual-push `brms.notify*`).
  Broker keystore fuera del repo (`~/certs/activemq.p12`). PC cliente:
  **ESTA MÁQUINA** (WINPC_V2, `DSS Client` PID 25900 + `MSG.exe` PID 15864,
  install `C:\DSS\DSS Client`, logs locales en `sdk_log\sdk_log.log`); el
  servidor la ve como **10.10.20.1** (pfSense 10.10.20.1 con Tailscale comparte
  la subnet — el origen real es 100.72.31.17).
- **Repo**: `poc/dss-v2-harness/` (gateway `brms-gateway/src`, e2e
  `e2e-lan-test.mjs`, compose, `activemq-ssl.xml`). Docs de contratos:
  `docs/NETWORK_PROTOCOLS.md` §31-§33.

## Evidencia recolectada (logs server-side)

| Fecha sesión (UTC) | Log | Hecho |
|---|---|---|
| 2026-11-04 22:14:49–22:15:51 | gw4.log | GetMqConfig 200 (4026B) ×2; `tree/deviceOrg?orgCode=` 200 (1724B, 001+VIGILAB); `tree/devices` 200 (154B = vacío, el e2e había borrado el registro); `fish-eye-data` 200 (89B); add 22:15:51 → 200 (5543B) **persistió** (D0238E885012, orgCode VIGILAB); join/batch 22:15:56 → 200 con `ids:[D0238E885012], orgCode:""`. **Cero requests HTTP después del join/batch.** |
| 2026-11-04 22:14–22:16 | amq4.log | Broker: sólo startup, **0 eventos de conexión** (MSG.exe nunca marcó 61616). |
| 2026-11-04 23:28:25–23:29:07 | gw6.log | Sesión con el payload NUEVO (mqtt="10.10.20.120:1883" desplegado desde 22:56): GetMqConfig 200 ×2; add 23:29:01.832 → 200 (6036B, body ONVIF completo `deviceName:EBAVOLVIO...`); `device/page` 23:29:01.893 → 200 (3401B, con la cámara); join/batch 23:29:06.802 `ids:[D0238JDG3016], orgCode:""` → 200 (2552B); **sí** re-fetch `discover/device/page` 23:29:06.849 y `device/page` 23:29:07.495, pero **nunca** `tree/deviceOrg`/`tree/devices` después del join. |
| 2026-11-04 23:0x–23:3x | gw6.log `[MQTT]` | Todos los `PUBLISH brms.notify* -> 0 subscriber(s)`. El único cliente MQTT que conectó fue `e2e11-sub` (mi e2e). El cliente nativo no abrió 1883. |
| 2026-11-04 ~21:55 UTC (sesión viva) | netstat local + `docker exec activemq cat /proc/net/tcp` + Jolokia 8161 | **REFUTADO "0 conexiones a 61616"**: MSG.exe (PID 15864) tiene `100.72.31.17:58816 -> 10.10.20.120:61616 ESTABLISHED`; dentro del contenedor hay ESTABLISHED en 61616 desde 10.10.20.1; Jolokia: `CurrentConnectionsCount=2`. ActiveMQ 6.2 NO loguea conexiones exitosas a INFO (log de 41 líneas = sólo startup) — la ausencia de logs no prueba ausencia de conexión. |
| 2026-11-04 ~21:57 UTC | Jolokia topics | **MSG.exe SÍ está suscripto, pero a los topics `mq.*`**: `ConsumerCount=1` en `mq.common.msg.topic`, `mq.vehicle.msg.topic`, `mq.alarm.msg.group.topic.`, `mq.event.msg.topic.1`, `mq.alarm.msg.topic.1`, `mq.carsurvey.alarm.msg.topic.1` (todas con `EnqueueCount=0` — nadie publicó nunca ahí). En `brms.notifyBatchAddDevices`/`brms.notifyChannelStatuses`: `ConsumerCount=0`, `EnqueueCount=152`, `DequeueCount=17` ( ésos son los publish del gateway por STOMP 61613 + consumidores del e2e). **Conclusión: el gateway publica notify a `brms.notify*` pero el cliente escucha sólo `mq.*` ⇒ el notify nunca llega.** |

## Contratos RE-verificados (Ghidra/javap, no adivinar)

- GetMqConfig (DPSDK `FUN_180214d60`, descriptor `FUN_1806755a0`): 5 claves
  STRING = `password`, `addr`, `mqtt`, `enableTls`, `userName`. `addr` es el
  "MQ Config" que se imprime en el log del cliente y se deriva a MSG.exe.
  `mqtt` vacío ⇒ pipe a MSG.exe (OpenWire); `mqtt` no vacío ⇒ rama libcurl-MQTT
  (DPSDK tiene libcurl con soporte MQTT: "mqtt_doing", "No MQTT topic found…";
  arma la URL con su formatter "%s://%s" ⇒ `mqtt` se sirve como `host:port`).
- MSG.exe (`CMQSDKManager::MQInit`, file 0x1f6340): construye
  `failover:(ssl://%s)?startupMaxReconnectAttempts=1&...` (variante tcp://
  existe) y setea `decaf.net.ssl.disablePeerVerification` ⇒ el broker sirve
  OpenWire sobre TLS en 61616 (`activemq-ssl.xml`, p12 de la System CA del lab).
- Árbol nativo: VO reales del paquete servidor V8.008 (javap) declaran
  `hasChild`/`checked`/`pId` como **String** ⇒ se sirven `"1"`/`"0"`.
  `BRMS.Organization.GetOrganizations` (descriptor `FUN_1806c97f0`, GET) llena
  Management→Sites (CMenuTreeWidget, toast en PluginFactory.dll 0x19fc170) con
  `GetOrganizationsVo{orgName,orgCode,parentOrgCode,sourceType,sourceId,
  associateId,remark,authority}`. `fish-eye-data` = `FishEyeDataVo{
  results:[FishEyeXo{orgCode,fileData}]}` (vacío legítimo).
- DPSDK lanza MSG.exe vía `MSGLogic::CProcessLogic::CreateMsgProcess`
  (string "MSG.exe" xref 0x180bda2d4) y escribe el pipe `<tomsgpipe>`
  (xref 0x180a48457, builder `FUN_180a488e0`, caller `FUN_180a406e0`).
- **MSG.exe (RE 2026-11-04 ~21:45)**: strings `failover:(ssl://%s)?startupMaxReconnectAttempts=1&wireFormat.maxInactivityDuration=0&connection.connectResponseTimeout=5000`
  y variante `failover:(tcp://%s)?...`; setea `decaf.net.ssl.disablePeerVerification`
  ⇒ ssl:// a 61616 con cert auto-firmado OK (coincide con la conexión viva).
  Pool de topics hardcodeado: `mq.alarm.msg.queue`, `mq.alarm.msg.topic.`,
  `mq.alarm.msg.group.topic.`, `mq.event.msg.group.topic.`, `mq.event.msg.topic.`,
  `mq.common.msg.topic`, `mq.carsurvey.alarm.msg.topic.`, `mq.vehicle.msg.topic`
  + formatter `%s.%s` (sufijo = UserId/GroupId del pipe) ⇒ las suscripciones
  `mq.*.msg.topic[.1]` vistas en el broker. Claves del pipe: `process, method,
  id, name, normalpipe, frequentpipe, tomsgpipe` y config `SessionId, UseMqFlag,
  MQUser, MQPwd, UserId, GroupId, SSLEnable, UnSSLPort, CertificatePath,
  ProtocolVersion, TopicInfos{Topic,IsAccUser}, MQConfig, SetMQTopic,
  SendMQMessage, StartRelogin, MQConnState, LocalCfg, DestroyMQ, WebsocketPort,
  StartWebsocketServer, ChangeMQTopic`.
- **activemq.dll (cliente)**: tabla de esquemas `openwire|stomp|tcp|ssl|nio|nio+ssl|mock|failover`
  y default `failover:(tcp://localhost:61616)`.
- **DPSDK pool de métodos MQ** (file 0xc71000+, ej. `brms.batchAddDevices`
  xref lea 0x180bbd094): `vms.addDev`, `brms.batchAddDevices`, `vms.notifyDeviceStatus`,
  `brms.notifyChannelStatuses`, `erms.organization.addOrganization`,
  `vms.LogicOrg`, … `Dpsdk::CDpsdkCore::ParseMQMsg` ("begin parese len=%d,strMsg=%s")
  y `HandleFrquentMQMsg` con claves `info`, `devices`, `addChannels`, `deleteChannels`.
- **PluginFactory.dll**: los 5 thunks de "Operation timed out." (0x1808f31d0,
  0x18094cf90, 0x180a66650, 0x180ab9430, 0x180ac9c50) son sólo toasts
  (`DSMessageNotify::AddTextNotification/AddErrorNotification`); sus llamadores
  (quién espera qué) en 0x1808fd03f, 0x180a46aae, 0x180aad18d, 0x180aedbf2,
  0x180aee237 — decomp en curso (gh-run-pf2). `FUN_180a33ca0` = handler del
  resultado de Add Device: lista vacía ⇒ toast "Successfully added the devices."
  + refresh; por ítem: código 0 ⇒ detalle "Add Device: <name>", 0x1aeb6 ⇒
  región, 0x1ae21 ⇒ no soportado, otro ⇒ "Failed to add device".

## ✅ Arreglado y verificado (NO tocar)

1. ActiveMQ sirve **ssl:// 61616** (p12 lab) — handshake TLS verificado,
   E2E-12 hace `tls.connect(61616)` + WireFormatInfo.
2. GetMqConfig sirve **doble capa** (legacy `UseMqFlag/MQConfig/MQType/MQUser/
   MQPwd/SSLEnable/UnSSLPort/ProtocolVersion/TopicInfos` + descriptor
   `addr/userName/password/enableTls/mqtt`) con `addr=MQConfig=10.10.20.120:61616`
   y **`mqtt="10.10.20.120:1883"`** (commit 31e8a2f).
3. Árbol con tipos string (`"1"/"0"`), descriptor completo de
   grade-device-tree (`FUN_1806d33a0`), GetOrganizations RPC (GET+POST),
   fish-eye `results:[]` (commits 20070bc, 329b4b3).
4. e2e cleanup seguro: `CREATED_CODES` + `PRE_EXISTING_CODES` (el add es
   idempotente por ip:port y devuelve el deviceCode del operador — jamá
   borrarlo; incidentes 22:10 y 23:03:37). live-verify.cjs tiene la misma
   guarda.
5. Tests verdes en vivo (estado al 2026-11-04 ~23:35): unit **45 pass / 0 fail /
   1 skip** (`node --test --test-timeout=20000 --test-reporter=spec src/test/*.test.js`
   en `brms-gateway`), e2e **12/12 ×3** (`node --test e2e-lan-test.mjs`), live-verify
   **15/15** (scp a /tmp + `docker exec -i dss-v2-harness-brms-gateway-1 node - < /tmp/live-verify.cjs`).
   La cámara del operador (D0238JDG3016, NUEVAMENTEVOLVIOAFALLAREBA, orgCode
   VIGILAB) **sobrevive** a las 3 corridas e2e y aparece en deviceOrg
   (`hasChild:"1"`, `device:[{id}]`), tree/devices, grade-device-tree y RTSP
   DESCRIBE 200.
6. **E-093**: `GET /ipms/api/v1.1/organization/list` ya NO va vacío — sirve
   el store persistente **001 root + VIGILAB** con doble clave
   `list`/`results` + `total`/`count` y claves de org según
   RE-SCHEMA-DPSDK.md §5.2 (`orgCode, orgName, id, parentCode, sort, domainId,
   modifyTime, channels, deparmentsCount` [sic]) + descriptor GetOrganizationsVo
   (E-087) + alias de árbol `hasChild`/`checked` como "1"/"0" (commit
   `5461508`; alias BRMS `/brms/api/v1.{1.0,1.1}/organization/list` también).
   Verificado en vivo: 200 con `list=2 results=2 total=2 count=2`. ⇒ el combo
   Organization de CDevAdd (`cmbGroupName`) ya lista VIGILAB.

## ❌ Abierto / bloqueante actual

- **El notify no llega al cliente nativo**: MSG.exe está conectado a
  ssl://61616 y suscripto a los 6 topics `mq.*.msg.topic[.1]`, pero el gateway
  publica los notify sólo a `brms.notify*` (STOMP 61613 → ActiveMQ y MQTT 1883
  del gateway) donde hay `ConsumerCount=0`. Ningún mensaje llegó nunca a
  `mq.*` (`EnqueueCount=0`). Consecuencia: CDevAdd expira su timer esperando
  el notify `brms.batchAddDevices` ("Operation timed out") y el árbol no se
  refresca solo tras join/batch.
- Fix en evaluación (RE en curso, gh-run-pf2 / gh-run-dpsdk4): (a) publicar el
  notify con `method:"brms.batchAddDevices"` a los topics `mq.*` que el cliente
  escucha (p.ej. `mq.common.msg.topic`), y/o (b) hacer que el cliente se
  suscriba a `brms.notify*` vía `TopicInfos` con `IsAccUser=1` (semántica RE
  pendiente en el parser DPSDK 0x180a496ec).
- Logs del cliente ya son accesibles localmente (`C:\DSS\DSS Client\sdk_log\sdk_log.log`,
  sólo componente Netsdk; falta hallar el log DPSDK/MSG con "MQ Config is %s" /
  "CreateMsgProcess").

## 🚫 NO repetir (ya descartado con evidencia)

- Servir OpenWire plano en 61616: MSG.exe siempre hace ssl:// (disablePeerVerification).
- `hasChild`/`checked`/`pId` como booleanos JSON: el parser liga strings.
- Quitar `addr` del GetMqConfig: era el "MQConfig vacío" del intento 3.
- `mqtt:""` con la expectativa de que MSG.exe marque 61616: pasó (0 conexiones
  *en el log*, pero la conexión SÍ existe — ver evidencia Jolokia de ~21:55;
  el log del broker no sirve como prueba negativa).
- "0 eventos de conexión en el log de ActiveMQ ⇒ el cliente no conecta":
  falso en ActiveMQ 6.2 (las conexiones exitosas no se loguean a INFO).
- Cleanup del e2e por prefijo de nombre ("EBA*") o por ip: borra la cámara del
  operador. Sólo códigos creados en la corrida y no pre-existentes.
- `enableTls:"0"/"1"`: no cambia el transporte (lo elige MSG.exe internamente).
- No tocar los 3 scripts untracked: `analyze-prod-pcap.mjs`, `generate-certs.mjs`,
  `inspect-client-plugins.mjs`.

## Checkpoint de avance

- **Checkpoint 2026-11-04 ~23:35 UTC — commits `31e8a2f` (código mqtt=1883 +
  cleanup seguro) y `bec3a63` (docs), pusheados a origin/main. Desplegado en el
  lab y verificado: unit 45/0/1, e2e 12/12 ×3, live-verify 15/15, registro del
  operador intacto.**
- **Checkpoint 2026-11-04 ~22:05 UTC — evidencia viva (este commit, docs):
  el cliente corre EN ESTA MÁQUINA; MSG.exe (PID 15864) está ESTABLISHED a
  ssl://10.10.20.120:61616 (verificado en host y dentro del contenedor + Jolokia
  `CurrentConnectionsCount=2`) y suscripto a 6 topics `mq.*.msg.topic[.1]`
  (`ConsumerCount=1`, `EnqueueCount=0`). Los `brms.notify*` que publica el
  gateway tienen `ConsumerCount=0`. ⇒ **la causa raíz del "Operation timed
  out" es de transporte de notify: el cliente escucha `mq.*`, el gateway
  publica `brms.notify*`.** RE nuevo: MSG.exe `failover:(ssl://%s)…` +
  `disablePeerVerification` + pool `mq.*.msg.topic`; DPSDK pool de métodos con
  `brms.batchAddDevices` (dispatch 0x180bbd094) y `ParseMQMsg`/`HandleFrquentMQMsg`
  (`devices`/`addChannels`/`deleteChannels`); PluginFactory: 5 toasts de
  "Operation timed out." con llamadores en 0x1808fd03f/0x180a46aae/0x180aad18d/
  0x180aedbf2/0x180aee237 (decomp pf2 en curso) y `FUN_180a33ca0` = handler del
  resultado de add.**
- **Checkpoint 2026-11-04 ~22:40 UTC — FIX E-088 desplegado y verificado:
  el notify ahora se publica TAMBIÉN a los topics `mq.*.msg.topic[.1]` que
  MSG.exe escucha (STOMP 61613), con envelope
  `{"method":"brms.batchAddDevices"/"vms.deleteDev", params:{operation,
  addOrgCode, deleteOrgCode, addChannels, deleteChannels, devices}, ...flat}`
  (`buildClientNotifyEnvelope`/`clientMqTopics` en e039-mq-notify.js).
  Verificación en vivo: Jolokia muestra `mq.common.msg.topic`
  EnqueueCount=34/**DequeueCount=34** (MSG.exe consumió todos tras el deploy)
  y ConsumerCount=1 en los 6 topics mq.*. Tests: unit 46/0/1, e2e 12/12 ×3
  (una corrida con flake SIP UDP E2E-7 tras el rebuild, luego 3 limpias),
  live-verify 15/15, cámara del operador D0238JDG3016 intacta.**
- **Checkpoint 2026-11-05 ~02:10 UTC — segunda causa raíz (E-089), fix
  desplegado (`e5d6b9c`)**: aunque el notify llegaba al broker
  (Enqueue=Dequeue en mq.*), el cliente lo descartaba porque ActiveMQ
  Classic mapea un STOMP SEND **con `content-length` a `ActiveMQBytesMessage`**
  (LegacyFrameTranslator.convertFrame) y MSG.exe (decaf OpenWire) espera
  **TextMessage**. Evidencia Jolokia browse: mensaje a `/queue/e088probe`
  (sólo content-length) => `BodyPreview` bytes, sin campo `Text`;
  `/queue/e088probe2` con `amq-msg-type:text` => campo `"Text"` con el JSON.
  Fix: `e040-amq-notify.js` ahora envía `amq-msg-type: text` en cada SEND
  (content-length se conserva para framing; amq-msg-type tiene prioridad).
  Verificado en vivo: MESSAGE entregado a `/topic/mq.common.msg.topic` con
  `amq-msg-type:text`. Tests: unit 46/0/1, e2e 12/12 ×3 (1 flake SIP/UDP E2E-7
  intermitente), live-verify 15/15 post-deploy. Sesión del operador
  2026-11-05 01:38:29 add → 01:38:34 join/batch → 01:39:03 logout SIN re-fetch
  de árbol (cliente ya corría con el fix E-088 pero sin E-089; además al
  logout MSG.exe cerró la suscripción — ConsumerCount=0 hasta el próximo
  login).**
- **Checkpoint 2026-11-05 ~03:10 UTC — tercera causa raíz (E-091), fix
  desplegado y verificado en vivo (`16f7e0f`)**: el envelope llegaba al broker
  y MSG.exe lo consumía, pero `Dpsdk::CDpsdkCore::ParseMQMsg`
  (FUN_1800306b0) **hace bail si el root del body NO tiene las claves
  `"info"` (DAT_180c76d40, string "info" @ VA 0x180c76d40) y `"method"`**;
  luego FUN_1800309c0/FUN_180030ed0 toman `root["info"]` y se lo pasan al
  handler registrado para el método (FUN_180bbd090 → LAB_180bdb2f0 →
  FUN_1800328b0 → FUN_180363e30), que lee de ESE objeto: `operation` (int,
  1=add/2=del/3=delOrg, return 0<op<4), `addOrgCode`/`deleteOrgCode`
  (string), `addChannels`/`deleteChannels` (array de strings), y
  FUN_1803bdc60 lee además `timeCell` (int) y `devices`. El envelope viejo
  usaba `params` y claves flat → ParseMQMsg descartaba el mensaje antes de
  despachar. Además `addChannels` debe llevar **channel codes**
  `<deviceCode>$1$0$<seq>` (layout E-038), no el deviceCode.
  Fix en `buildClientNotifyEnvelope`: root = `{method, info: payload,
  params: payload, ...payload}`; `info` incluye method/operation/addOrgCode/
  addChannels(channel codes)/deleteChannels/timeCell/devices[VO completo con
  channels]. Verificado EN VIVO con suscriptor STOMP a
  `/topic/mq.common.msg.topic` durante un add real: el MESSAGE entregado es
  exactamente `{"method":"brms.batchAddDevices","info":{"operation":1,
  "addOrgCode":"VIGILAB","addChannels":["D0238JDG3016$1$0$0"],...}}`.
  Ojo parser: ActiveMQ 6.2 emite EOLs entre frames STOMP (un `\n` antes de
  cada frame) — hay que strippearlos antes de leer el comando.
  Estado servidor OK (state-probe): device/page 1 row D0238JDG3016
  orgCode=VIGILAB online; tree/orgs VIGILAB bajo 001 con device+channel;
  tree/devices, tree/channels, grade-device-tree y admin tree/deviceOrg
  todos incluyen D0238JDG3016 / D0238JDG3016$1$0$0. Tests post-fix: unit
  46/0/1, e2e 12/12 ×3 limpias, live-verify 15/15 post-deploy.
  Sesión operador 02:10:57 add (200) + re-fetch tree/devices 48506B — el
  server ya era consistente; el gap era 100% el descarte en ParseMQMsg.**
- **Siguiente paso**: retest del operador con el cliente CERRADO y reabierto
  (MSG.exe reconecta ssl://61616 y re-suscribe mq.* en el login): relogin,
  Add Device ONVIF 192.168.0.238:8021, Discover join, combo Organization
  (VIGILAB), Management→Sites. Con E-088 (topics mq.*) + E-089
  (amq-msg-type:text → TextMessage) + E-091 (envelope method+info con channel
  codes) el notify debe despachar en DPSDK y el cliente re-pedir
  tree/deviceOrg+tree/devices sin "Operation timed out". Monitorear:
  `docker logs dss-v2-harness-brms-gateway-1` ([E039-NOTIFY]) y Jolokia
  Enqueue/Dequeue en mq.common.msg.topic[.1] con ConsumerCount=1 mientras el
  cliente está logueado.
- **Checkpoint 2026-11-05 ~04:00 UTC — cuarta causa raíz (E-092), fix
  desplegado (`0ab903d`)**: RE-SCHEMA-DPSDK.md (Ghidra dpsdk7–11) probó que
  `brms.batchAddDevices` es SÓLO el ACK de resultado
  (`info={session,successfulCount,failedCount}` → callback UI 0x5e) y **no
  lleva devices/channels** — el método que mete el dispositivo+canales en el
  árbol es `vms.LogicOrgChannel` `info={operation:1..3, addOrgCode,
  addChannels:["<dev>$1$0$<seq>"], deleteOrgCode, deleteChannels}` (parser
  FUN_180363e30, handler FUN_1800328b0); `vms.addDev` mete el nodo dispositivo
  completo (parser FUN_180364830/FUN_1803649a0, callback 0xd). Nuevo
  `buildClientNotifyEnvelopes(type, device)` en e039-mq-notify.js devuelve los
  3 sobres (add: vms.LogicOrgChannel op=1 + vms.addDev + ACK
  brms.batchAddDevices{session:'',successfulCount:1,failedCount:0};
  delete: op=3 + vms.deleteDev{devices:[...]}) y `createNotifyHub` publica
  CADA sobre a TODOS los `clientMqTopics(userId)` (bare + sufijo). Tests:
  unit 46/0/1, e2e 12/12 ×3, live-verify 15/15; desplegado
  (scp + `docker compose up -d --build brms-gateway`, container Up).
- **Checkpoint 2026-11-05 ~04:05 UTC — evidencia UI (RE PluginFactory.dll en
  curso, run-ghidra-pf.bat)**: el diálogo CDevAdd vive en PluginFactory.dll
  (string "CDevAdd" @ VA 0x1819a9828); su combo de organización es el widget
  **`cmbGroupName`** (label `lblGroup` @ 0x1819a9d78), llenado por código en
  0x180a9ea25 (setup findChild en 0x18095d3ff). En la sesión operador
  03:31–03:37 el cliente llamó `GET /admin/API/tree/deviceOrg?orgCode=`
  (200, 6028B, con VIGILAB), `POST /admin/API/tree/devices` (200, 12330B) y
  **`GET /ipms/api/v1.1/organization/list` → 200 cl=59 = `{list:[],total:0}`
  VACÍO** (index.js:1047) — principal sospechoso del combo vacío; el
  join/batch salió con `orgCode:""` (03:32:01) ⇒ el join no amarra a VIGILAB.
  Pendiente: contrato exacto que lee cmbGroupName (RE) antes de tocar
  endpoints de org. **RESUELTO por E-093 (checkpoint abajo, commit
  `5461508`)**: el endpoint ahora sirve 001+VIGILAB con doble clave
  list/results + total/count; el contrato que alimenta el combo es DPSDK
  `CRestLogical::GetOrgList` (FUN_1802af3d0 → `v1.1/organization/list`,
  parser `FUN_1804c5f00`).
- **Checkpoint 2026-11-05 ~14:20 UTC — quinta causa raíz (E-093), fix
  desplegado y verificado en vivo (`5461508`)**: el combo Organization de
  CDevAdd (`cmbGroupName`) se alimenta de `GET /ipms/api/v1.1/organization/list`
  (DPSDK `CRestLogical::GetOrgList` FUN_1802af3d0, parser
  `CDpsdkManager::GetOrgList` FUN_1804c5f00) y el gateway lo servía vacío
  (`{list:[],total:0}`, cl=59) ⇒ combo vacío y join/batch con `orgCode:""`.
  Fix: `buildOrganizationListPayload()` en `e041-orgs.js` sirve el store
  persistente (001 root + VIGILAB) con doble clave `list`/`results` +
  `total`/`count`; claves de cada org según RE-SCHEMA-DPSDK.md §5.2
  (`orgCode, orgName, id, parentCode, sort, domainId, modifyTime, channels,
  deparmentsCount` [sic]) + descriptor GetOrganizationsVo (E-087) + alias de
  árbol (`hasChild`/`checked` como "1"/"0"). Rutas: `/ipms/api/v1.1/
  organization/list` (GET+POST) y alias BRMS `/brms/api/v1.{1.0,1.1}/
  organization/list`, registrados antes del fallback `/ipms/api/*`.
  Tests: unit **47 pass / 0 fail / 1 skip** (incluye test E-093), e2e
  **12/12 ×3** pre-deploy contra el lab (baseline verde). Deploy: scp de
  `brms-gateway/src/` a `bruno@10.10.20.120:~/dss-v2-harness/brms-gateway/`
  + `docker compose up -d --build brms-gateway` (container Up). Post-deploy:
  live-verify **15/15** (cleanup saltado: D0238JDG3016 pre-existente) y
  `GET /ipms/api/v1.1/organization/list` → **200 `list=2 results=2 total=2
  count=2`** con `001/root (hasChild="1")` y `VIGILAB/VIGILAB
  (parentCode="001")` — verificado dentro del contenedor (127.0.0.1:11443) y
  desde fuera por `https://10.10.20.120:1443`. **Cámara del operador
  D0238JDG3016 intacta** (device/page 1 row, orgCode VIGILAB, RTSP
  `cam_D0238JDG3016` DESCRIBE 200). Logs: `%TEMP%\opencode\e093-*.log`.

- **Checkpoint 2026-11-05 ~16:10 UTC — sexta causa raíz (E-094), fix
  desplegado y verificado en vivo (`18cbedf`)**: sesión operador 15:55 UTC
  mostró toast **"Successfully added the devices."** (¡el "Operation timed
  out" ya no aparece!) y Discover con la cámara **Initialized**, pero la
  tabla Device Config mostraba **"Total 0 record(s)"**. Causa raíz hallada en
  el bundle web REAL servido por el gateway (`web-module/js/index-yv7-szZK.js`,
  componente `deviceTable`): la tabla llama **GET `/omms/api/v1.1/device/page`**
  (`useDeviceApi-CXeZa_J4.js` `getPageDevices`) y lee **`data.pageData` +
  `data.totalCount`**; esa ruta no estaba registrada (caía al fallback vacío)
  y `buildDevicePagePayload` no incluía `pageData`. El árbol de la izquierda
  usa `getOrg` → `/ipms/api/v1.1/organization/list` leyendo `data.results`
  con `orgCode/orgName/parentOrgCode` (ya cubierto por E-093).
  Fix: `pageData` + filas con `orgName/orgCode/onlineStatus/deviceTypeName`
  y filtro `orgCode` con `containChild` (descendientes incluidos) en
  `buildDevicePagePayload` (e025-devices.js); rutas registradas en index.js:
  `GET/POST /omms/api/v1.1/device/page`, `/omms/api/v1.1/channel/page`,
  `/omms/api/v1.1/device/channel/page` (todos con pageData+totalCount),
  `/omms/api/v1.1/device/statistics[/group-by-device-category/list]` y
  `/omms/api/v1.1/device/export`. Tests: unit **48 pass / 0 fail** (test
  E-094 incluido), e2e **12/12 ×3**. Deploy: scp + `docker compose up -d
  --build brms-gateway` (Up). Post-deploy: live-verify **15/15** y en vivo
  `GET /omms/api/v1.1/device/page?orgCode=&containChild=1` → **200
  code=1000 pageData=1 totalCount=1**, fila `D0238JDG3016 192.168.0.238:8021
  org=VIGILAB/VIGILAB onlineStatus=1`; `orgCode=VIGILAB` → 1 fila;
  `orgCode=NOPE` → 0; `omms channel/page` → pageData=1. D0238JDG3016 intacto.
  Logs: `%TEMP%\opencode\unit-e094.log`, `e2e-e094-{1,2,3}.log`,
  `live-verify-e094.log`.

- **Checkpoint 2026-11-05 ~23:45 UTC — séptima causa raíz (E-095), fix
  desplegado y verificado en vivo (`ca111cd`)**: la fila aparecía en la
  tabla Device pero en **Offline** aunque el server sabía que estaba online.
  Causa raíz verificada en el bundle real servido
  (`web-module/js/device-JBrSmGvP.js`: `DEVICE_STATUS:{OFFLINE:"0",
  ONLINE:"1",SLEEP:"2"}` — **strings**) y en las tablas SPA que comparan con
  `===` estricto (`index-DsQ1Ve9V.js`: `e.status === DEVICE_STATUS.ONLINE`;
  `index-CW-2lZHA.js`: `e.channelStatus === DEVICE_STATUS_TYPE.ONLINE`):
  nuestras filas enviaban `status: 1` **numérico** → `1 === "1"` es false →
  caía al else → "Offline". La tabla omms (`index-yv7-szZK.js`) lee texto de
  `statusName` e icono de `status` (loose ==). Fix (contratos RE-SPA-part2/3/4
  de `%TEMP%\opencode\`): `buildDeviceTableRow` emite `status/online/
  onlineStatus` como strings `"1"/"0"` + `statusName`/`faultStatusName` +
  columnas restantes de deviceTable; filtros CSV `status/faultStatus/
  deviceTypes/deviceCategory/deviceCode`; `channelVo` con `status:"1"`,
  `channelStatus:"1"`, `statusName:"Channel Online"`; contadores reales en
  `/omms/api/v1.1/device/statistics` (top-level `deviceCount/
  onlineDeviceCount/...`), `/account/device/overview` derivado del registro y
  `statistics/...group-by...` con `onlineCount` real; nuevas rutas
  `POST /omms/api/v1.1/device/status/history/record/fetch/page` (pageData con
  status/statusName/startTime/endTime/duration), `.../export` y
  `device/export` (session+fileUrl), `GET .../device/disk/status/page`,
  `GET /omms/api/v1.1/device/{code}` (detalle con status/statusName/
  offlineReason/faultReason/updateTime); diccionarios ANPR pedidos en vivo
  (2001/2016/2052/2053/2055/22/9041/9046) en `e024-catalogs.js`;
  `GET /brms/api/v1.1/user/list` real (admin) fuera del FALLBACK.
  Hallazgo RE-SPA-part4: la página DeviceStatus **no hace polling** — refresca
  solo al montar/cambiar pestaña/nodo/búsqueda (por eso bastaba con F5); el
  estado en tiempo real en otras vistas llega por push eventBus
  `vms.notifyDeviceStatus`/`vms.notifyDeviceOffline`. Tests: unit **49 pass /
  0 fail / 1 skip** (test E-095: `row.status === "1"` estricto), e2e
  **12/12 ×3**. Deploy + live-verify **15/15**. En vivo post-deploy:
  `omms+brms device/page` → `D0238JDG3016 status="1" statusName="Online"
  faultStatus="0" faultStatusName="Normal"`; statistics 1/1/0/0; history
  `status=1/Online`; detail `status=1 statusName=Online`; channel
  `channelStatus=1 statusName=Channel Online`; dict 2001=12 2016=15 2052=5
  2053=12 2055=9 22=6 9041=8 9046=5; user/list admin; overview
  `{deviceCount:1, onlineDeviceCount:1, offlineDeviceCount:0}`. Logs:
  `%TEMP%\opencode\unit-e095.log`, `e2e-e095-{1,2,3}.log`,
  `live-verify-e094.log`, `check-e095.ps1`.
  **Pendiente conocido**: el toast residual "Operation timed out" en CDevAdd
  proviene del waiter de 30 s del diálogo nativo (PluginFactory.dll
  `DAT_181f98388`) y del probe directo del cliente a 192.168.0.238 (inalcanzable
  desde WINPC_V2; sdk_log: error 90002002) — server-side la secuencia de add
  es toda 200 en 5-18 ms (cost-time/summary/device/join-batch) y el ACK MQ
  `brms.batchAddDevices` {session:'',successfulCount,failedCount} ya llega
  (toast "Successfully added the devices").


- **Checkpoint 2026-11-06 - E-096/E-097 (User/Role Management + push sin
  refresh), commit a523ea5**. RE: User Management nativo (UserLogical.dll
  -> DPSDK_GetUserManagerUsers -> v1.1/user/page; mapa completo DPSDK.dll
  @0xc9cfe0-0xc9d898 + tabla de metodos MQ @0xc711f8-0xc71840 con
  vms.notifyDeviceStatus/notifyDevChannelStatus @0xc71358/0xc71370).
  Implementado server-side: GET /brms/api/v1.1/user/page (pageData con
  id/username + flags STRING "1"/"0", filtros, admin visible),
  /user/group/list + /user/group-by-role-level/list (grupo Default),
  /config/ldap (GET/PUT), /user/:id (GetUser), lock/unlock, Add/Save/
  DeleteUser akcs, /user/email/associate/list + /user/email/page,
  GET /brms/api/v1.1/role/:id (GetRole) + CRUD role acks. E-097
  (no-refresh): e039 buildDeviceStatusNotifyEnvelopes ->
  vms.notifyDeviceStatus + vms.notifyDevChannelStatus (status STRING "1",
  E-095) publicados a los topics mq.* al terminar el provisioning de cada
  funnel de add (scheduleStreamProvisioning + addDeviceHandler) y frame WS
  eventBus para SPA. Tests: unit **51 pass / 0 fail / 1 skip** (E-096,
  E-097 nuevos), e2e **12/12 x3**, deploy + live-verify **15/15**. En
  vivo: user/page admin status="1" online="1", group/list Default,
  ldap 200, role/1 Administrator, user/1 admin, y log
  "[E039-NOTIFY] DEVICE_STATUS D0238JDG3016" (push emitido). Listo para
  probar en cliente: User Management con admin, Role Management,
  asignacion de camaras; Device en Online sin refresh manual.

- **Checkpoint 2026-11-06 (b) - E-098 permisos en cascada + camaras por org,
  commit 3e43083**. RE: GetResourceRoles -> v1.1/authority/resource/{id}/
  role/list (@0xc9c238 + /role/list, pResultRoleList), SetResourceRoles ->
  PUT/POST v1.1/authority/resource/{id}/role (UserLogical
  HandleSetResourceRoleIdList @0xc4ec8), ResourceAllocateGetOrgDevices ->
  v1.1/resource-allocate/organization/device/fetch/list (pOrgDevList
  @0xca5bd0). Implementado superset con checked/permission/operate STRING:
  admin (roleId 1) cascade-granted en todo recurso; operator solo en
  VIGILAB. Fix filtro root 001 (ve todo). organization/list confirmada en
  vivo con 001 (root) + VIGILAB. Logs de prueba: server ya graba
  [REQ]/[REQ-BODY]/[RES]/[FALLBACK] de TODO (gateway always-on); cliente
  subido a Debug: C:\DSS\DSS Client\Localcfg.ini [LogLevel] level=2 +
  [VaxplayerLogLevel] level=6 (tomar efecto al reiniciar el cliente),
  sdk_log sigue en C:\DSS\DSS Client\sdk_log\sdk_log.log.
  Ventana de captura de la prueba manual: usar docker logs con --since.
  Tests: unit 52 pass/0 fail/1 skip, e2e 12/12 x3, live-verify 15/15.

- **Checkpoint 2026-11-06 (c) - E-099 HOTFIX crash User Config, commit dd3ca0e**.
  Diagnostico conjunto (3 subagentes): gateway log 21:08-21:13 UTC muestra
  secuencia del dialog role/page -> function/available -> menu/available ->
  subsystem/available -> user/group/list -> config/ldap -> **role/list
  21:12:26.852 (ULTIMA, 200, 1903B)** y luego silencio total (unico evento
  posterior: TLS handshake timeout 21:14:29 = cliente ya muerto). sdk_log
  cliente: crash real ~18:11:19 local con todos los bind UDP broadcast
  fallando (err 10013 WSAEACCES en NICs virtuales Tailscale/VMware/Hyper-V,
  pSocket NULL, error SDK 90002002) - firma 0xC0000005 en netsdk por socket
  nulo; ademas el parser del SPA hacia strict === con "1" y role/list servia
  status/level/default/editable/deletable/userCount NUMERICOS (misma causa
  raiz que E-095). FIX server-side: buildRolePagePayload y role/:id ahora
  sirven TODOS los flags como STRING + statusName (+checked/permission/
  operate); igual function/available/list (superset menu+FunctionType),
  subsystem/available, alert-types y user/group list. Combo Organization del
  dialog: nuevo GET/POST v1.1/domain/organization/list (+ipms,
  domain/import/organization/page) sirviendo 001 root + VIGILAB con pageData
  (DPSDK GetDomainOrganizations @0xc5720). Gate de Live View: nuevos
  v1.1/account/function/channel/check[/batch] y /device/check
  (@0xc9ca80/@0xc7f0c0/@0xc9c978, clave functionCodes @0xcc9440) que
  otorgan TODOS los FunctionType (liveView 8, playback 9, ptz 13, download
  10...) en cada canal registrado -> D0238JDG3016\\\ en VIGILAB abre
  Live View/Playback/PTZ/Alarma; resource-binding/channel/relation/page
  sirve los canales bindeados. E-098 authority: inputChecked string y
  operator granted en cualquier asset VIGILAB (org/device/canal).
  Verificado en vivo: role/list flags string, domain org list [001,VIGILAB],
  channel check D0238JDG3016\\\ -> functionCodes incl 8/9/13,
  authority resource D0238JDG3016 -> admin checked "1". Tests: unit 53
  pass/0 fail/1 skip, e2e 12/12 x3, live-verify 15/15.
  NOTA cliente (ambiental): permitir UDP broadcast Dahua en el firewall de
  Windows o desactivar NICs virtuales (Tailscale/VMware/Hyper-V); si el
  crash persiste, capturar con procdump -ma -e 1 "DSS Client.exe".

- **Checkpoint 2026-11-06 (d) - E-100 white-screen/hang Users dialog, commit
  18f565f**. Prueba reincidente 21:58 UTC: el dialog paso role/list (200,
  flags string - E-099 funciono) y se colgo en la ULTIMA peticion
  GET /brms/api/v1.1/user/page (200, 7552B); Windows registro AppHangB1
  (cuelgue UI, NO APPCRASH), cero 5xx/FALLBACK. Auditoria del bundle SPA:
  consumidores de role/list leen e.id; email/page y group/list se leen por
  data.pageData (ausente = undefined = throw en render). Fix: role rows
  llevan id+roleId; email/page + group/list + group-by-role-level sirven
  pageData y contadores STRING; menu/available sort string; organization/
  list contadores string + pageData; user/page contadores string. Tests:
  E-100; unit 54 pass/0 fail/1 skip; e2e 12/12 x3; live-verify 15/15;
  desplegado y verificado en vivo (group/list con pageData, role/list con
  id). Pendiente: reporte RE del parser nativo de user/page (roleIds como
  array vs string CSV) - subagente reverse-engineer en curso.

- **Checkpoint 2026-11-06 (e) - E-101 + E-102, commits eac2a28 / 42d33db**.
  Ventana crash 22:53 UTC (contenedor confirmado corriendo E-100 por md5):
  ultima peticion user/page 200 7556B y luego 5m38s de silencio (AppHangB1).
  E-101: GET/POST tree/full/grade-device-tree (+search/list, v1.0/v1.1) ya no
  cae en FALLBACK (era el arbol de permisos del dialog); POST /role devuelve
  el rol real (no stub estatico); user rows sirven roleIds como CSV string +
  alias roleIdArray. E-102 (RE Ghidra/REA de los descriptores nativos
  FUN_180754c60 matcher SIN coercion de tipos: numero donde se espera string
  = campo NULL silencioso): user/page ahora incluye name, enableMPT y
  roles[] [{roleId,roleName}]; role/page incluye allowEdit/id/roleType/
  roleName/memo; authority role/list results[] con id/roleName/memo; nuevo
  PUT authority/resource/{id}/role/update (SetResourceRoles, echo roleIds);
  domain/organization/list en forma nativa (domainOrgExceeded + results[]
  domainOrgCode/Name/Path/Type/Dn/pId); group-by-role-level con users[].
  Verificado en vivo: admin name=Administrator roles=[{roleId:1,...}],
  VIGILAB en domain org results, role/update echo ["1","2"], full tree con
  checked string. Tests: unit 56 pass/0 fail/1 skip, e2e 12/12 x3,
  live-verify 15/15, md5 desplegado OK.

- **Checkpoint 2026-11-06 (f) - E-103, commit f63917e** (hallazgos QA de la
  secuencia E-102): role/page era el UNICO endpoint de la secuencia Users sin
  pageData[] (contrato nativo FUN_1806c6280) -> agregado; grade-device-tree
  filtra channels por org pedida (root 001 devolvia canales huerfanos sin
  device padre); roleName de admin unificado a \"Administrator\" (antes
  \"Super Administrator\" vs \"Administrator\" entre role/page y user/page);
  test E-102 endurecido. Verificado en vivo: role/page pageData=2,
  root 001 orgs=[VIGILAB] devices=0 channels=0 (sin huerfanos), VIGILAB con
  D0238JDG3016+D7001SHX9002 y sus canales. unit 56 pass/0 fail/1 skip,
  e2e 12/12 x3, live-verify 15/15. Pendiente: reportes de mision 1 (RE
  ciclo de vida) y mision 2 (forense ventana 00:05-00:10 UTC).

- **Checkpoint 2026-11-06 (g) - E-104, commit 032e262 + forense ventana
  00:05-00:10 UTC**. Forense: la secuencia del dialogo termino en
  role/list (00:07:56.823, 200, 4397B) y 3s despues ECONNRESET del cliente;
  user/page NUNCA se pidio en esa ventana; sin WER AppHang esta vez. Esa
  ventana corria con E-102 (contenedor iniciado 00:02:04) donde role/page
  NO servia pageData. Reporte RE completo (DPSDK): contrato envelope
  {code:int(1000), desc:string, data:objeto}; role/list nativo =
  data.results[] con allowEdit/id/roleType/roleName/memo strings;
  role/page = pageData[] + totalCount string; user/page = pageData[] +
  totalCount string con username/online/name/enableMPT/id/status/userType +
  roles[{roleId,roleName}]; authority/resource/{id}/role/list =
  data.results ARRAY DE STRINGS (roleIds) - servir objetos ahi hace que el
  parser nativo extraiga 0 elementos; config/ldap = data directo con
  username/port/autoSynTime/dn/enable/enableAutoSyn/ssl/server strings
  (enable/ssl comparados con "1"); user/group = results[] con
  groupId/groupName/users[{userId,username}]. Aplicado E-104 (authority
  results strings, ldap keys nativos). Verificado en vivo: role/page
  pageData=2, ldap keys nativos, authority results ["1","2"],
  user/email pageData, role/list rows id/roleName. unit 57 pass/0 fail,
  e2e 12/12 x3, live-verify 15/15. Pendiente: reporte mision 1 (ciclo de
  vida post-role/list) del reverse-engineer.

- **Checkpoint 2026-11-07 (h) - E-105, payload ESTRICTO de `v1.1/user/page` +
  causa del AppHangB1**. Forense (21:58:38.273 -> 21:58:39.934Z): la
  secuencia nativa termina en `GET /brms/api/v1.1/user/page?...` -> **200,
  7552 B** y **no hay ninguna peticion posterior**; 6.7 s despues el WER
  registra `AppHangB1`/`AppHangXProcB1` (EventTime 21:58:46.625Z) **sin
  0xC0000005** => el hilo de UI queda BLOQUEADO (no es un crash). El cuerpo
  servido en esa ventana (E-100, 7556 B) era un superset de 36 claves/fila
  con `roleIds`/`roleNames` como ARRAYS JSON, sin `name`/`enableMPT`/`roles[]`
  y con 5 arrays duplicados (`list/results/items/userList`) +
  `total/page/pageSize/pageCount`. RE binario (UserLogical/PluginFactory):
  el descriptor nativo `FUN_1806c8d20` exige **kind=2 (string) en todas las
  hojas** de la fila y sólo admite dos arrays (`data.pageData` y
  `data.pageData[].roles`); el matcher hace type-check ESTRICTO y deja el
  campo NULL/0 en silencio. El dialogo de Usuarios es NATIVO
  (`CUserManagerUserCtrl`): `OnNotifyUserManagerState` (`FUN_180ac8f90`)
  case `0xd` -> `FUN_180ac33a0` -> getter `UserList` vtable `+0x58` =
  `FUN_1800647d0` (UserLogical) que **toma el mutex `CUser+0x68`** (mutex
  recursivo PROPIO sin comprobacion de hilo propietario: `FUN_180014020` ->
  `WaitForSingleObjectEx(hEvent, 0xffffffff, 0)` sobre un evento
  AUTO-RESET) y **borra** el nodo del mapa; despues
  `SetTotalCount(notify+0x30)` y el bucle de filas acotado por
  `(end-begin)/0x88` (**nunca** por totalCount). La columna dibujada es
  **`username`** (no `name`); `name` va en col 1 rol 0x101; la col 2
  concatena `roles[].roleId` con ",". Aplicado E-105 en
  `brms-gateway/src/e025-devices.js`: `serializeUserPageRow()` (fila
  estricta: id/username/name/online/enableMPT/status/userType string +
  `roles:[{roleId,roleName}]`) y `buildUserPagePayload()` (`data` =
  `{pageData,totalCount}` y nada mas; `totalCount` = TOTAL de usuarios que
  casan, string). Body 7556 B -> **386 B**. El detalle `/user/:id` conserva
  los alias CSV (`roleIds:"1"`) y ya no tiene hojas-array. Tests
  `brms.test.js` E-096/E-101/E-102 actualizados: **57 pass / 0 fail**.
  Doc ampliada: `docs/DPSDK_USER_MANAGEMENT_CONTRACTS.md` §3.1, §8 y §10
  (pipeline completo, mapa columna->campo, mutex, 5 respuestas).

- **Checkpoint 2026-11-07 (h) - E-105, commit 01126b2**. Mision 1 (ciclo de
  vida) completada por audit del string pool DPSDK file 0xc9c000-0xc9d900:
  tabla completa CRestLogical de Users/Roles documentada en
  docs/DPSDK_USER_MANAGEMENT_CONTRACTS.md §9 (incluye orden observado del
  dialogo). Encontradas 3 rutas legacy SIN servir del mismo dialogo:
  /admin/API/Rights/Groups (GetUserGroup @0xc9cde8), /admin/API/Rights/Users
  (GetUserBaseInfo @0xc9ce70), /admin/API/Rights/User (GetUserDetailInfo
  @0xc9d028) -> servidas con los mismos shapes (user page/groups/user
  detail). Verificado en vivo: pageData=2 con admin, groups con users,
  detail con roles. unit 57 pass/0 fail/1 skip, e2e 12/12 x3,
  live-verify 15/15, md5 desplegado OK.
  RESUMEN arquitectura final Users/Roles: contratos nativos firmados en el
  doc (envelope code:int 1000; role/list results[] strings; role/page+
  user/page pageData[]+totalCount string con name/enableMPT/roles[];
  authority results = array de STRINGS + PUT role/update; domain org
  nativo; ldap nativo; tree/full GET sin huerfanos; Rights/* legacy).

- **Checkpoint 2026-11-07 (i) - E-106/E-106b, commits df2b96c/48d841c**.
  CAUSA RAIZ de los toasts \"Abnormal network\" y ventana vacía: el login
  real de segunda vez VerifyFirstTime -> GET /brms/api/v1.1/account/security/
  public-key/generate (@0xca13d9) y VerifySecondTime -> POST /account/
  security/password/check (@0xca1559, RSA \"Get RsaCryption\" @0xc7cbf4,
  claves publicKey/randomKey @0xcc70a8) caían en el catch-all [FALLBACK]
  (59B/40B) -> el proceso RSA nunca completaba -> accounts/authorize nunca
  corría -> TODAS las llamadas del dialogo iban con x-subject-token ABSENT
  -> \"Failed to get the LDAP configuration / role list: Abnormal network\"
  y ventana vacía (sin crash, y sin peticiones nuevas al server: la traza
  del cliente mostraba solo 3 peticiones). FIX: public-key/generate sirve
  clave RSA 1024 real (PEM) + randomKey (privada en PUBKEY_PENDINGS 5 min);
  password/check desencripta (PKCS1->OAEP) y devuelve success; authorize ya
  NO re-challengea el body RSA (evita loop de login). Verificado en vivo
  end-to-end: PEM OK -> password/check 1000 -> authorize 200 token 64 ->
  role/list results=2 -> user/page admin=Administrator. Tests: E-106,
  unit 58 pass/0 fail/1 skip, e2e 12/12, live-verify 15/15.
  Nota: subagentes MiniMax quedaron fuera por rate-limit 429; investigación
  cerrada localmente.

- **Checkpoint 2026-11-07 (j) - E-107, commit 746df4d**. Reporte final del
  log-analyzer confirmando E-106: el build que fallaba (md5 3b55e3e2) no
  tenia public-key/generate ni password/check -> [FALLBACK] 59B/40B ->
  DPSDK lee code:1000 del catch-all como \"Abnormal network\" -> sin
  authorize -> token ABSENT -> toasts LDAP/role list y ventana vacía.
  Riesgo residual cerrado: v1.0/role/list, v1.0/config/ldap e
  ipms/v1.1/role/list eran FALLBACK -> ahora handlers reales (5256B/351B);
  POST /admin/API/accounts/updateToken (refresh de token, observado
  08:14:56Z en FALLBACK 40B) -> 407B login envelope. Verificado en vivo:
  todas las variantes REAL, flujo E2E completo (PEM -> password/check ->
  authorize token 64 -> role/list -> user/page admin). unit 58 pass/0 fail,
  e2e 12/12 x3, live-verify 15/15.

- **Checkpoint 2026-11-07 (k) - E-108, commit 5644594**. Barrido QA de 56
  endpoints en vivo: 49 REAL, solo 3 genuinamente ausentes (catch-all
  [FALLBACK] confirmado por el log interno): account/menu/list
  (GetAccountMenuList @0xc9c8e0), config/videoIntercom y config/mail.
  Implementados con datos reales + todas las variantes de prefijo
  (brms v1.1/v1.0/v2.0, ipms v1.1). Verificado en vivo: menu/list 57.9KB,
  videoIntercom 117B, config/mail 322B. unit 59 pass/0 fail/1 skip,
  e2e 12/12 x3, live-verify 15/15.
  ESTADO ARQUITECTONICO: secuencia completa del dialogo Users servida
  (login RSA E-106 -> role/page pageData -> function/menu/subsystem
  available -> user/group/list+users -> config/ldap nativo -> role/list ->
  user/page admin -> Rights/* -> authority strings -> resource-allocate ->
  account/function gate). RTSP 200 en ambos canales; MediaMTX/ActiveMQ/SIP
  activos. REA/Ghidra sobre DPSDK no completó por timeout de import
  (17MB > 330s); la evidencia RE se cerró por string-pool + reportes de
  subagentes equivalente.

- **Checkpoint 2026-11-07 (l) - E-109, commit 57d1268**. Cosecha historica de
  [FALLBACK] del cliente real (2.782 requests, 12 URLs distintas): 8 ya estaban
  cubiertas (E-025/E-107 rutas explicitas) y 5 eran huecos reales que ahora se
  sirven: v1.1/server/list (GetServersList @0xc913a8 - servidor video#local
  dueno de cada device), storage/position/device/page (@0xc991d5, pageData real
  del registry), storage/disk/local-disk/list (@0xc987cd, disco real via
  statfs de /app/data), storage/disk/net-disk/list (@0xc9843d) y
  storage/group/list (@0xc98d75) vacios explicitos. Todos con variantes
  brms v1.1/v1.0/v2.0 + ipms. Ademas E-109b: journal persistente de
  [REQ]/[RES]/[FALLBACK] en /app/data/logs/requests-YYYY-MM-DD.log (volumen rw)
  para que la forensia sobreviva a docker compose up --build (la cosecha
  historica hubo que rescatarla de /tmp). Verificado en vivo: server/list
  1568B, storage position 2793B, local-disk 2037B, journal escribiendo.
  unit 60 pass/0 fail/1 skip, e2e 12/12 x3, live-verify 15/15.
  DOCS: docs/DSS_ENDPOINT_COVERAGE.md §8 con las 12 URLs y su estadofinal.

- **Checkpoint 2026-11-07 (m) - E-110, docs -18 + cfgs prefix**. Reporte RE
  definitivo (PluginFactory.dll @0x180ac3780/@0x180ac4370): el toast
  \"Abnormal network\" es la traduccion del ErrorId -18 (DPSDK_ABNORMAL_NETWORK
  de BaseErrorCode.db) que SOLO produce CheckLoginValid cuando m_strToken esta
  vacio (@0x1800d31cf); los 3 APIs del dialogo (ldap @0x1801f73f5, role/list
  @0x18028e869, user/page @0x1802a02a4) validan login ANTES de salir a red ->
  con token vacio devuelven -18 sin HTTP -> toasts y ventana vacia por fallo de
  user/page (mapa [r13+0xd8] nunca se llena), no por role/list. La capa HTTP
  trata code:1000+200 como exito (@0x18055dc19): el catch-all benigno NO es
  error de red pero deja el handshake incompleto. Cliente manda headers
  X-Subject-Token + X-Subject-Sequence (@0x18055cfa0). Accion: espejados los
  config calientes en /cfgs/api (prefijo alternativo que GetLdapConfig puede
  usar). Documentado en docs/DSS_ENDPOINT_COVERAGE.md §9. unit 60 pass/0 fail,
  e2e 12/12 x3 (sin cambios de ruta nuevos, solo alias cfgs).
