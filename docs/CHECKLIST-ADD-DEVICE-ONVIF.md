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
- **Siguiente paso**: (1) terminar decomp pf2 (quién dispara cada "Operation
  timed out.") y dpsdk4 (parser TopicInfos/IsAccUser 0x180a496ec), (2) publicar
  el notify `brms.batchAddDevices` a los topics `mq.*` (STOMP 61613) y/o servir
  TopicInfos con IsAccUser=1, (3) unit + e2e ×3 + live-verify, (4) deploy y
  pedir retest al operador (cerrar/reabrir cliente, relogin, Add Device ONVIF,
  Discover join, Organization VIGILAB, Management→Sites).
