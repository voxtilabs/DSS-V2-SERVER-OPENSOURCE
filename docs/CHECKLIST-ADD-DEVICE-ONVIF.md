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
  **10.10.20.1** (WINPC_V2) — NO alcanzable por red (445/22/5985 cerrados);
  sus logs hay que pedírselos al operador a mano.
- **Repo**: `poc/dss-v2-harness/` (gateway `brms-gateway/src`, e2e
  `e2e-lan-test.mjs`, compose, `activemq-ssl.xml`). Docs de contratos:
  `docs/NETWORK_PROTOCOLS.md` §31-§33.

## Evidencia recolectada (logs server-side)

| Fecha sesión (UTC) | Log | Hecho |
|---|---|---|
| 2026-11-04 22:14:49–22:15:51 | gw4.log | GetMqConfig 200 (4026B) ×2; `tree/deviceOrg?orgCode=` 200 (1724B, 001+VIGILAB); `tree/devices` 200 (154B = vacío, el e2e había borrado el registro); `fish-eye-data` 200 (89B); add 22:15:51 → 200 (5543B) **persistió** (D0238E885012, orgCode VIGILAB); join/batch 22:15:56 → 200 con `ids:[D0238E885012], orgCode:""`. **Cero requests HTTP después del join/batch.** |
| 2026-11-04 22:14–22:16 | amq4.log | Broker: sólo startup, **0 eventos de conexión** (MSG.exe nunca marcó 61616). |
| 2026-11-04 23:28:25–23:29:07 | gw6.log | Sesión con el payload NUEVO (mqtt="10.10.20.120:1883" desplegado desde 22:56): GetMqConfig 200 ×2; add 23:29:01.832 → 200 (6036B, body ONVIF completo `deviceName:EBAVOLVIO...`); `device/page` 23:29:01.893 → 200 (3401B, con la cámara); join/batch 23:29:06.802 `ids:[D0238JDG3016], orgCode:""` → 200 (2552B); **sí** re-fetch `discover/device/page` 23:29:06.849 y `device/page` 23:29:07.495, pero **nunca** `tree/deviceOrg`/`tree/devices` después del join. |
| 2026-11-04 23:0x–23:3x | gw6.log `[MQTT]` | Todos los `PUBLISH brms.notify* -> 0 subscriber(s)`. El único cliente MQTT que conectó fue `e2e11-sub` (mi e2e). **El cliente nativo no abrió NINGÚN socket MQ: ni 1883 ni 61616.** |

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

- **El cliente nativo no abre ningún socket MQ** (0 conexiones a 61616 en el
  broker; 0 subscribers en 1883 salvo el e2e) aunque recibe GetMqConfig con
  `mqtt:"10.10.20.120:1883"` y `UseMqFlag=1`. Consecuencia: CDevAdd expira su
  timer esperando el notify ("Operation timed out") y el árbol izquierdo no se
  re-pide solo tras join/batch (sólo re-pide `device/page` y
  `discover/device/page`).
- Falta el **log del cliente** (10.10.20.1 no es alcanzable por red): pedir al
  operador los logs del DSS Client (carpeta `log/` del install, p.ej.
  `Dpsdk.log`/`MSG.log`) — la línea clave es
  `GetMQConfig PSDKAPI_REQUEST is success, MQ Config is %s, MQ User Name is %s, PassWord is %s`
  y si aparece `CreateMsgProcess` / errores de pipe / de libcurl-MQTT.
- Ghidra run 5 en curso: gate de `CMSGProcess::Init` / `CreateMsgProcess`
  (0x180bda2d4), pipe `<tomsgpipe>` (0x180a48457), caller `FUN_180a406e0` —
  para ver qué condición decide pipe-vs-libcurl-MQTT y por qué no se abre nada.

## 🚫 NO repetir (ya descartado con evidencia)

- Servir OpenWire plano en 61616: MSG.exe siempre hace ssl:// (disablePeerVerification).
- `hasChild`/`checked`/`pId` como booleanos JSON: el parser liga strings.
- Quitar `addr` del GetMqConfig: era el "MQConfig vacío" del intento 3.
- `mqtt:""` con la expectativa de que MSG.exe marque 61616: pasó (0 conexiones).
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
- **Siguiente paso**: (1) log del cliente desde 10.10.20.1 (línea "MQ Config is
  %s" + CreateMsgProcess), (2) leer Ghidra run 5 del gate de MSG/MQTT, (3) según
  eso conmutar el contrato correcto (pipe MSG.exe a 61616 ssl, o libcurl-MQTT a
  1883) y re-verificar con sesión real del operador.
