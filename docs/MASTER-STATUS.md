# DSS-V2-SERVER-OPENSOURCE — Estado maestro (2026-11-08)

Documento índice de "todo investigado". Cada sección referencia el doc
detallado y los commits E-### que implementan la evidencia RE.

## 1. Identidad del sistema emulado

Gateway BRMS que emula un **Dahua DSS V8 (Pro/Ultimate)** para el
**DSS Client 8.006 (WINPC_V2)**: login RSA de dos tiempos, gestión de
usuarios/roles/permisos, Live View H265 vía relay RTSP propio, Event
Center con push MQ, Monitoring Center con vistas, auto-register Dahua
(ARS 9500 DVRIP/DHIP), P2P/Easy4IP real contra el cloud de Dahua.

- Arquitectura y puertos: `docs/ARCHITECTURE.md`, `docs/NETWORK_PROTOCOLS.md`
- Contratos nativos firmados (matcher sin coerción, flags string):
  `docs/DPSDK_USER_MANAGEMENT_CONTRACTS.md`
- Cobertura endpoint por endpoint: `docs/DSS_ENDPOINT_COVERAGE.md`
- Investigación del cliente y DLLs: `docs/DSS_CLIENT_RESEARCH.md`,
  `docs/RESEARCH.md`
- Compatibilidad Dahua (NVR/XVR/IPC, H265/H265+, ARS, P2P):
  `docs/DAHUA_COMPATIBILITY.md`, `docs/P2P_RESEARCH.md`

## 2. Evidencia RE por módulo (DPSDK.dll / UserLogical.dll / netsdk.dll / PluginFactory.dll)

| Módulo | Evidencia RE (offsets) | Implementación |
|---|---|---|
| Login RSA 2 tiempos + heartbeat renueva token | "Heartbeat is success, m_strToken = %s"; public-key/generate→password/check→authorize | E-106/E-114 |
| Versión: el cliente compara su major vs `platformVersion`/`softwareVersion` de `/videoService/version` y v1.0/version | MainFormPlugin.dll 0x6630b8 `Client major version: %s`, patrón `\d*\.\d*\.\d*\.\d*` 0x663098; toast 0x662e10 | E-122 |
| Toasts: "Abnormal network" = **-18** (fallo transporte curl/HTTP≠200, `curl_easy_perform fail` 0xcc6f68, `response [%s] return: %d` 0xcc6f80); "data abnormal" = **ErrorId 3101** en `ErrorDB/BaseErrorCode.db` 0x6053d; "Unknown error" = -1/-2 | PluginFactory 0x19b20e8; BaseErrorCode.db | E-125 (cierre de catch-alls) |
| Árbol permisos rol/usuario: `v1.1/tree/full/grade-device-tree` @0xc9cc40 → `BRMS.Tree.GetFullGradeDeviceTree` 0xcdb070; nodos: `checked` 0xcda378, `hasAuthority` 0xcd3168, `organizations` 0xcda368, `deivceNodes` (typo SDK) 0xcd9348; UI `CRoleManagerEditDlg` PluginFactory 0x19e0210 | DPSDK.dll pool | E-124 |
| Event Center: `eventCenter/messages/subscribe` 0xcbba90, `alarmTypes` 0xc97138, `alarm/messages/count` 0xc97268, subscribeAddress en GetMqConfig 0xc96498; schema evento `ParseAlarmEventNotify` 0xcacaf0 | DPSDK.dll | E-117/E-118 |
| IVS/tripwire Dahua: CrossLineDetection/CrossRegionDetection/Intrusion/FastMove... en netsdk.dll; IDs numéricos los da el server vía alarmTypes | netsdk.dll | E-118 (catálogo) |
| Auto-register ARS: framing DVRIP/DHIP magic+0x19930522+JSON, `AutoRegister.cpp` netsdk 0x01366578, header templates 0x01388648/0x013988dc; campos DeviceID/SerialNo/DeviceType/MachineAddress/IPAddress | netsdk.dll | E-119 |
| H265/H265+: StartVideo NO negocia codec; el SDP del server trae rtpmap H265/HEVC/HVC1; play.dll elige decoder en runtime | play.dll 0x009661a8 | E-115 (relay) |
| P2P/Easy4IP: `CP2PServerManager::GetDeviceInfoFromEasy4IP` → www.easy4ip.com SOAP getDeviceByDevSequence (lookup por SN, sin key de server) | DPSDK.dll | E-025 |

## 3. Módulos desplegados (commits)

E-095…E-125 en `main` (HEAD ver `git log`). Hitos: E-106/114 login+keepalive,
E-115/116 relay RTSP + guardian MediaMTX, E-117/118 Event Center + eventos
genéricos, E-119 ARS DVRIP/DHIP, E-120 Monitoring seed, E-121 Event Config,
E-122 versiones, E-123 authority en árbol + grants user, E-124
full/grade-device-tree, E-125 mirrors /admin/API/MTS + cierre catch-alls.

## 4. Operación

- Deploy controlado: ver sección "Despliegue" abajo (pendiente de validar
  con el agente DevOps).
- Tests: unit `node --test --test-timeout=20000 src\test\*.test.js`
  (72 pass), e2e `node --test e2e-lan-test.mjs` ×N (12/12), live-verify
  vía `docker exec -i dss-v2-harness-brms-gateway-1 node - < /tmp/live-verify.cjs` (15/15).
- Logs: journal persistente `/app/data/logs/requests-YYYY-MM-DD.log`
  (sobrevive a `docker compose up -d`); `docker logs` solo para boot.
- Estados persistentes: `/app/data/{devices,orgs,views,events}.json`.

## 5. Despliegue controlado (procedimiento)

1. Backup: `ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && tar czf /tmp/data-backup-$(date +%s).tgz brms-gateway/data"`
2. Push a main por SSH: `git push git@github.com:voxtilabs/DSS-V2-SERVER-OPENSOURCE.git main`
3. Deploy: scp de `src/` changed + `ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && docker compose up -d --build brms-gateway"`
4. Post-deploy: esperar 5s → health `curl http://127.0.0.1:11443/health` →
   live-verify 15/15 → journal tail sin catch-alls nuevos.
5. Rollback: `git revert <commit>` + push + repetir 3-4 (los JSON de data
   se restauran del backup del paso 1 si un deploy corrompe estado).

## 6. Pendientes abiertos (se cierran con los agentes en curso)

- REA residual: inventario total de literales vs servidos (agente REA).
- Validación pila TCP/IP + riesgos de listeners (agente DevOps).
- Validación manual del operador con DSS Client 8.006.

## 7. CIERRE DE COBERTURA (2026-11-08, agentes ses_e46bd58b8ffe2Tfmm3n6r4m2uP + ses_e46bd58b7ffe3V5NVN6XT2zaDx)

**REA residual cerrado (E-127, commit cd68bdd):** los 76 literales P0 de
DPSDK.dll que faltaban (devicesManager/*, alarmBusiness/alarmDuty/alarm-host,
DMS/Ptz|Cruise|Device, config server/mail/ldap/key/callMode, omc upgrade,
map raster/vector, inspect/plan, eventCenter subscribeAddress, common/request,
api/actualGps|message, privileges/menus, accounts/users/password) ahora se
sirven en `src/e127-p0-coverage.js` (1808 rutas sobre todas las raíces) con
envelopes ricos. Quedan P1/P2 (storage raid, log export, tvwall operate,
face/vehicle/parking/acs) servidos como listas vacías válidas — el cliente
los acepta con `envelope({list:[],...})`. **No queda ningún literal P0 sin
mapear.** Hallazgo de implementación: `hasRoute()` matchea el wildcard del
catch-all → registro incondicional con try/catch anti-duplicado.

**Pila TCP/IP auditada y endurecida (E-128/E-128b, commits cd68bdd/d37a999):**
ACK DVRIP/DHIP con offsets RE correctos, reensamblado de frames ARS,
caps anti-DoS (1MiB payload / 4MiB buffer), keepalive/logout en ruta binaria.
Verificado live: frame fragmentado en 3 chunks → ACK Ret:100; payloadLen
0xFFFFFFFF → sin OOM; health OK; live-verify 15/15; unit 75/0; e2e 12/12.
Riesgos MEDIOS/BAJOS y pendientes de red documentados en
`docs/LISTENER-SECURITY.md` (matriz puerto/propósito/riesgo + contrato
binario DVRIP/DHIP). Runbook verificado en `docs/DEPLOY-RUNBOOK.md`.

**Docs de cierre:** `DEPLOY-RUNBOOK.md`, `LISTENER-SECURITY.md`, además de
los existentes (ARCHITECTURE, NETWORK_PROTOCOLS, DAHUA_COMPATIBILITY,
P2P_RESEARCH, DPSDK_USER_MANAGEMENT_CONTRACTS, DSS_ENDPOINT_COVERAGE,
CHECKLIST-ADD-DEVICE-ONVIF, evidence/). Estado: **cobertura RE cerrada**;
pendiente solo la prueba manual del operador con DSS Client 8.006.

**Iteración 2 del cierre (2026-11-08, agentes ses_e45812db8ffe07Z4sg36E7wf46 +
ses_e45812db5ffe5zhZ2PvSWoNcvF + ses_e451b4956ffeQdao3cVAOkhYQp):**
- E-129 (commit b260003): 543 rutas para los 32 literales **P1** restantes
  (login/recuperación, domain/license, server status, alarm-host, monitor
  URIs, p2p) con claves de descriptor del .rdata de DPSDK.dll. Quedan 369
  literales P2 servidos por wildcard de lista vacía válida (aceptado por el
  cliente). **REST: 0 P0/P1 sin handler dedicado.**
- E-130 (commit ca39f64): SIP **TCP 5080 + TLS 5061** (DPSDK 0xc56d30/
  0xc56528) con handler compartido 200 OK — verificado live `SIP/2.0 200 OK`;
  MQ_TOPICS ampliado a los **86 topics** del pool de DPSDK.dll (GetMqConfig
  anuncia TopicInfos completo); 554/37777 descartados por REA (outbound al
  dispositivo, sin listener); contrato WSS de MSG.exe documentado.
- Estado final: **no queda ningún literal REST ni protocolo binario del
  cliente sin mapear** — REST P0/P1 con handler + claves, P2 con wildcard
  válido, RPC BRMS.*/DMS.*/VMS.* vía /admin/API, DVRIP/DHIP con reensamblado +
  caps + ACK offsets RE, SIP UDP/TCP/TLS, MQTT 86 topics, STOMP/OpenWire,
  WS event, RTSP relay 9100, ARS 9500. Unit 77/0, e2e 12/12, live-verify 15/15.

**Iteración 3 del cierre (2026-11-09, E-131, commit 99bb907):** mapa de
compatibilidad sobre los **1363 exports DPSDK_*** + contratos MSG.exe/play.dll/
UserLogical (REA con MCP operativo) → `docs/COMPATIBILITY-MAP.md`. Fixes:
GetMqConfig con tipos int (SessionId/ProtocolVersion) + GroupId + IsAccUser
string + envelope de alarma con `info`; rutas nuevas SS/Playback,
license/{deactivate,export,reactive}, map/label/*, VMS/TvWall/* (raíces de
subistema emap/omms/obms/ipms/arms en urlsFor → 4294 rutas P0 + 2240 P1).
Unit 78/0, e2e 12/12 ×2, live-verify 15/15. **REA MCP ahora CAIDO** (desapareció
del catálogo): para retomar análisis fino (xrefs, decompilar) hay que reiniciar
el cliente MCP; mientras tanto todo REA sigue cubierto por string-pool.
Pendientes aceptados (no bloquean): stream nativo DPSDK, playback con índice
real, túnel P2P, workflow alarmas, mapas emap servidos, TVWall decode.

**Iteración 4 (2026-11-09, E-132, commit 078f461):** cierre de los avisos
vivos. (a) Toast "Client & server versions don't match": REA trazó el compare
a `data.baseVersion` de `GET /videoService/version` (UserLogical emite código
10 si el server parsea MENOR que V8.006.0000000.0; el string vive en
MainFormPlugin 0x180664810, único xref 0x180166cd3). El log del cliente prueba
que con el server actual el compare pasa IGUAL, pero `selectPlatformVersion()`
podía devolver V8.000/V8.004 por un token del UA → endpoint y `upgradeable`
anclados al build 8.006 (nunca más viejo), `serverName` añadido. (b) Toasts
"data abnormal" (ErrorId 3101 = IsKeyValid CommonFunc.cpp:149): la sesión viva
mostraba `Invalid key: [warningContent] [warningType]`; todas las rutas
warning/abnormity (explícitas + capa P0/P1 vía WARN_KEYS) devuelven el set
completo como strings (warningHappened/warningTime/warningContent/
warningType/warningLevel/standbyServerRemainDays/abnormityType/results...).
Unit 79/0, e2e 12/12 ×2, live-verify 15/15. **REA MCP intermitente**: volvió
y cayó de nuevo (catalogo Code Mode ya no lo lista); todo REA pendiente se
cubre con string-pool node+fs.

**Iteración 5 (2026-11-09, E-133, commit b7c6314):** cierre del reporte REA
`ses_e4217e907` (toasts 3101 + Monitoring). (a) Rutas **POST** de
license/warning, hot-spare/abnormity, hot-spare/info y demás warning sirven
WARN_KEYS completo (el SPA usa POST; antes caían al fallback 40B → toast).
(b) RPC de 3 segmentos conserva `:cls` (`BRM.Resource.Tree.GetDeviceOrg` ya
no colapsa) + GET en la familia + handlers Tree.GetDeviceOrg→departments[] /
Tree.GetDeviceTree→devices[] — **esto puebla Resources/Browser del Monitoring
Center** (verificado en vivo: 3 devices incl. D0238JDG3016). (c) POST
/admin/API/tree/deviceOrg. (d) user/group/list con eventTypes[] por fila.
(e) disk/memory server lists con fila real (serverIp/warnDisks). Unit 80/0,
e2e 12/12 ×2, live-verify 15/15.

**Iteración 6 (2026-11-09, E-134 commit c78207e + E-134b commit 9f7de36):** cierre
de los 8 deltas del auditor REA `ses_e41b71d20`. (a) D1/D4 `buildLoginSuccess()`
ampliado al cluster de 26 claves (secretKey/secretVector/credential/reused/
verification/userLevel/pocId/userGroupId/unlockRemainTimes/unlockRemainTime +
versionInfo.patchVersion) — keepalive/updateToken heredan `credential`
(FUN_18072a2b0 / FUN_1806771a0; mataba "LoginSecTime is failed, PrivateDecrypt
Failed"). (b) D2 los 3 handlers MTS StartVideo leen `body.data` del envelope RPC
→ `/admin/API/MTS/Video/StartVideo` devuelve `cam_D0238JDG3016` (no cam1).
(c) D3 compose: `9100:9100` publicado del **brms-gateway** (relay e115 traduce
`?token=` → `/trackID=N`); MediaMTX pasa a `18554:8554` en host. Verificado en
vivo: OPTIONS/DESCRIBE/SETUP `?token=` en :9100 → 200/200/200 (antes 400).
(d) D5 GetCurrentMediaVK con createDate/algorithm=MD5/vkValue MD5. (e) D6 SIP:
Via = original + `;received=` (1 branch, verificado en vivo), From/To
textuales con host/tag originales. (f) D7 MQTT `brms.notify*` publica también
el envelope `{method, info}` (ParseMQMsg FUN_1800306b0) además del VO plano.
(g) E-134b: alias RPC versionado `/brms/api/v1.x/BRM/*` GET+POST 2/3 segmentos +
`BRM.Config.GetCurrentMediaVK` (cerraba el último FALLBACK del journal 09-11).
**MCP REA endurecido** (diagnóstico `ses_e3f9d9415` →
`%TEMP%\opencode\rea-mcp-diagnosis.md`): causa raíz = kill masivo de node.exe
(code 255) + timeout Ghidra 330s. Aplicado en `~/.config/opencode/opencode.jsonc`:
`mcp.timeout`/`rea.timeout` execution 1800000, env
REA_GHIDRA_STARTUP_TIMEOUT_MS=900000 / DECOMPILE=300 / GHIDRA_HEADLESS_MAXMEM=3G,
`codemode:false`, permissions deny `*Get-Process node*` / `*taskkill*node*` +
ask `*Stop-Process*`; limpiados 9,94 GB de `%TEMP%\rea-ghidra-*`. Fallback
permanente commiteado: `tools/ghidra-fallback/` (ReaStrings/ReaDecomp/
ReaExports .java sin BOM + rea-ghidra.ps1). Tests: unit 81/0/1, e2e 12/12 ×3
(pre y post deploy), boot local health 200, live-verify 15/15, sondeos vivos
D1/D2/D3/D4/D5/D6 OK. **Gap analysis por capas** (subagentes REA
`ses_e3f22b574…` server / `ses_e3f22b577…` cliente →
`%TEMP%\opencode\rea-gap-server.md` / `rea-gap-client.md`): ~730 métodos
server-only sin cubrir (BRMS 468, IPMS 82, Express 78, OBMS 48…), raíces
ausentes (otms/iams/erms/ecos/vehicleServer/psib/faceService/alarmProcess/
arms), 5 notify topics faltantes, WS subscribe por `methods[]` pendiente,
Event Center pull-queue pendiente, licencia/upgrade OMC/P2P reales pendientes.


## Iteración 7 EN CURSO (2026-11-09, E-135/E-136) — "completar el motor"

Gap analysis por capas cerrado (reportes `%TEMP%\opencode\rea-gap-client.md`
52 filas con parser VA + claves obligatorias, y `rea-gap-server.md` TOP20):
el motor completo son ~730 metodos server-only / 2.024 metodos RPC del pool
cliente (cosechados en `brms-gateway/src/data/rpc-method-catalog.txt`), 97
notify topics (`src/data/dpsdk-notify-topics.txt`, faltaban 5), ~15 raices de
subsistema ausentes y 4 flujos async (WS subscribe methods[], Event Center
pull-queue, alarm handle/ack + notify, post-login functions/Rights-Nodes).

- **E-135-A** (subagente `ses_e3dea7bd2…`): router generico del catalogo RPC
  (2.024 metodos, envelope correcto, nunca catch-all 40B) + payloads reales
  P0 del gap-client + raices faltantes. Archivos nuevos `src/e135-*.js`.
- **E-136-B** (subagente `ses_e3dea7bcaffe2…`): `src/e136-*.js` — alarm store
  persistente + Event Center (BRMS.Alarm/AlarmPlan/User/Role/Rights-Nodes),
  WS hub MSG.exe (subscribe/unsubscribe methods[] + siteSessionId +
  NotifyNormalMsg/FrequentMsg), eventCenter pull-queue, 5 topics + routing
  mq.*.msg.topic.<UserId> en e039.

Integracion (supervisor, al recibir reportes): cablear register() en index.js,
unit + e2e x2, deploy server, live-verify 15/15 + sondeos de flujos, commit.


### E-135 cerrada (2026-11-09, commit 6dbd9fc)

Motor RPC + raices, integrado por el supervisor en `index.js`:
`brmRpcHandler` fallback -> `e135BuildRpcPayload` (ya no stub vacio) y
`registerE135RpcCatalog` + `registerE135Roots` tras e127/e129 (find-my-way:
static > param > wildcard, no pisa rutas). Envelope alineado a **code 1000**
(constante `RPC_CODE_OK` en e135-rpc-catalog.js; tests e135 actualizados).
Cobertura: 110 metodos P0 con claves obligatorias del gap matrix + 1.940 por
familia (list/write/del) sobre el catalogo de 2.024; 18 raices
(/obms /ipms /omms /emap /emapService /arms /otms /OTMS /iams /erms /ecos
/vehicleServer /psib /faceService /alarmProcess /cfgs + versionadas
/brms/api/v1.0|v1.1), 72 rutas GET+POST 2/3 seg. Eco de body+query. Nunca 404
ni 40B: todo responde 200 envelope code 1000. Unit 155 tests 154/0/1; boot
local health OK + sondeos (BRMS.Alarm.GetPageAlarmRecords, SS.Record P0,
/arms/api label, OBMS door open, v1.1 BRMS.Storage); e2e 12/12 (server sigue
en E-134b). E-136-B en curso (subagente `ses_e3dea7bcaffe2…`).


### Iteracion 7 cerrada (2026-11-09/10, commits 6dbd9fc E-135 + 154797f E-136)

**E-136 (commit 154797f, 10 archivos, +3.125 lineas)**: 4 flujos async del
cliente nativo, cableados por el supervisor en `index.js`:
- **WS hub MSG.exe** (`e136-ws-hub.js`): parche `WebSocketServer.prototype.on`
  instalado ANTES de `createWebSocketServer` (start()); frames texto
  `subscribe`/`unsubscribe` con `methods[]`+`siteSessionId` -> ACK
  `{type:'ACK',code:1000}`; push `NotifyNormalMsg`/`NotifyFrequentMsg`.
- **Event Center** (`e136-eventcenter.js`): 23 RPC `BRMS.*` + 14 REST
  (Rights/Nodes, user/self/password, ...) via preHandler + 14 rutas nuevas;
  pull-queue `eventCenter/messages/subscribe` (msgId/seq, initMessageId);
  stores persistentes `data/{alarms,alarm-plans,users,roles}.json`.
- **Alarmas**: ingesta (`/brms/api/v1.x/alarm/general/event`,
  `/admin/API/GenericEvent/Report`) -> store + cola + NOTIFY.alarmEvent;
  `HandleAlarm`/`BatchHandleAlarms`/`DisarmAlarm` matchean por cualquier id
  (findIndex robusto, fix verificado en vivo: records=1); cada alarmEvent se
  rutea ademas al hub WS (`brms.notifyAlarms`).
- **e039**: 93 topics (+5), `alarmMqTopics(userId)` publica
  `mq.*.msg.topic.<UserId>` via STOMP 61613 con `amq-msg-type:text`
  (TextMessage para el consumer OpenWire de MSG.exe).

**Verificacion en vivo server (10.10.20.120, post `docker compose up -d --build`)**:
health 200 en 11443 y 1443; logs `[E135-RPC] catalog=2024`,
`[E135-ROOTS] roots=18 routes=72`, `[E136-WS] hub listo (ws-patch=true)`,
`[E136-EVENTCENTER] rpc=23 rest=14 routes added=14`; **live-verify 15/15**.
Probe flujo completo: login 2-step OK -> WS WELCOME+subscribe ACK OK ->
ingesta alarma OK -> **WS NotifyNormalMsg OK** -> eventCenter pull #1
msgId=1 messages=1 -> HandleAlarm records=1 -> pull #2 msgId=2 messages=1;
E-135 en server OK (BRMS.Storage code 1000, `/arms/api/BRM/label/addLabel`
echo query OK); Users/Roles/Rights-Nodes OK. **STOMP probe crudo 61613**:
5/5 topics (`brms.notifyAlarms`, `mq.alarm.msg.topic.1`, `mq.event.msg.topic.1`,
`mq.common.msg.topic.1`, `aps.notifyAlarmProcessRecord`) reciben MESSAGE con
envelope nativo `{method:"vms.alarm.msg", timestamp, info:{...}, ...VO}`.
**MQTT 1883** (dual lab): `brms.notifyAlarms` mismo envelope dual.
Tests: unit **225 tests, 224 pass / 0 fail / 1 skip** (skip preexistente
brms.test.js:1451); e2e **12/12 x2** post-deploy contra el server.

**Pendiente D8**: probar el DSS Client real (toasts 3101) con sesion viva
post E-132..E-136 - tabla de evidencias flujo a flujo en el cierre.


### Iteracion 8 cerrada (2026-11-10, commit 0bf9a37 E-137)

**Diagnostico del bug Resources**: Monitoring Center -> Resources mostraba solo
el nodo estatico "Browser". Journal server ventana 02:17:40-02:19:30Z: el
cliente pedia GET /admin/API/tree/deviceOrg, POST /admin/API/tree/devices,
GET /brms/api/v1.1/tree/full/grade-device-tree (200, 526KB) - todo 200, pero
grade-device-tree servia organizations roots-only, asi que el parser nativo
(parentCode/pId) no podia montar VIGILAB bajo 001 y el arbol colapsaba.
Logs cliente: DPSDK_GetAreaTree/GetDepartmentTree success en login,
Open Widget[ResourceManager] OK, canal presente en modelo
(OPEN_VIDEO strChannelId[D0238JDG3016\\\]) pero MoidfyDevStatus
updateStatus=0 cada minuto (devices offline en el cliente aunque el server
los tiene online:1).

**E-137 (commit 0bf9a37, 3 archivos, +20/-2)**:
- e124-grade-tree.js: uildFullGradeDeviceTreePayload sirve
  organizations/departments PLANOS (todos los orgs linkeados por pId) y
  conserva ademas los hijos anidados bajo la key organizations de cada nodo
  (doble contrato: parser nativo por parentCode + renderer de dialogos por
  hijos anidados).
- e039-mq-notify.js: los eventos DEVICE_STATUS publican los envelopes
  {method, info} de uildDeviceStatusNotifyEnvelopes tambien al topic plano
  rms.notifyChannelStatuses (MQTT y AMQ/STOMP), no solo a
  mq.*.msg.topic.<UserId>.
- rms.test.js: asercion nueva - VIGILAB presente como org top-level plano.

**Verificacion**: unit **225 tests, 224 pass / 0 fail / 1 skip**; e2e **12/12
x2**; deploy en server via docker compose up -d --build brms-gateway, health
https://127.0.0.1:1443/health HTTP 200; live-verify dentro del contenedor
**15/15**; probe en vivo confirma organizations.length=2 (001 pId=0,
VIGILAB pId=001) plano + anidado, devices 3 planos con channels,
channels 10 con pId=deviceCode, 	ree/deviceOrg departments 001 + VIGILAB
(device 3, channel 10). RTSP cam_D0238JDG3016 DESCRIBE 200 OK.

**Pendiente**: que el usuario reabra Monitoring Center -> Resources y confirme
001 -> VIGILAB -> D0238JDG3016 -> canal D0238JDG3016\\\, y que
MoidfyDevStatus updateStatus pase a 1 (topic plano consumido por MSG.exe via
OpenWire 61616 / MQTT 1883).

### Iteracion 9 cerrada (2026-11-10, commit 46d7354 E-138)

**REA ses_e3c071651ffeoKjtc23nzZtAEO (DPSDK.dll, sha256 ce43c8b7...) entrego el
contrato exacto** -> %TEMP%\opencode\rea-grade-tree.md:
- Arbol de grado (esquema FUN_1806d33a0 @0x1806d33a0): raiz dentro de data
  con organizations[], devices[], channels[] (arrays, plano canonico) +
  devices[].channels[] anidado redundante. Enlace hijo->padre = **pId**.
  devices[].status y channels[].status son **STRING** (typeCode=2):
  solo "status":"1" vincula; el numero 1 se descarta en silencio. online
  NO existe en este contrato (es clave de usuarios).
- Notify MQ (ParseMQMsg FUN_1800306b0 exige {method, info} en raiz):
  ms.notifyDeviceStatus -> parser FUN_180360120 lee info{deviceCode,
  onlineStatus INT (1->1, 2->2, resto->0), offlineReason, syncChannelStauts
  (typo SDK)}; ms.notifyDevChannelStatus y rms.notifyChannelStatuses
  -> handler FUN_1800312e0 / parser FUN_180360450 leen info objeto o array
  de {channelId, onlineStatus INT}. Claves viejas status/online/
  deviceStatus NO existen ahi -> se ignoraban => onlineStatus ausente =>
  normaliza a 0 => MoidfyDevStatus updateStatus=0 (ese log es del cliente UI,
  no de DPSDK: 0 matches en DPSDK.dll).
- DPSDK NO filtra nodos offline del arbol (copia verbatim); solo
  ilterEmptyDevice (server-side) quita devices sin canales.

**E-138 (commit 46d7354, 2 archivos, +57/-16)**: uildDeviceStatusNotifyEnvelopes
ahora emite el contrato exacto: ms.notifyDeviceStatus con
{deviceCode, onlineStatus:1 (int), offlineReason:"", syncChannelStauts:1} +
claves legacy; ms.notifyDevChannelStatus un envelope por canal
{channelId, onlineStatus:1}; rms.notifyChannelStatuses con info como
ARRAY de todos los canales. El arbol de grado ya servia status:"1" string y
pId (e124/e037 verificados).

**Verificacion**: unit 224/0/1; e2e 12/12 x2; deploy server health 1443 HTTP
200; live-verify 15/15; captura STOMP 61613 en vivo muestra en
/topic/brms.notifyChannelStatuses los envelopes nuevos
(onlineStatus:1) y en el pool mq.*.msg.topic.* (donde MSG.exe escucha).

**Pendiente**: retest del cliente real (updateStatus deberia pasar a 1) y
shape del contrato paged 	ree/orgs|devices|channels (FUN_18071dac0:
{totalCount, results[]} con online string, parentId, isParent,

odeType) - REA MainFormPlugin en curso (ses_e3c06c344ffennJpZfYkJQlPBF).

### Iteracion 10 cerrada (2026-11-10, commit 233d4ae E-139)

**REA ses_e3c06c344ffennJpZfYkJQlPBF (MainFormPlugin/UICommonModule/GroupLogical)
entrego el segundo contrato** -> %TEMP%\opencode\rea-resourcemanager.md:
- El arbol de Resources vive en UICommonModule.dll (CGradeGroupCtrl /
  CGroupSortFilterProxyModel), no en MainFormPlugin. Carga perezosa via
  \1.1/tree/grade-device-tree\ al expandir + timer de arranque
  (OnLoadGroupTimeout). El literal "Browser" es una etiqueta CLIENTE para sitio
  tipo 8 (UICommonModule 0x1809c06f0 / helper 0x180544220) y aparece SIEMPRE
  junto a la raiz code=\"001\" - no es sintoma de arbol vacio por si solo.
- Filtro clave: \SetShowOfflineNode\ escribe flag 0x67 en el proxy
  (0x18001d624); si es 0, los nodos device/canal (tipos 1/2) con estado rol
  1=OFFLINE se OCULTAN (filterAcceptsRow 0x18001e2a9). hasChild rol 0x2ff en
  orgs es obligatorio para expandir. Refresco push: notify tipo 0x7C ->
  OnNotifyGroupManagerState (0x180016cc0) -> HanldeQueryGradeDeviceTree.
- \MoidfyDevStatus updateStatus=\ es de GroupLogical.dll FUN_18004ecf0
  (Device.cpp:2441), no de DPSDK.

**E-139 (commit 233d4ae, 4 archivos, +213/-7)**: contrato PAGED
FUN_18071dac0 (rea-grade-tree.md Q2.3) para \1.0/tree/orgs|devices|channels\
- el cliente real llama estos 3 POST en cada login (journal 09:10 UTC) pero el
server servia solo \departments/deviceList/channelList\ con \parentCode\;
este esquema usa \{totalCount, results[]}\ con \parentId\, \online\ STRING
(typeCode=2), \
odeType\ (0 org / 1 device / 2 canal), \isParent\, \hasChild\.
- Nuevo \e139-paged-tree.js\ (buildPagedOrgs/Devices/ChannelsPayload) mergeado
  como superset en los 6 handlers GET+POST (aliases legacy se conservan);
  alias \online\ anadido a DeviceInfoVo en e037.

**Verificacion**: unit 226 tests / 225 pass / 0 fail / 1 skip; e2e 12/12 x2;
deploy server health 1443 HTTP 200; live-verify 15/15; check en vivo con login:
orgs totalCount=2 (001 parentId=0 hasChild=1; VIGILAB parentId=001 online=\"1\"
hasChild=1 nodeType=0), devices 3 (D0238JDG3016 parentId=VIGILAB online=\"1\"
nodeType=1), channels 10 (D0238JDG3016\\\ parentId=D0238JDG3016 online=\"1\"
nodeType=2), GET tambien paged.

**Estado global post E-137+E-138+E-139**: arbol de grado plano pId + status
string (E-137), notify onlineStatus int contrato exacto (E-138), contrato paged
en v1.0 tree trio (E-139). Pendiente: retest cliente real - Resources deberia
mostrar 001 -> VIGILAB -> D0238JDG3016 -> canal y updateStatus=1.

### Iteracion 11 cerrada (2026-11-10, commit E-140)

**2 subagentes REA nuevos entregaron los 2 informes que faltaban**
(`%TEMP%\opencode\rea-dataflow-resources.md` 575 lin + `rea-controlplane-status.md`
312 lin):

- **Resources se puebla SOLO por** `HanldeQueryGradeDeviceTree`
  (UICommonModule `0x1804f1d70`) -> `IGroupManager::GetGradeDeviceTree` (vfunc
  `+0x3c0`) -> GroupLogical `0x1800f2c90` -> **GET
  `/brms/api/v1.1/tree/full/grade-device-tree?orgCode=<nodo>&roleId=1`**.
  FINISH_GROUP es del path B (deviceOrg) y NUNCA puebla este arbol.
- **REGLA DE APLANADO (verificada, no hipotesis)**: `CreateChildItem`
  `0x1804f2200` cuelga TODO `organizations[]`+`devices[]` recibido como hijos
  DIRECTOS del nodo expandido (`appendRows` en `0x1804f1d70`). El cliente NO
  re-empareja por pId/orgCode ⇒ **el servidor debe scopear por orgCode** (lazy,
  1 nivel por request). La hipotesis E-137 (parser reconstruye por pId) quedo
  REFUTADA. Canales cuelgan del device (`dev+0x110` = `channels[]`).
- Raiz hardcodeada `"001"` (`0x18002eec4`); "Browser" es etiqueta 100% cliente
  (tipo sitio 8, `0x1809c06f0`/`0x180544220`).
- Envelope HTTP obligatorio `{code:number, desc:string, data:object}` - la
  clave es **`desc`** (no `message`); si falta, el parser lee la raiz ⇒ arrays
  vacios. Ya cumplido por `envelope()` (index.js:544). `status` del arbol =
  STRING (typeCode 2); `onlineStatus` del notify = INT (E-138). No mezclarlos.
- **Control plane**: `updateStatus=1` es 100% server-driven: solo con
  `vms.notifyDeviceStatus.info.onlineStatus` = int 1 + `deviceCode` exacto,
  publicado tambien en `mq.*.msg.topic.<UserId>` (MSG.exe escucha ese pool,
  ConsumerCount=0 en brms.notify*). `MoidfyDevStatus` = GroupLogical
  `FUN_18004ecf0` (Device.cpp:2441), unico caller `0x180055760` <-
  `FUN_1800cde90` <- notify MQ. `originStatus` se siembra del REST (arbol).
  Correccion: rol de estado del arbol = `0x2fe` (0x376 = preview).
  Verificado en gateway: MQ_USER_ID='1' = userId del login = GetMqConfig, y
  los envelopes DEVICE_STATUS ya se publican en `clientMqTopics('1')` +
  `brms.notifyChannelStatuses` (E-088/E-097/E-137).

**E-140 (3 archivos: e124-grade-tree.js, index.js, test/brms.test.js)**: scope
por `orgCode` en `buildFullGradeDeviceTreePayload` —
`orgCode` ausente/`scope=full` ⇒ arbol completo (dialog de roles + espejo
admin RPC); `orgCode=001` ⇒ solo orgs con `parentCode==='001'` (VIGILAB, sin
recursion, `hasChild` calculado contra todos los devices para el expander) y
devices con `orgCode==='001'`; `orgCode=VIGILAB` ⇒ devices de VIGILAB con
`channels[]` anidados + canales root. En `index.js` la query gana sobre el body
(DPSDK manda orgCode como query en el GET) y el espejo
`/admin/API/BRM/Tree/GetFullGradeDeviceTree` fuerza `scope:'full'`.
`search/list` siempre busca en el arbol completo. Nuevo test E-140 (scope
001/VIGILAB/full/mirror/query-wins/search-full).

**Verificacion**: unit 227 tests / 226 pass / 0 fail / 1 skip; e2e 12/12 x2;
live-verify 15/15; check en vivo con login real: orgCode=001 -> organizations
=[VIGILAB(pId="001",hasChild="1")] devices=[]; orgCode=VIGILAB -> 3 devices
con channels anidados (D0238JDG3016$1$0$0), status string; sin orgCode ->
arbol completo; espejo admin -> full.

**Retest cliente pendiente**: abrir Monitoring Center -> Resources, EXPANDIR
la raiz ("Browser"/001): request `full/grade-device-tree?orgCode=001` debe
devolver 1-3 KB con VIGILAB; expandir VIGILAB -> devices con canal; log
`MoidfyDevStatus ... updateStatus = 1` por el notify E-138.

### Iteracion 12 cerrada (2026-11-10, commit E-141)

**2 subagentes REA nuevos entregaron `rea-media-path-noroute.md` y
`rea-remaining-gaps.md`**:

- **Media path SIN ruta a camara (confirmado por REA)**: `StartVideo` no lleva
  `deviceIp`; el TCP connect del cliente va a candidatos server-provided
  (`server/video/list`, `server/serviceStatus`) y el host de la URL RTSP solo
  ordena por distancia de octetos 0..15 sin umbral. No hay ICMP ni ruta directa
  a `192.168.0.238` desde el cliente. Estado online/offline es 100%
  server-driven (REST tree + MQ `vms.notifyDeviceStatus`).
- **Contratos nuevos del cliente**: `StartVideo` puede leer `rtspUrl`/`rtspUrls`
  en base64 ademas de `url`/`url2`; `server/video/list` y `serviceStatus`
  deben exponer `ip/port/url` del servidor de media (nunca la IP de la camara).
- **Unico gap P1 real restante**: contratos exactos de
  `storage/configure/picture/warning` -> `{warningServers:[], warningHappened:"0"}`
  y `subsystem/register/warning` -> `{warningSubsystems:[], warningHappened:"0",...}`.
  Los 38 FALLBACK restantes del barrido v2 son sondas del analista, no gaps.

**E-141 (3 archivos: index.js, e109-storage.js, test/brms.test.js)**:
- `StartVideo` ahora incluye `rtspUrl`/`rtspUrls` base64 (decode == `url`) y
  sigue devolviendo `url`/`url2` planos; nunca expone `192.168.0.238`.
- Nuevas rutas `server/video/list` (GET/POST) en `/brms/api/v1.x`,
  `/ipms/api/v1.1`, `/admin/API`, `/admin/api` con candidato `video#local` ->
  `PUBLIC_HOST:RTSP_PORT` (`rtsp://10.10.20.120:9100`), via
  `buildVideoServerListPayload()` en `e109-storage.js`.
- `serviceStatus/:svc` y `allServiceStatus` enriquecidos con
  `ip/port/url/s/ports` apuntando solo al host publico; fix ruta duplicada
  `/admin/API/server/allServiceStatus` (Fastify lanzaba
  `Method 'GET' already declared` al importar).
- P1 cerrado: `GET/POST /brms/api/v1.1/storage/configure/picture/warning` y
  `/brms/api/v1.1/subsystem/register/warning` con los contratos exactos de REA.
- Nuevo test E-141: StartVideo base64, video/list en ambas bases sin IP de
  camara y con ip/port iguales al host de la URL RTSP, serviceStatus con
  ip/port/url, y los dos contratos warning.

**Verificacion**: unit 228 tests / 227 pass / 0 fail / 1 skip; e2e 12/12 x2;
deploy a `10.10.20.120` (scp + docker cp + restart), health 200,
`GET /brms/api/v1.1/server/video/list` 200 con `ip=10.10.20.120 port=9100
url=rtsp://10.10.20.120:9100`; live-verify dentro del contenedor
**15/15** (StartVideo `rtsp://10.10.20.120:9100/cam_D0238JDG3016?token=...`,
RTSP DESCRIBE 200 OK).

**Retest cliente pendiente**: Monitoring Center -> Resources -> expandir
raiz "Browser"/001 -> VIGILAB -> D0238JDG3016 -> canal
`D0238JDG3016$1$0$0`; en `C:\Users\Public\DSS Client\log\` debe aparecer
`MoidfyDevStatus ... updateStatus = 1`; en el journal del server solo 2
requests grade-tree (`orgCode=001`, `orgCode=VIGILAB`), ya no uno plano de
962 KB. El cliente debe tomar el stream desde `server/video/list`/
`serviceStatus` (10.10.20.120:9100) sin route a la camara.

### Iteracion 13 cerrada (2026-11-11, commit E-142)

**Subagente REA `ses_e378213d8ffebzE70Lc8VPPjdW` entrego
`%TEMP%\opencode\rea-flows-v3.md` + `rea-evidence-dpsdk-v3.json` (93 records)**:
quedaba **1 P0 real** (Event Center pull) y **6 P1 reales**. Veredicto clave:
el cliente DSS 8.006 **no usa DHIP/DVRIP/ARS contra el servidor DSS** (0 hits
en DPSDK.dll) — esos quedan P2.

**E-142 (7 archivos: index.js, e118, e136, e127, e135, e025, test/brms.test.js)**:
- **P0 Event Center subscribe** (`FUN_1804d2d80`): `data.totalCount` INT +
  `data.nextMsgId` STRING + `data.results` ARRAY-of-STRING (cada evento
  serializado; el cliente re-envuelve `vms.vslalarm.msg`). Arreglado en
  `e118.buildEventCenterSubscribePayload` y en la cola real de
  `e136.buildEventCenterSubscribePayload` (antes `nextMsgId` ausente ⇒ cursor
  -1 y el polling de alarmas no avanzaba).
- **alarm count**: ruta **POST** `eventCenter/alarm/messages/count` añadida y
  respuesta con `totalCount` INT único (acepta los 4 arrays INT + 6 STRING).
- **alarmTypes**: `groups[]` anidado `{groupId, groupName, alarmTypes:[{other,
  alarmTypeId, alarmTypeName}]}` en vez de catálogo plano.
- **subscribeAddress**: contrato VSL completo — `subscribePassword`,
  `subscribeUser`, `subscribeAddrType` INT, `initMessageId` ARRAY
  `{msgId STRING, type INT}` (e127 + e136 REST handler).
- **SS.Record.QueryRecords (plural)**: rutas POST explícitas en
  `/brms/api/v1.1|v1.0`, `/admin/API`, `/videoService`; raíz `pageCount`
  STRING + `totalCount` INT + `session`; `records[]` con las 13 claves STRING
  (`ssId, forgotten, endTime, streamType, recordName, diskId, recordType,
  streamId, planId, recordSource, startTime, channelId, fileLength`). P0_EXACT
  también corregido (`pageCount:'1'`, `totalCount:0` int).
- **BRMS.Device.AddDevice**: respuesta `{deviceCode STRING,
  failedDevices:[{errorMsg, deviceIp}]}` (quitada la clave `code` duplicada
  que pisaba el envelope; `failedDevices:[]` añadido en e025).
- **devicesManager/deviceTypes**: `groups[]` anidado con
  `categoryId/categoryName` + `deviceTypes:[{typeCode,typeId,typeName}]`.
- Nuevo test E-142 cubre los 6 contratos.

**Verificacion**: unit 229 tests / 228 pass / 0 fail / 1 skip; e2e 12/12 x2;
deploy a `10.10.20.120` (scp + docker cp + restart), health 200, subscribe
200 con `totalCount:0 nextMsgId:"0" results:[]`, alarm count POST 200
`totalCount:0`, `devicesManager/deviceTypes` 200 con grupos anidados;
live-verify dentro del contenedor **15/15**.
