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
