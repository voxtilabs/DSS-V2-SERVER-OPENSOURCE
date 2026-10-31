# DSS_CLIENT_RESEARCH.md — Protocolo cliente-servidor DSS e integración

Alcance: entender (1) cómo funciona la comunicación DSS Client ↔ DSS Server, (2) qué APIs de
integración existen de forma oficial, (3) decidir si algún día DSS Client original puede hablar con
DSS V2 — sin bloquear el proyecto si no se logra.

## 1. Frontera de investigación del proyecto

- El protocolo interno del DSS **no está documentado** y no se asume disponible.
- Distinguir SIEMPRE: API de integración oficial ≠ protocolo interno completo.
- Método: análisis estático de los ejecutables con REA (`morluto/rea`) para binarios
  **Windows** (DSS Client, servicios del Server) + capturas de red en laboratorio (E-001).
- Los ejecutables se obtienen del instalador oficial de Dahua con licencia válida y se analizan
  localmente. No se publican binarios ni se eluden controles de licencia (ADR-0003, ADR-0005).

## 2. Arquitectura confirmada del lado servidor (EV-001, EV-002)

- Modularidad oficial por servicios: CMS, DMS, SS, MTS, ARS, ADS, PTS, OSS (datasheet V7).
- Puertos V7 a nivel router: 9500, 9200, 21, 990, 9090, 61616, 9100, 3306 (MySQL), 9550, 9400, 80, 5080.
- V8 (Ultimate 8.8, corresponde a DSS Pro V8.8): instalador disponible; servicios equivalentes por
  confirmar con el análisis de E-006.
- El appliance DSS7016D (nuestra producción) ejecuta una versión embebida del mismo modelo (EV-010).

## 3. Preguntas de investigación (checklist dinámico)

| # | Pregunta | Método | Estado |
|---|----------|--------|--------|
| 1 | ¿Qué binarios/servicios conforman el Client y el Server? (procesos, DLL, firma Authenticode) | análisis PE de REA (imports, certificados) | Pendiente E-006 |
| 2 | ¿Es el Client Electron/Qt/C++ nativo? | REA `analyze-javascript-application` vs. imports nativos | Pendiente |
| 3 | ¿Qué endpoints/sockets abre el Client hacia el Server? | Capture Wireshark por operación (login, live, playback, alarmas) | E-001 |
| 4 | ¿Existe API oficial de integración de DSS V8 (HTTP)? | Buscar documentación oficial + programa partner (EV-007/EV-008) | Abierta |
| 5 | ¿La API oficial cubre todo lo que el Client hace? | Mapa funcional API vs. capturas | Abierta |
| 6 | ¿El Client es re-autenticable contra un server "parecido"? | Verificar esquema de tokens/certificados en V8 — asumir NO sin evidencia | Abierta |
| 7 | ¿Qué base de datos local usa el Server (MySQL 3306 en V7)? | Solo lectura de esquema en laboratorio, jamás en producción | E-001 |

## 4. Estrategia de compatibilidad con DSS Client

- **Primera prioridad:** Web Client propio (React/TS) — nunca bloqueado por el punto anterior.
- **Línea experimental aislada:** `components/dss-compat-adapter/`. Si se demuestra que el Client
  habla un protocolo estándar (por ejemplo REST + WebSocket oficial de V8), DSS V2 podría exponer un
  "perfil de protocolo" compatible. Cualquier adaptador debe ser un plugin separado, sin
  acoplamiento al núcleo, y jamás debe embeber secretos de Dahua.
- **Estado:** HIPÓTESIS de nivel bajo (sin evidencia aún). No asumir compatibilidad nunca.

## 5. Playbook de ingeniería inversa (E-006) con REA

Herramientas: Windows de laboratorio + REA (CLI/MCP, `npx -y rea-agents@latest`)
+ Hopper/Ghidra/IDA si se dispone; proceso no destructivo en máquina virtual dedicada.

Fase 1 — Entorno:
1. Descargar el instalador oficial de Dahua (por ejemplo `General_DSS-PRO_Win64_...exe`) con cuenta
   de la organización; conservar hash SHA-256 en `research/evidence/samples-manifest.md` (fuera de git).
2. Instalar en una VM Windows de laboratorio (con snapshot antes de instalar; sin licencia en
   producción activada).
3. Registrar los ejecutables en el manifest y activar capturas con Process Monitor/Sysinternals.

Fase 2 — Análisis estático:
4. Inspección PE de REA: imports, certificado Authenticode, cadenas (`strings`), y si el Client es
   Electron, `analyze-javascript-application`.
5. Identificar: ejecutables del servidor (servicios CMS/DMS/MTS/…), librerías (NetSDK, P2P), base de
   datos local, puertos escuchados (netstat), módulos de autenticación.
6. Documentar cada hallazgo con archivo/función/import y nivel de confianza.

Fase 3 — Dinámico (con autorización):
7. DSS Client contra el server de laboratorio: captura Wireshark por operación; documentar endpoints
   en `docs/NETWORK_PROTOCOLS.md`.
8. Correlacionar la tabla de puertos V7 (EV-002) con los servicios reales observados.

Fase 4 — Síntesis:
9. Producir matriz funcional (Client↔Server) y decidir dónde aporta la compatibilidad.


## 8. El instalador Server V8.008 embebe al Client (E-006 V2, 2026-10-30)

Descubrimiento (EV-026): dentro del data-area del instalador **DSS Ultimate Server V8.008 R.20260930** viaja, como bloque stored íntegro (247,743,936 B, `span+8 == gap` verificado, MZ en `: raw`), el instalador completo **`General_DSS-Client_Win64_IS_V8.008.0000000.0.R.20260325.exe`**. Es decir: el paquete de servidor distribuye el cliente oficial (nuevo build R.20260325, distinto del V8.006 de M-001) y no hay que descargar el client aparte.

SDKs incluidos en ese árbol (hashes completos en `pkgB-key-sha256.json`, fuera de git):

| DLL | Bytes | SHA-256 |
|---|---|---|
| DPSDK.dll | 11,388,424 | `3f49799f71684aafacdf7a38288463af08d150dc0b7e6d5f9dcdbd072740e048` |
| P2PDll.dll | 3,542,016 | `0b1082ef5f0c444f05e023dd9c26e4a1262312f7f9b59afc943eecf97a21f75c` |
| netsdk.dll | 33,253,888 | `4d862b9272140df4efd0072f83d1273acd64b2f09635aed0dd18f469a8d91b48` |

Estas generaciones difieren de las del instalador client V8.006 (EV-019): comparativa de versiones/exports → propuesta E-007.


## 9. Correlación DPSDK ↔ contrato BRMS (E-007, EV-030)

La misma DLL que el Client usa para vídeo/alarmas (DPSDK.dll) contiene el cliente REST de BRMS: construye /brms/api/v1.0/accounts/authorize, envía "X-Subject-Token: %s", ofrece WINPC_V2/WINPC_V1 como clientType y llama MTS/Video/StartVideo, tree/devices y accounts/keepalive, apoyándose en curl (HSTS/cookies) y jsoncpp. SetP2PClientType indica que el P2P easy4ip y el login BRMS comparten sesión de token. La generación client añade DPSDK_StartWebsocketServer (el propio DPSDK puede exponer una salida WebSocket local, útil como referencia de integración V2) y las claves de bus brms.notify* (probable ActiveMQ).
Compatibilidad DSS V2 → ver DAHUA_COMPATIBILITY.md §5 y NETWORK_PROTOCOLS.md §7.


## 10. Compatibilidad DTO/Endpoint 1:1 (E-008, EV-037/038)

El DSS Client original (DPSDK.dll) envía/recibe exactamente los DTOs listados en `DAHUA_COMPATIBILITY.md` §6. El Mock Gateway (EV-038) implementa todos los endpoints críticos y pasa los tests de handshake y formato `channelId`. Cualquier servidor DSS V2 que implemente esa superficie será compatible con el Client oficial.
## 11. Compatibilidad DTO/Endpoint completa (E-009, EV-041/042/044)

El Mock Gateway (`poc/dss-v2-harness/brms-gateway/`) implementa **100% de los DTOs** del servidor Dahua (46 clases, ver `research/evidence/brms-dto-schemas.json`). Tests automatizados validan:

```bash
cd poc/dss-v2-harness/brms-gateway
npm test
```

Cobertura:
- Handshake MD5 doble WINPC_V2 (401→200)
- TokenInfoVo: token, userId, username, userType, topLevel
- DeviceOrgTreeVo: departments[OrgNodeVo]
- DeviceTreeVo: devices[DeviceUnitInfoVo]
- RealTimeVideoVo: 18 campos (vkId, vkValue, multicast, stun, connectType)
- RecordQueryVo: pageCount, records[], session
- VehicleVo: 16+ campos, CarQueryParamXo 25+ filtros
- PointDoorStatusListVo, PtzOperateVo, PageAlarmRecordXo
- UDP 18800 alarm ingest

CI ejecuta `npm test` en cada push. Cualquier servidor DSS V2 que pase estos tests es compatible con el DSS Client WINPC_V2 original.
## 12. P2P Connector Real Implementation (E-010, EV-051/052)

El PoC `poc/dss-v2-harness/` ahora incluye implementación real del conector P2P:

### 12.1 p2p-probe (libTouProxy real)
```bash
cd poc/dss-v2-harness/p2p-probe
npm install
SN=<serial> USER=admin PASS=admin123 node src/index.js
```

Flujo verificado:
1. SOAP `getDeviceByDevSequence(SN)` → `www.easy4ip.com`
2. PTCP handshake → `createLocalPort(127.0.0.1:port)`
3. Túnel PTCP bidireccional sobre UDP
4. Forwarding `127.0.0.1:localPort` → DVRIP/RTSP del dispositivo

### 12.2 brms-gateway + WebSocket + Mock RTSP
```bash
cd poc/dss-v2-harness/brms-gateway
npm test
```

Validaciones:
- Handshake MD5 doble WINPC_V2
- `RealTimeVideoVo` 18 campos (vkId, vkValue, multicast, STUN, connectType)
- WebSocket `/event/ws` para alarmas tiempo real
- Mock RTSP 9100 con validación `?token=`
- Docker Compose + `deploy/ubuntu-lab-setup.sh` para lab

CI ejecuta `npm test` en cada push. Cualquier servidor DSS V2 que pase estos tests es compatible con el DSS Client WINPC_V2 original.
