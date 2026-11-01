# DAHUA_COMPATIBILITY.md — SDKs oficiales, versiones y licencias

## 1. NetSDK (SDK oficial de integración a dispositivos)

| Aspecto | Estado | Evidencia |
|---|---|---|
| Existe versión Linux x86_64 | **CONFIRMADO** (NuGet `Dahua.NetSDK.Native` v3.57.2023.309 incluye `linux-x64`; vías históricas con libs lin64 por Download Center) | EV-004 |
| API cubre login/canales/video/playback/PTZ/alarma | CONFIRMADO por Programming Guide (`CLIENT_Init/LoginEx2/RealPlay/PlaybackByFile/…`) | EV-004 |
| Puerto estándar de dispositivo | 37777 (privport) | EV-004/EV-013 |
| P2P integrado en el SDK standalone | **NO OPERATIVO** según reporte (requiere `libP2PDll` + credenciales de app) | EV-005 |
| Lenguaje de integración en DSS V2 | C++ directo (FFI hacia .so) | ADR-0002 |

### Reglas del proyecto sobre el SDK
1. Los binarios del SDK **nunca** se commitean. Se descargan del canal oficial, se registran con
   Sha-256 y fecha en `research/evidence/sdk-manifest.md` (fuera de git), carpeta local avalada.
2. Este repositorio no redistribuye el SDK: quien clone necesita obtenerlo por su propia vía legal.
3. Cualquier envoltorio (wrapper) que escribamos vive en `components/p2p-connector/vendor/…` con notas
   de integración, sin incluir el binario nativo.

## 2. Matriz de compatibilidad objetivo (por llenar en E-002)

| Dispositivo | Modelo | Firmware | NetSDK login | Canales | RealPlay | Playback | Eventos |
|---|---|---|---|---|---|---|---|
| NVR de laboratorio | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## 3. Ecosistema de productos De Dahua (referencias)

| Producto | Rol en el ecosistema | Información |
|---|---|---|
| DSS Professional / Ultimate V8.x | VMS licenciado de referencia; puerta OpenAPI por definir | dahuasecurity.com, EV-003 |
| DSS Express | Variante de DSS para SMB | catálogo |
| DSS7016D appliance | producción actual (VMS embebido) | EV-010 |
| SmartPSS | client ligero para dispositivos (liga P2P `libP2PDll`) | EV-005 |
| DMSS / gDMSS | móviles con P2P por SN | EV-006 |
| DoLynk / Imou clouds | nube IoT de consumo (DoLynk Developer) | EV-009 |

## 4. Puntos de licencia y cumplimiento

- EULA del instalador: prohibida la ingeniería inversa salvo límites legal aplicable. Trabajamos con
  el "fair use"/excepción de interoperabilidad solo con ejecutables que la organización administra y
  analizando localmente; NO redistribuimos nada.
- No se requiere desactivar (bypass) la activación/licencia: nuestro laboratorio usa licencias de
  prueba y dispositivos propios. Nunca se elude, ni se publica cómo hacerlo (ADR-0003).
- SDK: redistribución restringida; mencionar a Dahua si el proyecto crece (vía Partner, EV-008).

## 5. Multi-fabricante (fase posterior)

Interoperabilidad Open: cualquier driver ONVIF/Generic-RTSP debe ser plugin separado; por ahora el
alcance es Dahua-first.


## 5. Compatibilidad REST con DSS Client V8 (E-007, EV-029/EV-030)

Un servidor de reemplazo (DSS V2) que sirva al DSS Client original debe exponer, en puerto 1443 con TLS, como mínimo:
1. POST /brms/api/v1.0/accounts/authorize con handshake MD5 doble (realm + randomKey + signature, clientType WINPC_V2) y respuesta {"token","duration":86400}; además accounts/keepalive, GET accounts/current, accounts/unauthorize.
2. Cabecera X-Subject-Token en todos los recursos autenticados y formato channelId "num$K$m$0".
3. v1.0/tree/orgs|devices|channels con deviceCode y channelType.
4. v1.0/MTS/Video/StartVideo|StopVideo|KeepAlive; streaming RTSP en 9100 con token= (o RTSP-over-HTTP, soportado por el cliente) y HLS v1.1/video/live.
5. El resto de recursos según alcance (eventos, grabaciones SS, PTZ, ANPR, control de puertas) — ver EV-029/EV-030.
El contrato lo fijan los strings del Client; no hay requisito de credenciales de app Dahua por parte de DSS V2 (ADR-0004).


## 6. Catálogo completo de endpoints BRMS por controlador (E-008, EV-037)

| Controlador (paquete) | Método público | Payload Request (DTO) | Respuesta (DTO) | Endpoint HTTP inferido |
|---|---|---|---|---|
| AuthorizeController (v1s1.authorize) | getToken | TokenInfoXo | ResponseInfo | POST /brms/api/v1.1/accounts/authorize |
| AuthorizeController | checkToken | TokenInfoXo | ResponseInfo | POST /brms/api/v1.1/accounts/check |
| AuthorizeController | checkCredence | CredenceXo | ResponseInfo | POST /brms/api/v1.1/accounts/credence |
| AccountController (linux.account) | getMenus | — | ResponseInfo<MenuListVo> | GET /brms/api/v1.1/accounts/menus |
| AccountController | updatePassword | AccountInfoVo | ResponseInfo | POST /brms/api/v1.1/accounts/password |
| DeviceTreeController (v1s0.brm.deviceTree) | getDeviceOrgTree | (orgId, userId, deviceType) | DeviceOrgTreeVo | POST /brms/api/v1.0/tree/orgs |
| DeviceTreeController | getDeviceInfoTree | DeviceTreeXo | DeviceTreeVo | POST /brms/api/v1.0/tree/devices |
| DeviceTreeController | searchDeviceTree | DeviceTreeSearchXo | TreeNodePageVo | POST /brms/api/v1.0/tree/search |
| MTSVideoController (v1s0.mts.video) | startVideo | RequestInfo<RealTimeVideoXo> | ResponseInfo<RealTimeVideoVo> | POST /brms/api/v1.0/MTS/Video/StartVideo |
| MTSVideoController | stopVideo | — | — | POST /brms/api/v1.0/MTS/Video/StopVideo |
| EventController (ecos.event) | pushEvent | EventXo | ResponseInfo | POST /brms/api/v1.0/event/subscription |
| EventController | batchPushEvent | EventXos | ResponseInfo | POST /brms/api/v1.0/event/batch |
| SSRecordController (v1s0.ss.record) | queryRecords | RequestInfo<RecordQueryXo> | RecordQueryVo | POST /brms/api/v1.0/SS/Record/QueryRecord |
| SSRecordController | startRecord | RecordStartStopXo | RecordStartStopVo | POST /brms/api/v1.0/SS/Record/Start |
| AccessController (v1s1.obms.access) | getDoorCurrentStatus | PointIdsXo | SessionVo | POST /brms/api/v1.0/access/door/status |
| AccessController | getAreaAccessRecordPage | AccessRecordPageXo | PageBean<AreaRecordVo> | POST /brms/api/v1.0/access/records |
| VehicleController (v1s1.ipms.vehicle) | getCars | CarQueryParamXo | PageVo<VehiclePageVo> | POST /brms/api/v1.0/vehicle/list |
| VehicleController | addCars | AddCarsXo | RepeatOrExistCarsNewVo | POST /brms/api/v1.0/vehicle/add |
| VehicleController | getEntranceAccessInfo | (groupId, entranceId, plateNo) | VehicleEntranceAccessAuthInfo | POST /brms/api/v1.0/vehicle/entrance/info |
| PtzController (v1s1.ptz) | moveAbsolutely | (channelId, PtzMoveAbsolutelyXo) | PtzOperateVo | POST /brms/api/v1.0/ptz/direction |
| PtzController | getPresetPoints | channelId | PtzPresetPointVo | POST /brms/api/v1.0/ptz/preset |
| BRMAlarmController (v1s0.eams.alarm) | handleAlarm | AlarmHanleXo | ResponseInfo | POST /brms/api/v1.0/alarm/handle |
| AlarmRecordController (v1s1.eams.alarm) | queryAlarmRecords | PageAlarmRecordXo | PageVo<AlarmVo> | POST /brms/api/v1.0/alarm/records |

Compatibilidad DSS V2: implementar los endpoints arriba con `RequestInfo<T>`/`ResponseInfo<T>`, cabecera `X-Subject-Token`, handshake MD5 doble (`WINPC_V2`).
## 7. Contrato DTO completo para compatibilidad DSS Client (E-009, EV-041/042/044)

El Mock Gateway (`poc/dss-v2-harness/brms-gateway/`) implementa **todos los DTOs** extraídos del servidor Dahua (46 clases, ver `research/evidence/brms-dto-schemas.json`). Un servidor DSS V2 compatible debe:

1. Usar envelope `ResponseInfo<T> = { code, desc, data }` con `code: 1000` para éxito.
2. Implementar handshake MD5 doble exacto (`temp = md5(md5(user+md5(pass)))`, `sig = md5(md5(user:realm:temp):randomKey)`, `clientType: "WINPC_V2"`).
3. Devolver DTOs exactos (ver `research/evidence/brms-dto-schemas.json`):
   - Auth: `TokenInfoVo` (token, userId, username, userType, topLevel)
   - Tree: `DeviceOrgTreeVo`, `DeviceTreeVo`, `DeviceTreeXo`
   - Video: `RealTimeVideoVo` (18 campos incluyendo vkId/vkValue, multicast, stun)
   - Records: `RecordQueryVo` (pageCount, records[], session)
   - Vehicle: `VehicleVo` (16+ campos), `CarQueryParamXo` (25+ filtros)
   - PTZ: `PtzPresetPointVo`, `PtzMoveAbsolutelyXo`
   - Alarms: `AlarmVo`, `PageAlarmRecordXo`
4. UDP 18800/19800 para alarmas CRLF.
5. WebSocket opcional para eventos en tiempo real (`DPSDK_StartWebsocketServer` observado en client gen).

Tests de compatibilidad: `npm test` en `poc/dss-v2-harness/brms-gateway/`.
## 8. PTCP/Tou Protocol & ProxyClientImpl (E-010, EV-049/050)

Para compatibilidad P2P completa con DSS Client:

1. **Vtable CProxyClientImpl** (offsets x64):
   - `vtable[0]`: destructor
   - `vtable[1]`: `getState() -> uint32` (0=uninit, 1=ready, 2=error)
   - `vtable[2]`: `createLocalPort(bindCtx, localPort, remoteIp, ...) -> int`
   - `vtable[3]`: `deletePort(port) -> int`
   - `vtable[4]`: `getDeviceInfo(callback) -> void` (async, entrega `jsonDevInfo`)

2. **PTCP/Tou Wire Protocol** (UDP):
   - Puerto local bind: `0.0.0.0:localPort` (validación `remoteIp==127.0.0.1`)
   - Relay: `/relay/agent` + `agenthost:` (DNS)
   - Paquetes: `cmd(4) | seq(4) | len(4) | flags(4) | payload`
   - Keepalive 30s

3. **Integración DSS V2**: reimplementar `createLocalPort` + túnel PTCP en `poc/dss-v2-harness/p2p-probe/`.

## 9. E-011: E2E Integration Lab Deployment & DSS Client Connection (EV-054/055)

### 9.1 Lab Deployment Verified
- **Server**: Ubuntu 26.04 at 10.10.20.120 (Node 20.20.2, Docker 29.9.2)
- **Container**: `dss-v2-harness-brms-gateway:latest`
- **Exposed Ports**:
  - 1443/TCP: HTTPS BRMS API (self-signed cert CN=10.10.20.120)
  - 11443/TCP: HTTP BRMS API
  - 9100/TCP: RTSP Mock (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN + SDP H.265)
  - 18800/UDP: Alarm Ingest Primary
  - 19800/UDP: Alarm Ingest Backup
  - WebSocket: `wss://10.10.20.120:1443/brms/api/v1.0/event/ws`

### 9.2 E2E Test Suite Results (All 5 PASS)
| Test | Validation |
|------|------------|
| E2E-1 | Auth handshake 401→200 (double MD5, WINPC_V2) + keepalive/current |
| E2E-2 | Tree/orgs + devices + channels (exact DTOs) |
| E2E-3 | MTS StartVideo → RTSP URL + **TCP probe OPTIONS/DESCRIBE** → `RTSP/1.0 200 OK` + H.265 SDP |
| E2E-4 | UDP 18800 → WebSocket push (event `type:ALARM` received) |
| E2E-5 | P2P probe manual profile (`restart: "no"`) |

Unit tests: 10/10 PASS in brms-gateway.

### 9.3 DSS Client Windows Connection Guide
**Prerequisites:**
- Install `DSS Client V8.008` (M-001/M-002)
- Import `cert.pem` (CN=10.10.20.120) to Trusted Root CA: `certmgr.msc` → Trusted Root Certification Authorities → Certificates → Import

**Connection Steps:**
1. Launch DSS Client
2. Server IP: `10.10.20.120`
3. Port: `1443`
4. Username: `admin`
5. Password: `admin123`
6. Click **Login**

**Client Flow (Auto-handled):**
1. Client sends `POST /brms/api/v1.0/accounts/authorize` with `{"userName": "admin"}`
2. Server returns HTTP 401 with `realm: "DSS-V2-LAB"`, `randomKey`, `challengeKey`
3. Client computes:
   - `temp = md5(md5("admin" + md5("admin123")))`
   - `signature = md5(md5("admin:DSS-V2-LAB:" + temp) + ":" + randomKey)`
4. Client sends `POST /brms/api/v1.0/accounts/authorize` with `{"userName": "admin", "randomKey": "...", "signature": "...", "clientType": "WINPC_V2", "challengeKey": "..."}`
5. Server returns `{"token": "...", "duration": 86400}`
6. All subsequent requests include `X-Subject-Token: <token>`

**Live View:**
- Tree: `POST /brms/api/v1.0/tree/orgs|devices|channels` → `channelId: "1000171$1$0$0"`
- Start Video: `POST /brms/api/v1.0/MTS/Video/StartVideo` with `{"channelId": "1000171$1$0$0", "streamType": 1, "dataType": 1}`
- Returns RTSP URL: `rtsp://10.10.20.120:9100/1000171$1$0$0?token=<token>`
- Client opens RTSP: `OPTIONS` → `DESCRIBE` → `SETUP` → `PLAY` → H.265 playback

**Alarms:**
- UDP 18800: `ANPR_EBA|CAM001|plate=ABC1234\r\n`
- Gateway broadcasts via WebSocket `wss://10.10.20.120:1443/brms/api/v1.0/event/ws`
- Client receives real-time event popup

### 9.4 Verification Commands
```bash
# Unit tests
cd poc/dss-v2-harness/brms-gateway && npm test

# E2E tests (from Windows)
node --test poc/dss-v2-harness/e2e-lan-test.mjs

# Server health
curl -k https://10.10.20.120:1443/health
```

## 10. E-012: Real H.265 Video Engine + Bootstrap APIs + P2P Bridge (EV-056..059)

### 10.1 Componentes Actualizados
| Componente | Versión | Cambios |
|------------|---------|---------|
| `brms-gateway` | 0.4.0 | MediaMTX integration, Bootstrap APIs, P2P Register, Inspector Middleware |
| `docker-compose.yml` | - | MediaMTX service, puertos actualizados |
| `e2e-lan-test.mjs` | - | RTSP signaling validation, P2P register tests |

### 10.2 MediaMTX H.265 Streaming
- **Servicio**: `mediamtx` (`bluenviron/mediamtx:latest` v1.21.3) en docker-compose
- **Puertos**: 9100:8554 (RTSP), 1935 (RTMP), 8888 (HLS), 8889 (WebRTC)
- **Paths**: `test`, `cam1` con `source: publisher`
- **Estado actual**: RTSP signaling funcional (OPTIONS 200 OK, DESCRIBE 404 sin publisher)
- **Requisito para H.265 real**: Publisher FFmpeg externo → `runOnInit` con `testsrv2` + `libx265`

### 10.3 Bootstrap APIs (Post-Login Client Initialization)
Endpoints que DSS Client invoca tras login exitoso:

| Endpoint | DTO Response | Descripción |
|----------|--------------|-------------|
| `GET /brms/api/v1.0/accounts/menus` | `MenuListVo` | Menú principal |
| `GET /brms/api/v1.1/accounts/menus` | `MenuListVo` | Menú v1.1 |
| `GET /brms/api/v1.0/accounts/userinfo` | `UserInfoVo` | Info usuario |
| `GET /brms/api/v1.0/system/time` | `ServerTimeVo` | Tiempo NTP |
| `GET /brms/api/v1.0/version` | `VersionVo` | Versión servidor |
| `GET /brms/api/v1.0/system/version` | `VersionVo` | Versión (alt) |
| `GET /brms/api/v1.0/capability` | `CapabilityVo` | Capacidades |
| `GET /brms/api/v1.0/license` | `LicenseInfoVo` | Licencia |

**Inspector Middleware**: Catch-all hook loggea request/response completo.

### 10.4 P2P Device Register Bridge
Nuevos endpoints en `brms-gateway`:

| Endpoint | Body | Response |
|----------|------|----------|
| `POST /brms/api/v1.0/device/p2p-register` | `{ sn, user, password, name, channels }` | `{ deviceId, channelIds, p2pStatus }` |
| `POST /brms/api/v1.0/device/p2p-unregister` | `{ sn }` | `{ success: true }` |
| `POST /brms/api/v1.0/device/p2p-list` | - | `{ devices: [...] }` |

**Flujo**: SN → `deviceId` (`P2P-xxx`) + `channelIds` (`P2P-xxx$1$0$0`) → túnel PTCP futuro.

### 10.5 E2E Tests Results (All PASS)
| Test | Validación |
|------|------------|
| E2E-1 | Auth handshake + keepalive/current |
| E2E-2 | Tree/DTOs exactos |
| E2E-3 | RTSP OPTIONS 200 OK + DESCRIBE (200/404) |
| E2E-4 | UDP 18800 → WebSocket push `type:ALARM` |
| E2E-5 | P2P probe manual + register endpoints |

### 10.6 Verification Commands
```bash
# Unit tests (includes bootstrap, P2P endpoints)
cd poc/dss-v2-harness/brms-gateway && npm test

# E2E tests (from Windows)
node --test poc/dss-v2-harness/e2e-lan-test.mjs

# Health check
curl -k https://10.10.20.120:1443/health

# Test P2P register
curl -k -X POST https://10.10.20.120:1443/brms/api/v1.0/device/p2p-register \
  -H "X-Subject-Token: <token>" -H "Content-Type: application/json" \
  -d '{"sn":"SN123456","user":"admin","password":"admin123","channels":4}'

# Test ARS register (device auto-registration, no auth)
curl -k -X POST https://10.10.20.120:1443/brms/api/v1.0/ars/register \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"CAM-001","deviceName":"Test Cam","ip":"192.168.1.100","port":37777}'
```

### 10.7 ARS (Auto Register Service) - Registro Automático Tradicional
**Validado por Don Omar**: "El autoregistro requiere que le des una IP, un puerto y un ID para el registro. Puedes desactivar p2p y el autoregistro funciona igual."

| Endpoint | Auth | Body | Response |
|----------|------|------|----------|
| `POST /ars/register` | No | `{ deviceId, deviceName, ip, port, username, password, deviceType, channelNum }` | `{ success, deviceId }` |
| `POST /ars/keepalive` | No | `{ deviceId }` | `{ success, deviceId }` |
| `POST /ars/unregister` | No | `{ deviceId }` | `{ success }` |
| `POST /ars/list` | Sí | - | `{ devices: [...] }` |
| `POST /ars/device-info` | Sí | `{ deviceId }` | `DeviceTreeVo` |

**Diferencia clave**: ARS = device-to-server (sin P2P), P2P Register = client-to-server (con P2P).

## 11. E-013: ARS TCP Real + H.265 Real + Contenedores Sanos (EV-061..063)

### 11.1 ARS TCP Binary Protocol (DVRIP/DHIP) - Puerto 9500
Protocolo binario nativo Dahua para autoregistro de dispositivos (VMS_ARCMS.exe).

| Aspecto | Detalle |
|---------|---------|
| Puerto | TCP 9500 |
| Protocolo | DVRIP/DHIP binario (cabecera 32 bytes + payload) |
| Magic | `0x44484950` ("DHIP") |
| Comandos | REGISTER (0x0001), HEARTBEAT (0x0002), LOGOUT (0x0005) |
| Respuestas | REGISTER_ACK (0x8001), HEARTBEAT_ACK (0x8002), LOGOUT_ACK (0x8005) |

**Payload REGISTER**: Device ID, Name, Type, Channels, IP, Port, Credentials, MAC, Firmware (strings null-terminated)

### 11.2 MediaMTX H.265 Real Publisher
- **Custom Docker**: Multi-stage (alpine + FFmpeg 6.1 + libx265) + MediaMTX v1.11.3
- **Puertos**: 9100:8554 (RTSP), 1935 (RTMP), 8888 (HLS), 8889 (WebRTC)
- **FFmpeg publisher**: `runOnInit` con `libx265` + `testsrv2` + `keyint=25`
- **SDP H.265 real**: `rtpmap:96 H265/90000` + `sprop-vps/sps/pps` válidos

### 11.3 E2E Test Results (All PASS)
| Test | Validación |
|------|------------|
| E2E-1 | Auth handshake + keepalive/current |
| E2E-2 | Tree/DTOs exactos |
| E2E-3 | RTSP OPTIONS 200 OK + DESCRIBE 200 OK + SDP H.265 real (VPS/SPS/PPS) |
| E2E-4 | UDP 18800 → WebSocket push |
| E2E-5 | P2P probe + ARS REST + ARS TCP |

### 11.4 Verification Commands
```bash
# Unit tests
cd poc/dss-v2-harness/brms-gateway && npm test

# E2E tests (from Windows)
node --test poc/dss-v2-harness/e2e-lan-test.mjs

# Health check
curl -k https://10.10.20.120:1443/health

# Test ARS TCP binary (raw DVRIP on port 9500)
# See poc/dss-v2-harness/test-ars-tcp.mjs for reference implementation
```
