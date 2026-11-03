# NETWORK_PROTOCOLS.md — Protocolos y puertos observados/documentados

Todo dato de este archivo debe tener evidencia en `docs/RESEARCH.md` y nivel de confianza.

## 1. Dispositivo Dahua (NVR/XVR/IPC)

| Puerto/protocolo | Uso supuesto | Confianza | Evidencia |
|---|---|---|---|
| TCP 37777 (DVRIP / privport) | Control + integración SDK (NetSDK) | CONFIRMADO como estándar NetSDK | EV-004, EV-013 |
| TCP 37778 (tlsprivport) | DVRIP sobre TLS | PROBABLE | EV-013 |
| TCP 554 (RTSP / rtspport) | Video en directo | PROBABLE (url `/cam/realmonitor?channel=N&subtype=S`) | EV-013, EV-006 |
| TCP 80 (httpport) | Web del dispositivo | PROBABLE | EV-013 |
| UDP P2P (Easy4IP/dahuap2p) | Registro SN, rendezvous, PTCP | PROBABLE | EV-006 |

Creencias pendientes de validación (hipótesis):
- Mismos puertos en todos los firmwares de nuestra flota → verificar por NVR modelo con E-002.
- Comportamiento de reconexión P2P tras caída de WAN → E-003.

## 2. Servidor DSS (referencia de integrapción)

### V7 — CONFIRMADO (EV-002)

Puertos listados en el manual oficial para mapear en router:
`9500, 9200, 21, 990, 9090, 61616, 9100, 3306, 9550, 9400, 80, 5080`.

Interpretación probable (a correlacionar en laboratorio E-001):
- 3306: MySQL (almacén de configuración/metadatos)
- 21/990: FTP con FTPS (transferencia de recordings/exportaciones)
- 61616: broker de mensajería interno (típico ActiveMQ)
- 80/443: portal HTTP/S del server (login de Client)
- 9500/9200/9090/9100/9550/9400/5080: servicios internos (CMS/DMS/MTS/SS/…); mapeo exacto a
  determinar.

### V8 — NO VERIFICADO (por confirmar en E-001/E-004)

## 3. Operaciones a capturar (E-001)

Separar captura por operación y registrar: IPs, puertos, protocolos, duración, frecuencia, tamaño de
paquete, DNS, conexiones persistentes, servicios identificados, cifrado observado (TLS?). Template:
`experiments/E-001-capturas-lab/README.md`.

1. Inicio del DSS Client
2. Autenticación
3. Consulta de dispositivos
4. Apertura de Live View
5. Multiview
6. Playback
7. Desconexión de NVR
8. Reconexión de NVR
9. Recepción de alarmas

## 4. P2P — resumen operativo

Ver `docs/P2P_RESEARCH.md` (handshake, `/info/device/{SN}`, PTCP, relay).

## 5. Tabla de dominios DNS vistos por evidencia

| Dominio | Función reportada | Confianza |
|---|---|---|
| easy4ip.com | nube P2P Dahua/derivados | PROBABLE (EV-005/EV-006) |
| dahuap2p.com | nube P2P Dahua | PROBABLE |
| amcrest ddns/services | variante Amcrest | PROBABLE |

Fuentes de confirmación propias: registro DNS en capturas de E-003.

## 6. Seguridad sobre el canal

- El transporte aplicación -> dispositivo suele ser DVRIP con Login cifrado (MD5 con realm) y TLS
  opcional 37778 — conf. EV-006/EV-013: PROBABLE. Verificar variantes de cifrado por firmware.
- Para DSS V2: todo habla salir con TLS (ver `docs/SECURITY.md`), independizándose del estado del
  canal dispositivo→VMS (que puede no ser cifrado end-to-end).


## 7. Gateway REST BRMS (puerto 1443/TLS) — contrato observado (E-007, EV-029/EV-030)

Base: https://<server>:1443/brms/api/v1.0/ (y v1.1), JSON UTF-8, token en cabecera X-Subject-Token.

### 7.1 Handshake de autenticación (EV-029)
1. POST accounts/authorize con {"userName": "..."} —> HTTP 401 con realm y randomKey.
2. temp = md5(md5(userName + md5(password))); signature = md5(md5(userName + ":" + realm + ":" + temp) + ":" + randomKey).
3. POST accounts/authorize con {"userName","randomKey","signature","clientType":"WINPC_V2"} —> {"token","duration":86400}.
4. Sesión: POST accounts/keepalive; GET accounts/current; POST accounts/unauthorize.

Confirmación estática: DPSDK.dll genera exactamente esas rutas y cabeceras ("X-Subject-Token: %s", "buildMd5DigestAuthReq", "WINPC_V2") — EV-030.

### 7.2 Recursos confirmados y su uso por el Client
v1.0/tree/orgs|devices|channels; v1.0/MTS/Video/StartVideo|StopVideo|KeepAlive; v1.1/video/live/channel/{channelId}/hls; v1.0/SS/Record/QueryRecord; v1.0/event/subscription|query; v1.0/vehicle/anpr/records|whitelist; v1.0/access/door/control; v1.0/ptz/direction|preset. channelId = "num$K$m$0".

## 8. MTS Media Streaming (9100) y Alarmas (18800/19800)

- rtsp://<ip>:9100/...?token=<TOKEN> para video en vivo; el cliente RTSP de DPSDK alcanza MTS por OPTIONS/DESCRIBE envueltos en HTTP (EV-030); HLS por v1.1/video/live.
- Generic Alarm Ingest: 18800 (UDP/TCP), 19800 UDP de respaldo; tramas de texto con CRLF disparan pop-ups y Alarm Schemes en el Client (confirmado por el operador; el client además usa la ruta HTTP alternativa "/bayonetServer/alarmReport").

## 9. Flujo P2P Easy4IP visto desde el Client (EV-031/EV-032)

SN → CP2PServerManager::LoginP2PServer (cloud easy4ip por HTTP+SOAP sobre DDNS) → NAT traversal PTCP/Tou o relay (/relay/agent) → DHProxyClientAddPortEx registra el puerto local tunelado → DVRIP 37777 / RTSP H.265 contra el dispositivo vía 127.0.0.1:puerto. Detalles del cable: E-008 (captura dinámica).


## 10. SOAP Easy4IP Lookup (EV-034) y Endpoints Cloud (EV-035)

```xml
POST /ws/getDeviceByDevSequence HTTP/1.1
Host: www.easy4ip.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "getDeviceByDevSequence"

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:getDeviceByDevSequence xmlns:ns2="http://webservice.ddns.dahua.com/">
      <devSequence>SN123456789</devSequence>
    </ns2:getDeviceByDevSequence>
  </soap:Body>
</soap:Envelope>
```

Dominios cloud: `www.easy4ip.com`, `www.easy4ipcloud.com`, `www.dahuap2p.com`, `www.dahuap2pcloud.com`. Host interno observado: `172.23.1.120`.

## 11. Resumen de contratos REST BRMS por controlador (EV-037)

Ver tabla completa en `docs/DAHUA_COMPATIBILITY.md` §6. Cada controlador usa `RequestInfo<T>` / `ResponseInfo<T>` con `X-Subject-Token` en cabecera.

## 12. Mock BRMS Gateway — uso (EV-038)

```bash
cd poc/dss-v2-harness/brms-gateway
npm install
npm start      # escucha en :1443 (TLS disabled for lab)
npm test       # valida handshake MD5 doble + endpoints
```

## 13. P2P Probe — uso (EV-039)

```bash
cd poc/dss-v2-harness/p2p-probe
npm install
SN=<serial> USER=admin PASS=admin123 node src/index.js
```
## 14. libTouProxy Protocol (E-009, EV-040)

Cadena completa de llamadas P2P:

```
P2P_Init
  → DHProxyClientInit
    → getDomainIP (DNS resolve via getaddrinfo / DAT_18032f928)
    → new ProxyClientImpl (single instance enforced)
P2P_Connect
  → DHProxyClientAddPortEx (Src/Client/ProxyClientCWrap.cpp, libTouProxy)
    → FUN_18001e160
      → FUN_18001d1d0 (core implementation)
        → FUN_18001c8e0 (createLocalPort)
          → bind UDP 0.0.0.0:localPort
          → validate remoteIp == 127.0.0.1 or ::1
          → listen socket (FUN_18008dd80)
          → register in CPortResource map keyed by localPort
P2P_GetDeviceInfo
  → DHProxyGetDeviceInfo
    → FUN_18000dd60
      → FUN_1800108c0
        → vtable call offset 0x20 (FUN_18002e620)
```

Detalles clave:
- **getDomainIP**: parsea dominio/IP, si es dominio usa `getaddrinfo` (Windows) para resolver A/AAAA records.
- **createLocalPort**: bind UDP en `0.0.0.0:localPort`, valida `remoteIp` sea `127.0.0.1` o `::1`, `listen` socket, registra en `CPortResource` map keyed by `localPort`.
- **Relay**: `/relay/agent` + `agenthost:` para coordinación de relay PTCP/Tou.
- **jsonDevInfo**: payload JSON devuelto por `P2P_GetDeviceInfo` con info del dispositivo.
- **Single instance**: global `tagmast_pClient`, error si se intenta segunda instancia: `"SDK Client need has one instance first!"`.
- **Wire format**: PTCP/Tou propietario sobre UDP; relay opcional via `/relay/agent`.

## 15. DTO Contracts BRMS (E-009, EV-041)

Envelope estándar: `ResponseInfo<T> = { code: 1000, desc: "Success", data: T }`

### 15.1 Auth
- `TokenInfoVo`: token, userId, username, userType, topLevel
- `TokenInfoXo`: token
- `CredenceXo`: credence

### 15.2 Tree
- `DeviceOrgTreeVo`: departments[]
- `DeviceTreeVo`: devices[]
- `DeviceTreeXo`: categories, containVirtualDevice, deviceCodes, filterAreaAuthority, orgCode, resourceTypes, sourceTypes
- `DeviceTreeSearchXo`: act, cascading, id, keyWord, nodeType, page, pageSize, typeCode

### 15.3 Video (MTS)
- `RealTimeVideoXo`: channelId, dataType, enableMulticast, enableRtsps, extend, fakeSdp, forceSynPlay, keyCode, operateType, planId, streamType, trackId
- `RealTimeVideoVo`: connectType, ip, minRate, multicastIp, multicastPort, port, protocol, session, stopTime, stunEnable, stunPort, token, trackId, url, url2, vkId, vkValue

### 15.4 Records (SS)
- `RecordQueryXo`: All, Device, Timer, cardNo, channelId, deviceInfo, diskPath, endIndex, endTime, page, recordSource, recordType, session, startIndex, startTime, streamIds, streamType
- `RecordQueryVo`: pageCount, records[], session

### 15.4 Records (SS)
- `RecordQueryXo`: All, Device, Timer, cardNo, channelId, deviceInfo, diskPath, endIndex, endTime, page, recordSource, recordType, session, startIndex, startTime, streamIds, streamType
- `RecordQueryVo`: pageCount, records[], session

### 15.5 Vehicle/ANPR
- `VehicleVo`: id, personId, plateNo, carType, carNumColor, carBrand, vehicleColor, orgCode, orgName, companyName, entranceGroups, surveyGroups, carStatus, carMark, carCode, bindingDeviceCode
- `CarQueryParamXo`: companyName, containChild, containVisitorVehicle, entranceEffectiveEndTime, entranceEffectiveStartTime, entranceEffectiveStatus, entranceFailureEndTime, entranceFailureStartTime, entranceGroupId, entranceGroupIds, filterAuthorityOrg, groupType, keyword, orgCode, orgName, page, pageSize, parkingLotId, personId, personName, plateNo, plateNoMatchMode, surveyEffectiveEndTime, surveyEffectiveStartTime, surveyEffectiveStatus, surveyFailureEndTime, surveyFailureStartTime, surveyGroupId, vehicleBrand, vehicleColor

### 15.6 PTZ
- `PtzMoveAbsolutelyXo`: ptzPan, ptzTilt, ptzZoom
- `PtzPresetPointVo`: channelId, presetPoints[]

### 15.7 Alarms
- `AlarmVo`: alarmCode, alarmType, alarmGrade, alarmDate, channelId, channelName, deviceCode, deviceName, alarmStat, handleStat, handleType, handleUserName, id, linkRecordChannels
- `PageAlarmRecordXo`: TRUE, currentPage, page, pageSize, splitId, splitTime
- `AlarmVo` (detailed): alarmCode, alarmType, alarmGrade, alarmDate, channelId, channelName, deviceCode, deviceName, alarmStat, handleStat, handleType, handleUserName, id, linkRecordChannels, alarmPic, alarmPicSize, gpsX, gpsY, handleDate, handleMessage, handleUserGroupName, handleUserGroupUsers, mailReceivers, memo, eventRemark, extData

## 16. UDP Alarm Ingest (E-009, EV-047)

Puerto 18800 UDP (primario), 19800 UDP (backup). Tramas texto CRLF:
```
ANPR_EBA|CAM001|plate=ABC1234\r\n
ALARM|deviceCode=CAM001|type=Intrusion|channel=1\r\n
```

Gateway recibe en `dgram` socket `0.0.0.0:18800` (backup 19800), parsea, loggea, reinyecta en canal de eventos interno.
## 17. ProxyClientImpl Vtable & PTCP State Machine (E-010, EV-049/050)

### 17.1 Vtable CProxyClientImpl (libTouProxy)
```cpp
class CProxyClientImpl : public INotify {
  // vtable entries (offset from vtable base):
  // 0x00: destructor
  // 0x08: getState() -> uint32_t
  // 0x10: createLocalPort(bindCtx, localPort, remoteIp, ...) -> int
  // 0x18: deletePort(port) -> int
  // 0x20: getDeviceInfo(callback) -> void (async, jsonDevInfo via callback)
  // ...
};
```

Offsets confirmados (x64, 8 bytes/entry):
- `vtable[0x00]`: destructor
- `vtable[0x08]`: `getState` (0x1800107c0)
- `vtable[0x10]`: `createLocalPort` (0x18001c8e0)
- `vtable[0x18]`: `deletePort` (0x18001d150)
- `vtable[0x20]`: `getDeviceInfo` → callback con `jsonDevInfo`

### 17.2 PTCP/Tou State Machine
```mermaid
stateDiagram-v2
  [*] --> Init: DHProxyClientInit
  Init --> DNS_Resolve: getDomainIP(agenthost)
  DNS_Resolve --> Create_Instance: CProxyClientImpl singleton
  Create_Instance --> Connect: P2P_Connect/AddPort
  Connect --> Bind_Local: createLocalPort(0.0.0.0:port)
  Bind_Local --> Validate_IP: remoteIp == 127.0.0.1 or ::1
  Validate_IP --> Listen_UDP: socket listen
  Listen_UDP --> Register_Port: CPortResource[key=localPort]
  Register_Port --> Relay_Handshake: /relay/agent + agenthost
  Relay_Handshake --> PTCP_Tunnel: PTCP over UDP
  PTCP_Tunnel --> Forward_Data: 127.0.0.1:localPort <-> Device
  PTCP_Tunnel --> Get_Device_Info: vtable[0x20] -> jsonDevInfo
```

### 17.3 Packet Format (PTCP/Tou over UDP)
- Header: `uint32_t cmd; uint32_t seq; uint32_t payload_len; uint32_t flags;`
- Commands: `0x01=HELLO`, `0x02=CHALLENGE`, `0x03=RESPONSE`, `0x04=DATA`, `0x05=KEEPALIVE`, `0x06=BYE`
- Payload: JSON (`jsonDevInfo`) o datos binarios (video/audio)
- Keepalive cada 30s (`Dahua::Tou::CProxyChannel::sendKeepAlive`)

## 18. p2p-probe Real Implementation (E-010, EV-051)

```bash
cd poc/dss-v2-harness/p2p-probe
npm install
SN=<serial> USER=admin PASS=admin123 node src/index.js
```

Flujo implementado:
1. `soapGetDeviceByDevSequence(SN)` → `www.easy4ip.com` (SOAP EV-034)
2. `touHandshake(relayHost, relayPort, localPort)`:
   - DNS resolve `agenthost:`
   - PTCP handshake: `HELLO` → `CHALLENGE` → `RESPONSE` (SN + credenciales)
   - `createLocalPort` bind `127.0.0.1:localPort`
   - Tunnel established → bidirectional `dgram` forward
3. Loop: `127.0.0.1:localPort` ↔ PTCP tunnel ↔ Device

Tests: `npm test` (handshake → tunnel → loopback echo).

## 19. MTS/RTSP + WebSocket Events (E-010, EV-052)

### 19.1 WebSocket Event Stream
```javascript
// Endpoint: ws://host:11443/brms/api/v1.0/event/ws
// Subscription: POST /brms/api/v1.0/event/subscription
// Payload: { eventTypes: ["ANPR", "Intrusion", ...] }
// Server pushes: { type: "ANPR_EBA", data: "...", timestamp: "..." }
```

### 19.2 Mock RTSP 9100
```bash
# Validate token from StartVideo
rtsp://127.0.0.1:9100/1000171$1$0$0?token=MOCK-xxx
```
Handles: `OPTIONS`, `DESCRIBE` (SDP H.265), `SETUP`, `PLAY`, `TEARDOWN`.

## 20. E-011: E2E Integration Lab Deployment (EV-054/055)

### 20.1 Deployment Topology
- **Ubuntu Lab Server**: 10.10.20.120 (Ubuntu 26.04, Node 20.20.2, Docker 29.9.2)
- **BRMS Gateway Container**: `dss-v2-harness-brms-gateway:latest`
- **Ports Exposed**:
  - 1443/TCP: HTTPS BRMS API (self-signed cert CN=10.10.20.120)
  - 11443/TCP: HTTP BRMS API (internal)
  - 9100/TCP: RTSP Mock Server (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN)
  - 18800/UDP: Alarm Ingest Primary
  - 19800/UDP: Alarm Ingest Backup
  - WebSocket: `wss://10.10.20.120:1443/brms/api/v1.0/event/ws`

### 20.2 Environment Variables
```bash
PORT=11443
HTTPS=true
HTTPS_PORT=1443
SSL_KEY=/certs/key.pem
SSL_CERT=/certs/cert.pem
REALM=DSS-V2-LAB
PUBLIC_HOST=10.10.20.120
RTSP_PORT=9100
EASY4IP_HOST=www.easy4ip.com
```

### 20.3 E2E Test Suite Results (All PASS)
| Test | Description | Validation |
|------|-------------|------------|
| E2E-1 | Auth handshake (401→200) + keepalive/current | TokenInfoVo exact match |
| E2E-2 | Tree/orgs + devices + channels | DeviceOrgTreeVo, DeviceTreeVo, channelId `num$K$m$0` |
| E2E-3 | MTS StartVideo → RTSP URL + **TCP probe OPTIONS/DESCRIBE** | `RTSP/1.0 200 OK` + SDP H.265 |
| E2E-4 | UDP 18800 → WebSocket push | Event `type:ALARM` received |
| E2E-5 | P2P probe manual profile | `/p2p/status` endpoint |

### 20.4 DSS Client Windows Connection Guide
1. Install `DSS Client V8.008` (M-001/M-002)
2. Add `cert.pem` (CN=10.10.20.120) to Trusted Root CA (`certmgr.msc`)
3. Login: Server IP `10.10.20.120`, Port `1443`, User `admin`, Password `admin123`
4. Client performs MD5 handshake (WINPC_V2) → receives token
5. Live View: `MTS/Video/StartVideo` → RTSP `rtsp://10.10.20.120:9100/...?token=...` → OPTIONS/DESCRIBE → H.265 playback
6. Alarms: UDP 18800 → WebSocket push → Client popup

### 20.5 Verification Commands
```bash
# Unit tests
cd poc/dss-v2-harness/brms-gateway && npm test

# E2E tests (from Windows)
node --test poc/dss-v2-harness/e2e-lan-test.mjs

# Check server health
curl -k https://10.10.20.120:1443/health
```

## 21. E-012: Real H.265 Video Engine + Bootstrap APIs + P2P Bridge (EV-056..059)

### 21.1 Deployment Updates
- **MediaMTX Service**: `bluenviron/mediamtx:latest` (v1.21.3) en docker-compose
  - Puertos: 9100:8554 (RTSP), 1935 (RTMP), 8888 (HLS), 8889 (WebRTC)
  - Paths: `test`, `cam1` con `source: publisher` (requiere publisher externo)
  - RTSP Signaling validado: OPTIONS 200 OK, DESCRIBE 404 (sin publisher)

### 21.2 Bootstrap APIs (Post-Login Client Initialization)
| Endpoint | Method | Description | DTO Response |
|----------|--------|-------------|--------------|
| `/brms/api/v1.0/accounts/menus` | GET | Menú principal v1.0 | `MenuListVo` |
| `/brms/api/v1.1/accounts/menus` | GET | Menú principal v1.1 | `MenuListVo` |
| `/brms/api/v1.0/accounts/userinfo` | GET | Info usuario actual | `UserInfoVo` |
| `/brms/api/v1.0/system/time` | GET | Tiempo servidor NTP | `ServerTimeVo` |
| `/brms/api/v1.0/version` | GET | Versión servidor | `VersionVo` |
| `/brms/api/v1.0/system/version` | GET | Versión servidor (alt) | `VersionVo` |
| `/brms/api/v1.0/capability` | GET | Capacidades servidor | `CapabilityVo` |
| `/brms/api/v1.0/license` | GET | Info licencia | `LicenseInfoVo` |

**Inspector Middleware**: Catch-all hook que loggea método, URL, headers, body, status, duración.

### 21.3 P2P Device Register Bridge
| Endpoint | Method | Body | Response |
|----------|--------|------|----------|
| `/brms/api/v1.0/device/p2p-register` | POST | `{ sn, user, password, name, channels }` | `{ deviceId, channelIds, p2pStatus }` |
| `/brms/api/v1.0/device/p2p-unregister` | POST | `{ sn }` | `{ success: true }` |
| `/brms/api/v1.0/device/p2p-list` | POST | - | `{ devices: [...] }` |

**Flujo**: Registra SN → genera `deviceId` (`P2P-xxx`) + `channelIds` (`P2P-xxx$1$0$0`) → prepara túnel PTCP/Tou.

### 21.4 ARS (Auto Register Service) - Device Auto-Registration
Tradicional registro automático de dispositivos Dahua (device → server). **Funciona SIN P2P** (confirmado por Don Omar).

| Endpoint | Method | Auth | Body | Response |
|----------|--------|------|------|----------|
| `/brms/api/v1.0/ars/register` | POST | No | `{ deviceId, deviceName, ip, port, username, password, deviceType, channelNum, ... }` | `{ success, deviceId, message }` |
| `/brms/api/v1.0/ars/keepalive` | POST | No | `{ deviceId }` | `{ success, deviceId }` |
| `/brms/api/v1.0/ars/unregister` | POST | No | `{ deviceId }` | `{ success, message }` |
| `/brms/api/v1.0/ars/list` | POST | Sí | - | `{ devices: [...] }` |
| `/brms/api/v1.0/ars/device-info` | POST | Sí | `{ deviceId }` | `DeviceTreeVo` compatible |

**Flujo**: Dispositivo envía registro con su info → Server añade a árbol de dispositivos → Dispositivo hace keepalive periódico.
**Clave**: Requiere IP, puerto y ID del dispositivo (como indicó Don Omar). **P2P se puede desactivar** y funciona igual.

### 21.5 RTSP/H.265 con MediaMTX
- **MediaMTX** en docker-compose (puerto 9100 → 8554 interno)
- Paths `test`, `cam1` con `source: publisher`
- **Limitación**: Requiere publisher FFmpeg externo para H.265 real
- **Validación actual**: OPTIONS 200 OK, DESCRIBE 404 (sin publisher) → protocolo RTSP funcional

### 21.5 E2E Test Suite Results (All PASS)
| Test | Validation |
|------|------------|
| E2E-1 | Auth handshake + keepalive/current |
| E2E-2 | Tree/DTOs exactos |
| E2E-3 | RTSP OPTIONS 200 OK + DESCRIBE (200/404) |
| E2E-4 | UDP 18800 → WebSocket push `type:ALARM` |
| E2E-5 | P2P probe manual + register endpoints |

### 21.6 Verification Commands
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

# Test ARS TCP register (device auto-registration, no auth)
curl -k -X POST https://10.10.20.120:1443/brms/api/v1.0/ars/register \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"CAM-001","deviceName":"Test Cam","ip":"192.168.1.100","port":37777}'
```

## 22. E-013: ARS TCP Real + H.265 Real + Contenedores Sanos (EV-061..063)

### 22.1 ARS TCP Binary Protocol (DVRIP/DHIP) - Puerto 9500
Implementación real del protocolo binario DVRIP/DHIP usado por `VMS_ARCMS.exe` (servicio ARS del servidor Dahua).

| Aspecto | Detalle |
|---------|---------|
| Puerto | TCP 9500 (configurable `ARS_PORT`) |
| Protocolo | DVRIP/DHIP binario - cabecera 32 bytes |
| Magic | `0x44484950` ("DHIP" little-endian) |
| Cabecera | 32 bytes: magic, command, sequence, payload_len, session_id, device_type, flags, reserved |
| Comandos | REGISTER (0x0001), HEARTBEAT (0x0002), LOGOUT (0x0005) |
| Respuestas | REGISTER_ACK (0x8001), HEARTBEAT_ACK (0x8002), LOGOUT_ACK (0x8005) |

**Payload REGISTER** (tras cabecera 32 bytes):
- Device ID (SN, null-terminated, max 64 bytes)
- Device Name (null-terminated, max 64 bytes)
- Device Type (uint16), Channel Count (uint16)
- IP (string null-terminated), Port (uint16)
- Username/Password (null-terminated)
- MAC (6 bytes), Firmware (null-terminated)

**Flujo NVR**: TCP connect → REGISTER (0x0001) → REGISTER_ACK (0x8001) → HEARTBEAT periódico (0x0002) → LOGOUT (0x0005)

### 22.2 MediaMTX H.265 Real Publisher (FFmpeg + libx265)
- **Imagen custom**: Multi-stage Docker (alpine + FFmpeg 6.1 + libx265) + MediaMTX v1.11.3
- **Puertos**: 9100:8554 (RTSP), 1935 (RTMP), 8888 (HLS), 8889 (WebRTC)
- **Paths**: `test`, `cam1` con `source: publisher` + `runOnInit` FFmpeg
- **FFmpeg command**: `ffmpeg -re -f lavfi -i "testsrc2=size=1920x1080:rate=25" -c:v libx265 -preset ultrafast -tune zerolatency -x265-params "keyint=25:min-keyint=25:no-scenecut=1" -pix_fmt yuv420p -f rtsp rtsp://localhost:8554/test`

**SDP Real H.265 en DESCRIBE**:
```
v=0
o=- 0 0 IN IP4 127.0.0.1
s=No Name
c=IN IP4 0.0.0.0
t=0 0
m=video 0 RTP/AVP 96
a=control:trackID=0
a=rtpmap:96 H265/90000
a=fmtp:96 sprop-pps=RAHAcYMS; sprop-sps=QgEBAWAAAAMAkAAAAwAAAwB4oAPAgBEHy5bpKTC8BaAgAAADACAAAAMDIQ==; sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwB4ugJA
```

### 22.3 E2E Test Suite Results (All PASS)
| Test | Validation |
|------|------------|
| E2E-1 | Auth handshake + keepalive/current |
| E2E-2 | Tree/DTOs exactos |
| E2E-3 | RTSP OPTIONS 200 OK + DESCRIBE 200 OK + SDP H.265 real (VPS/SPS/PPS) |
| E2E-4 | UDP 18800 → WebSocket push `type:ALARM` |
| E2E-5 | P2P probe manual + ARS REST + ARS TCP |

### 22.4 ARS TCP Binary Test (DVRIP)
```bash
# Conectar a 10.10.20.120:9500
# Enviar paquete DVRIP REGISTER (cabecera 32B + payload)
# Recibir REGISTER_ACK (0x8001)
# Enviar HEARTBEAT (0x0002) → HEARTBEAT_ACK (0x8002)
# Enviar LOGOUT (0x0005) → LOGOUT_ACK (0x8005)
```

### 22.5 Verification Commands
```bash
# Unit tests
cd poc/dss-v2-harness/brms-gateway && npm test

# E2E tests (from Windows)
node --test poc/dss-v2-harness/e2e-lan-test.mjs

# Health check
curl -k https://10.10.20.120:1443/health

# Test ARS REST register
curl -k -X POST https://10.10.20.120:1443/brms/api/v1.0/ars/register \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"CAM-001","deviceName":"Test Cam","ip":"192.168.1.100","port":37777}'

# Test ARS TCP binary (requires raw TCP client)
# See poc/dss-v2-harness/test-ars-tcp.mjs for reference implementation
```

## 23. Add Device catalog contracts (E-024)

The "Add Device" dialog of DSS Client 8.006 renders its combo boxes from server
catalogs. These are the exact contracts recovered from the real client.

### 23.1 Endpoints

| Method | Path | Client consumer |
| --- | --- | --- |
| GET/POST | /brms/api/v1.1/dictionary/list?types=3,107 | web addDevice view + DPSDK GetDictionaryList |
| GET/POST | /brms/api/v1.1/definition/device-type/list | web addDevice view + DPSDK GetDeviceTypes |
| GET | /brms/api/v1.1/definition/channel-capability/list | web addDevice view + DPSDK GetChannelCapabilities |
| GET | /brms/api/v1.1/server/available/list | web addDevice view + DPSDK GetAvailableServers |
| GET | /brms/api/v1.1/config/snmp/protocol/manufacturer/list | web addDevice view + DPSDK GetSNMPManuList |
| POST | /admin/API/BRM/BRMS/{Dictionary,Definition,Config}/... | BRMS RPC transport (same payloads) |

### 23.2 Response shapes

```jsonc
// GET /brms/api/v1.1/dictionary/list?types=3,107
{
  "code": 1000, "desc": "Success",
  "data": {
    "results": [
      { "type": "3",   "items": [ { "code": "1", "name": "Dahua", "param1": "246,1,2", "param2": "246" } ] },
      { "type": "107", "items": [ { "code": "246", "name": "Dahua", "param1": "", "param2": "" } ] }
    ]
  }
}
```
- type "3" = access protocols, type "107" = manufacturers.
- param1 = manufacturer codes allowed when deviceCategory == 53 (AUDIO_DEVICE);
  param2 = manufacturer codes allowed for every other category (CSV, split with ",").
- The client filters the manufacturer combo with that CSV, so both sides must
  agree on the codes (SIA_CID/SIA_DCS are hardcoded to manufacturer "246").

```jsonc
// GET /brms/api/v1.1/definition/device-type/list
{
  "code": 1000, "desc": "Success",
  "data": {
    "results": [
      {
        "deviceCategory": "1",
        "deviceCategoryName": "Encoder",   // drives the Device Category combo
        "deviceTypeName": "Encoder",       // drives the store caption
        "deviceTypes": [ { "deviceType": "2", "deviceTypeName": "IPC" } ]
      }
    ]
  }
}
```
- 26 categories are published (DEVICE_CATEGORY_TYPE of the client).
- Capability list: data.results = [{code,name,group}] (group = array or null).
- Server list: data.results = [{serverCode:"video#local",serverName:"Current Site"}].
- SNMP list: data.results = [{manufacturerCode,manufacturerName}].

### 23.3 Enums reproduced (from js/device-JBrSmGvP.js of the real server)

| Enum | Values |
| --- | --- |
| DEVICE_CATEGORY_TYPE | ENCODER=1, DECODER_DEVICE=2, ALARM_CONTROLLER=3, SCREEN=4, ANPR=5, MATRIX_DEVICE=6, SECURITY_DEVICE=7, ACCESS_CONTROL=8, DYN_ENV=9, VOICE=10, TRANSCODER=11, UVSS=15, DIAPLAY_DEVICE=16, HOST_TRIAL_DEVICE=20, VIDEO_INTERCOM=21, RECORD_SERVER=23, VISITOR_MACHINE=30, EMERGENCY=34, UAV_DEVICE=38, POS_DEVICE=40, RADAR=43, VIDEO_WALL_CONTROL=45, LIFT_CONTROL=50, NETWORK_BASE=51, AUDIO_DEVICE=53, GATE_DEVICE=70 |
| ENCODER_TYPE | DVR=1, IPC=2, NVS=3, MDVR=5, NVR=6, MPT=9, EVS=10, SMART_IPC=12, SMART_NVR=14, VTT=21, THERMAL_CAMERA=26, WATCHER=34, MCS=35, IVSS=43, IVS=77, EEC=97 |
| DEV_PROTOCOL_TYPE | DAHUA=1, HIK=2, RTSP=68, SNMP=98, ONVIF=99, SIA_CID=100, SIA_DCS=110, DDIP=120, JIUZHOU=185 |
| DEV_ADD_TYPE | IP_ADDRESS=1, IP_SECTION=2, DOMAIN=3, AUTO_REGISTER=4, P2P=5, RTSP_ADDRESS=6 |
| CAPABILITY_TYPE | 1..29 (INTELLIGENT_ALARM=1 ... AR=29) |

### 23.4 Verification commands

```bash
curl -sk "https://10.10.20.120:1443/brms/api/v1.1/dictionary/list?types=3,107"
curl -sk "https://10.10.20.120:1443/brms/api/v1.1/definition/device-type/list"
curl -sk "https://10.10.20.120:1443/brms/api/v1.1/definition/channel-capability/list"
curl -sk "https://10.10.20.120:1443/brms/api/v1.1/server/available/list"
curl -sk "https://10.10.20.120:1443/brms/api/v1.1/config/snmp/protocol/manufacturer/list"
```

## 24. E-025: QT/CEF bridge, device add/discovery and P2P (verified live 2026-11-01)

### 24.1 Web <-> native bridge (recovered from CefRender.exe / PluginFactory.dll / real bundles)

| Direction | API | Notes |
|---|---|---|
| web -> native | `window.ClientObject.MainCall(method, param, callbackName)` | injected by CefRender.exe; `param` is a JSON **string** ('' when none) |
| native -> web | `window.webAPICaller(callbackName or action, jsonPayloadString)` | literal JS in the DLLs: `window.webAPICaller('%1','%2')` |
| token | `MainCall('getToken','',cbId)` -> `webAPICaller(cbId,{token,resourceToken})` | the production launcher ALWAYS does this when the URL carries no token |
| module hand-off | `MainCall('switchMenuTab', JSON.stringify({menuCode,pluginName,menuName,externData}), cbId)` | parsed by CWebBusinessControl::OnMainCall; native then emits `webAPICaller('changeRoute',{"router":...})` |
| other native methods | `openVedio`, `openRecord`, `closeWebPage`, `addSite`, `delSite`, `updateSiteToken`, `clientCallback`, `getLocalConfig`, `getWebsocketPort`, `invokeClientNotify` | same dispatcher |

### 24.2 Device add / discovery flow (client order, from useDeviceApi)

```
POST /brms/api/v1.1/device/discover/cost-time   {deviceIp,devicePort,protocolType,deviceCategory,deviceType,...}
POST /brms/api/v1.1/device/discover/summary     {same body}
POST /brms/api/v1.1/device                      {+ loginPass (md5), serverCode:"video#local", encoderChannelCount:1}
GET  /brms/api/v1.1/device/page
GET  /brms/api/v1.1/discover/device/page
```

Response shapes (`data`): `device` (DeviceVo) + `results[]` + `channels[]` with `channelId = <deviceCode>$<no>$0$0`;
`cost-time` -> `{costTime,costTimeMs,totalTime,deviceCount,online,results[]}`; `summary` -> identity fields + `online/status/deviceStatus/errorCode/errorMsg`.

### 24.3 Real ONVIF probe (GetDeviceInformation)

```http
POST http://<ip>:<port>/onvif/device_service HTTP/1.1
Content-Type: application/soap+xml; charset=utf-8

<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <env:Body><tds:GetDeviceInformation/></env:Body>
</env:Envelope>
```

Live result for the lab camera 192.168.0.238:8021: Manufacturer `AI Sentinel`, Model `EBA1_LECTOR_FHD_H265`, FirmwareVersion `2.1.0-H265`, SerialNumber `SENTINEL_8021`, HardwareId `1.0` (3-4 ms).

### 24.4 Auto register (DVRIP/DHIP) TCP 9500

Frame = 32-byte LE header (magic `DHIP` = 0x44484950, cmd, seq, payloadLen, ...) + payload:
`deviceId\0 deviceName\0 u16 deviceType u16 channelCount ip\0 u16 port user\0 pass\0 mac[6] fw\0`.

Server answers `REGISTER_ACK` (0x8001) echoing the sequence; the device then appears in `/brms/api/v1.0/ars/list`, `/brms/api/v1.0/tree/devices`, `/brms/api/v1.1/device/page` and the category statistics.

### 24.5 P2P / Easy4IP (endpoints from DPSDK.dll; reachability measured from 10.10.20.120)

```
POST http://www.easy4ip.com/webservice/GetDeviceInterface?wsdl
Content-Type: text/xml; charset=UTF-8

<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body>
<ns2:getDeviceByDevSequence xmlns:ns2='http://webservice.ddns.dahua.com/'><devSequence>SERIAL</devSequence></ns2:getDeviceByDevSequence>
</soap:Body></soap:Envelope>
```

| Host | DNS | TCP 80 | TCP 443 |
|---|---|---|---|
| www.easy4ip.com | 47.253.80.249 | OPEN | OPEN |
| www.easy4ipcloud.com | 152.32.199.10 | blocked | blocked |
| www.dahuap2p.com | 47.98.190.1 | OPEN | OPEN |
| www.dahuap2pcloud.com | 47.98.234.36 | blocked | blocked |
| p2p.myeasyip.com | 35.169.170.49 | OPEN | OPEN |

Serial answers: HTTP 400 for a malformed serial; HTTP 200 with an **empty `<return></return>`** for the lab camera serial -> that serial is not published on the Dahua cloud, so P2P cannot resolve it until the camera is registered on Easy4IP and the server shares that P2P account.

### 24.6 Verification commands

```bash
# launcher bridge contract
curl -sk https://10.10.20.120:1443/web/client-module/ | grep -E "ClientObject.MainCall|getToken|switchMenuTab"
# device add flow
BODY='{"deviceIp":"192.168.0.238","devicePort":8021,"protocolType":99,"deviceCategory":1,"deviceType":6,"deviceName":"EBA1","serverCode":"video#local","encoderChannelCount":1}'
curl -sk -X POST https://10.10.20.120:1443/brms/api/v1.1/device/discover/summary -H 'Content-Type: application/json' -d "$BODY"
curl -sk -X POST https://10.10.20.120:1443/brms/api/v1.1/device -H 'Content-Type: application/json' -d "$BODY"
# catalogs / p2p
curl -sk https://10.10.20.120:1443/brms/api/v1.1/system/network/list
curl -sk https://10.10.20.120:1443/brms/api/v1.1/device/statistics/count-by-device-category/list
curl -sk -X POST https://10.10.20.120:1443/brms/api/v1.0/ars/list
```


## E-026: ONVIF -> MediaMTX video bridge (verified live 2026-11-02)

Camera: AI Sentinel EBA1_LECTOR_FHD_H265, S/N SENTINEL_8021
- ONVIF device service: http://192.168.0.238:8021/onvif/device_service
- RTSP stream: rtsp://192.168.0.238:8554/EBA1_LECTOR (port 554 CLOSED)
- MediaMTX: pulls :8554/EBA1_LECTOR, serves :9100/cam1 (H265 25fps)

MTS/Video/StartVideo returns:
  url: rtsp://<PUBLIC_HOST>:9100/cam1?token=<token>
  protocol: RTSP, port: 9100
Plus all 18 RealTimeVideoVo fields (vkId, vkValue, connectType, session, ...).

POST /device returns rtspUrl/url/streamUrl/playUrl = rtsp://<PUBLIC_HOST>:9100/cam1.

Config (env, no hardcodes):
  MEDIAMTX_API_URL=http://mediamtx:9997
  MEDIAMTX_CAMERA_PATH=cam1
  RTSP_PORT=9100
  PUBLIC_HOST=10.10.20.120

See .env.example for full template.

Verification:
  curl -sk -X POST https://10.10.20.120:1443/brms/api/v1.0/MTS/Video/StartVideo \
    -H 'X-Subject-Token: <token>' -d '{"channelId":"1000171","streamType":1}'
  timeout 8 bash -c 'exec 3<>/dev/tcp/localhost/9100; printf "OPTIONS rtsp://localhost:9100/cam1 RTSP/1.0\r\nCSeq: 1\r\n\r\n" >&3; read -t 5 line <&3; echo ""'

## E-027/E-028 additions (verified live 2026-11-02)

### Device add poll contract (native DPSDK, UA "lightMyRequest")
- POST /brms/api/v1.1/device/discover/cost-time | discover/summary -> identity probe.
- POST /brms/api/v1.1/device -> add (idempotent per ip:port; returns device + results[]).
- GET /brms/api/v1.1/discover/device/page?initialized=&orderType=2&... -> the add
  dialog polls this until the added device appears with initialized == "1"
  (INITIALIZED; enum INITIALIZED:"1", MODIFY_IP:"2", ADAPTED:"3" from
  real-index-BIzql2yJ.js). Poll deadline 30e4 ms; empty list = DPSDK
  "Operation timed out". Our payload merges the device registry + discovered
  scans; registered devices always report initialized:"1".
- config/interface/common/timeout: data.timeout in SECONDS (client multiplies x1000).

### Storage Plan (menuCode 003005)
- POST /brms/api/v1.{0,1}/storage/plan/channel/plan-config-status/fetch/batch/list
  body {channels:[id]} -> data.results[{channelId,configured,status,configStatus}].
- GET|POST|PUT /brms/api/v1.{0,1}/storage/plan/channel/:channelCode/new-device-record-plan
  -> 24x7 template contract {code,name,enable,planPeriod[7]{weekday,enable,
  timeSlices[{timeSliceStart,timeSliceEnd}]},planWeekDays,recordType,streamType,scheduleType}.
- SSRecordController (EV-037): POST /brms/api/v1.0/SS/Record/{QueryRecord,StartRecord,
  StopRecord,LockRecord,UnlockRecord,DeleteRecord}.

### /web/client-module/ (CefRender.exe entry)
- Always GET /web/client-module/?userId=..&locale=..&skin=..&logLevel=..; module
  routing is in-page (hash router of the REAL production bundle mirrored by the
  gateway). Inventeds pages are prohibited; bundle missing -> 503 neutral.

### E-028 additions (verified live 2026-11-02)
- /web/client-module/ serves the mirrored production bundle: hashed chunks
  immutable (Cache-Control: public, max-age=604800, immutable), index.html
  no-store, extensionless paths fall back to the real index.html (hash router),
  missing bundle -> 503 neutral page. Every referenced chunk MUST resolve
  (986/986 verified) or the real SPA never finishes loading.
- GET /brms/api/v1.1/discover/device/page: ONE row per ip:port; a registered
  device is returned with initialized:"1" (INITIALIZED) even when it was
  discovered by a scan first - duplicate rows with initialized:"" made the
  native add dialog time out.
- Transport: keepAliveTimeout 65s on 1443/9443/11443 (Node's 5s default closed
  the socket the native client keeps across the add flow -> ECONNRESET ->
  "Operation timed out").

## 25. E-029: new-generation SPA (client module 8.006) contracts (EV-080, verified live)

The six views formerly answered by the generic fallback (empty {list,total} -> "Abnormally returned the service or device data"; code 111553). Shapes read directly from the mirrored bundle consumers at web-module/js.

### 25.1 Device tree (Device Config view)

```jsonc
POST /brms/api/v1.1/tree/grade-device-tree        // body: treeType "2", domain "0", conditions[...], orgCode "001"
POST /brms/api/v1.1/tree/grade-device-tree/search/list
{
  "code": 1000,
  "data": {
    "organizations": [ { "orgCode": "001", "orgName": "Current Site", "pId": "0", "deviceCount": 1, "onlineDeviceCount": 1 } ],
    "devices": [
      { "id": "D0238...   ", "deviceCode": "...", "deviceName": "...", "orgCode": "001",
        "deviceIp": "...", "devicePort": "...", "deviceType": "2", "deviceCategory": "1",
        "status": "1", "online": 1,
        "channels": [ { "channelId": "...", "channelName": "...", "channelNo": 1,
                        "deviceCode": "...", "deviceName": "...", "capability": "..." } ] }
    ],
    "channels": [ /* flat channel rows (search view) */ ],
    "organizationExceeded": "0", "deviceExceeded": "0", "channelExceeded": "0"
  }
}
```
- Tree unwrap: `bt(e,o) = e?.data || o`; node labels/ids come from
  optimizeOrganization/optimizeDevice/optimizeChannel (type 1/2/3).
- Root id is client-local "001"; deeper nodes lazy-loop query(orgCode).
- exceeded flags: "1" OVER / "0" UNDER (BATCH.EXCEEDED_FLAG_ENUM).

### 25.2 Storage plan list pages

```jsonc
GET /brms/api/v1.1/storage/plan/channel/record-plan/page?page=1&pageSize=20&orgCode=&keyword=&position=1
GET /brms/api/v1.1/storage/plan/motion-detection-record-plan/page?page=1&pageSize=20&orgCode=&keyword=   // NO /channel/
{
  "code": 1000,
  "data": { "totalCount": 1, "pageData": [ { "id": "...", "channelId": "...", "channelName": "...",
             "deviceName": "...", "orgName": "...", "positionName": "Central Storage",
             "timeTemplateName": "24x7 schedule", "streamTypeName": "Main Stream",
             "remark": "", "status": "1" } ] }
}
```
Rows list only CONFIGURED plans (channel/plan-config-status fetch/new-device-record-plan writes them).

### 25.3 Bootstrap counters

```jsonc
GET /brms/api/v1.1/account/user/level        -> { "code": 1000, "data": { "level": "1" } }
GET /brms/api/v1.1/config/timezone/info?area=America/Santiago
   -> { "code": 1000, "data": { "dstType": "1", "enableDst": "1", "timezoneOffset": "-240",
        "dstBeginDate": "9/1/0", "dstBeginTime": "00:00:00",
        "dstEndDate": "4/1/0", "dstEndTime": "00:00:00" } }
```
dstBeginDate/dstEndDate are month/week/day; the client .split("/") them, so a
missing key breaks the bootstrap. User level lands in localStorage.roleLevel.

### 25.4 Add-Discover page + join batch

- GET /brms/api/v1.1/discover/device/page rows must include pageData + per-row
  id, initStatus ("0"/"1") and protocol; batch add sends those ids:
- POST /brms/api/v1.1/discover/device/join/batch  { ids: ["D0238...", "DSC-ip:port"] }
  -> { "code": 1000, "data": { "results": [ { "result": "0", "deviceCode": "...",
       "deviceName": "...", "deviceIp": "...", "errorMsg": "" } ], "total": 1 } }
- result "0" (strict string) = success; 110113 = DEVICE_PROTOCOL_NOT_SUPPORT;
  110262 = DEVICE_NOT_SUPPORT_IN_AREA. A discovered id creates the device.

Timezone note: DSS "m/w/d" maps Chile DST from first Sunday of September to
first Sunday of April, both 24:00 -> our "9/1/0".."4/1/0" 00:00:00 values.

## 26. E-030: native app device tree + join/batch results semantics (EV-081)

- The DSS Client desktop app draws its device tree from
  /admin/API/tree/deviceOrg + /admin/API/tree/devices (admin API base, loaded at
  login; NOT grade-device-tree). Contracts:
    GET  tree/deviceOrg?channelTypes=<c>&sort=&orgCode=
         -> {orgList:[{orgCode:"001",orgName,deviceNum,childCount,status:1}],
             deviceList:[{deviceCode,deviceName,deviceType,type,ip,port,
             manufacturer,model,protocol,status,online,orgCode}],
             channelList:[{channelId:"code$1$0$0",channelName,deviceCode,
             channelType:1,channelNo:1,orgCode,status,online,videoEncode,...}]}
    POST tree/devices {categories,orgCode,deviceCodes,containVirtualDevice}
         -> same deviceList/channelList + {orgCode,containVirtualDevice,total}
  All rows come from the live device registry (never the E-019 CAM001 mock).
- join/batch results semantics (proven from index-DsQ1Ve9V.js): results must
  carry ONLY failure rows (result != "0"); full success = results: [].
  The single-add dialog sets its failure flag on every row it sees, so a
  success row inside results is mislabeled "Failed to add device".
