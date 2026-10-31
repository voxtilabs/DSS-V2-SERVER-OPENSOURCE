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
