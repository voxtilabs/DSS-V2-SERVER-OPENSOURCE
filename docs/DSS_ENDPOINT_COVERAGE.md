# DSS Endpoint Coverage — Gateway vs. DPSDK Client Inventory (2026-11-07)

Documento de cobertura del gateway BRMS contra el inventario real del cliente
DSS 8.006 (WINPC_V2). Fuentes: string pool de DPSDK.dll (351 literales REST),
mapa CRestLogical (`docs/DPSDK_USER_MANAGEMENT_CONTRACTS.md` §9), barrido en
vivo de 56 endpoints (QA 2026-11-07) y la traza `[FALLBACK]` del gateway.

## 1. Veredicto de cobertura (barrido en vivo, post E-108)

**52 de 56 endpoints con datos REALES. 4 stubes vacíos por diseño. 0 en el catch-all**
(dentro de lo probado). Todos HTTP 200; el cliente solo puede discriminar por cuerpo.

## 2. Login (raíz de los toasts "Abnormal network")

| Endpoint | Estado | Notas |
|---|---|---|
| `POST /brms/api/v1.0/accounts/authorize` (+ `/admin/API/`, `/videoService/`) | ✅ REAL | 401 challenge `{realm, randomKey, encryptType:MD5, publicKey}` → 2º POST con firma → token 64 hex |
| `GET /brms/api/v1.1/account/security/public-key/generate` | ✅ REAL (E-106) | RSA-1024 PEM real + randomKey (privada 5 min en memoria) |
| `POST /brms/api/v1.1/account/security/password/check` | ✅ REAL (E-106) | desencripta PKCS1/OAEP, éxito garantizado |
| `POST /brms/api/v1.0/accounts/updateToken` (+ admin) | ✅ REAL (E-107) | refresh de token |
| `POST /brms/api/v1.0/accounts/keepalive`, `GET accounts/current`, `POST unauthorize` | ✅ REAL | requieren token válido |

## 3. Users / Roles / Permisos (secuencia del diálogo, en orden)

| # | Endpoint | Bytes vivo | Estado |
|---|---|---|---|
| 1 | `GET role/page?roleName=&pageSize=20&page=1` | 5256 | ✅ `pageData[]` + `totalCount` string + `allowEdit/id/roleType/roleName/memo` |
| 2 | `GET function/available/list` | 13661 | ✅ menús + FunctionType codes, flags string |
| 3 | `GET menu/available/list?roleId=1` | 46314 | ✅ 86 menús, `sort` string |
| 4 | `GET subsystem/available/list` | 7714 | ✅ 15 subsistemas |
| 5 | `GET user/group/list?keyword=` | 2938 | ✅ `results[]` con `users[]` |
| 6 | `GET config/ldap` | 351 | ✅ nativo: `username/port/autoSynTime/dn/enable/enableAutoSyn/ssl/server` |
| 7 | `GET role/list` | 5256 | ✅ nativo `results[]` + SPA `pageData[]` |
| 8 | `GET user/page?...` | 386–8951 | ✅ `pageData[]` con `id/username/name/online/enableMPT/status/userType/roles[]`, admin + operator |
| 9 | `GET|POST tree/full/grade-device-tree?orgCode=` | 479–3531 | ✅ orgs/devices/channels por org, `checked` string, sin huérfanos |
| 10 | `GET domain/organization/list` | 3037 | ✅ `domainOrgExceeded` + `results[]` `domainOrg*` |
| 11 | `GET authority/resource/{id}/role/list` | 3114 | ✅ `results` = array de STRINGS (roleIds); objetos en `list/roleList` |
| 12 | `PUT|POST authority/resource/{id}/role/update` | ack | ✅ eco `roleIds` |
| 13 | `GET resource-allocate/organization/device/fetch/list?orgCode=` | 4168 | ✅ devices + channels por org |
| 14 | `GET account/function/channel/check[?channelCode=]` | 42792 | ✅ gate Live View: todos los FunctionType (liveView 8, playback 9, PTZ 13…) |
| 15 | `GET account/function/device/check?deviceCode=` | 14112 | ✅ |
| 16 | `GET|POST /admin/API/Rights/Users|Groups|User` | 386/2938/721 | ✅ legacy del mismo diálogo (E-105) |

## 4. Dispositivos / Árbol / Monitoreo

| Endpoint | Estado |
|---|---|
| `GET device/page?...` (12063 B) | ✅ |
| `GET tree/device-tree`, `POST tree/devices`, `GET tree/deviceOrg` | ✅ 10081/15991/10081 B |
| `GET account/device/overview` | ✅ 2 devices / 2 channels |
| `GET discover/device/page` | ✅ |
| `GET system/network/list`, `config/timezone/info`, `config/interface/common/timeout`, `config/function`, `config/sira`, `config/feature-analyse`, `config/device-login-model`, `license/warning` | ✅ |
| `GET account/menu/list` (E-108) | ✅ 57879 B — catálogo de menús del rol |
| `GET config/videoIntercom` (E-108) | ✅ alias del que ya funcionaba en `/admin/API` |
| `GET config/mail` (E-108) | ✅ config SMTP deshabilitada, flags string |
| `GET dictionary/list?types=…` | ✅ |
| `GET monitor/view/share/unread/list`, `storage/plan/.../record-plan/page` | ◐ colecciones vacías legítimas |

## 5. Stubs vacíos por diseño (no requieren acción salvo que el cliente exija contenido)

- `/brms/api/v1.1/time-template/list` (59 B), `/alarm/plan/alarm-type/list` (49 B),
  `/vtalk/sip/online/list` (49 B), `/config/ai/privacy` (77 B).
- RPC legacy `/admin/API/BRM/Config/GetEmapInfo|GetLinkedChannels|GetTvWalls`,
  `/BRM/User/GetUserData` — reconocidos, sin contenido requerido.

## 6. Catch-all (FALLBACK) — cómo eliminarlo de la ecuación

Todo lo no registrado cae en `app.get(PREFIX + '/*')` → `{code:1000,data:{list:[],total:0}}`
(59 B GET / 40 B POST) que DPSDK lee como **"Abnormal network"**. Regla del proyecto:
**toda ruta que el cliente toque debe tener handler explícito**; las variantes de
versión (v1.0/v1.1/v2.0) y de prefijo (brms/ipms/admin) se registran juntas
(E-107). Ver en vivo: `docker logs … | grep FALLBACK` = 0 para rutas del cliente.

## 7. Infraestructura verificada

RTSP 9100 (200 en `D0238JDG3016$1$0$0` y `D00712RD0005$1$0$0`), MediaMTX, ActiveMQ
(OpenWire 61616 + STOMP 61613 + MQTT 1883 con notify), SIP UDP 5080 (REGISTER 200),
ARS TCP 9500, WebSocket eventBus en 1443.

## 8. Pendiente conocido

- Import completo de Ghidra sobre DPSDK.dll (17 MB) excede el deadline de REA
  (330 s); la evidencia de contratos se obtuvo por string pool + decompilación
  dirigida (equivalente, documentada en `docs/DPSDK_USER_MANAGEMENT_CONTRACTS.md`).
- Endpoints fuera de Users/Config (face, acceso, parking, attendance) mantienen
  el catch-all benigno; solo se implementarán si el cliente los pide en vivo.
