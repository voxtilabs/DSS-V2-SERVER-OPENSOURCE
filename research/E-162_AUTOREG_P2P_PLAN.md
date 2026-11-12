# E-162 — Autoregistro Dahua (ARS 9500) y cámaras P2P (Easy4IP): estado, evidencia y plan

**Fecha**: 2026-11-12 · **Alcance**: `poc/dss-v2-harness/brms-gateway/src/` (gateway Node/Fastify)
**Cliente oficial**: `C:\DSS\DSS Client\` — **sólo lectura** (no se modificó nada allí).
**Regla de evidencia**: cada afirmación va marcada `[EV]` (leído en binario/código del repo, con offset o `archivo:línea`)
o `[HYP]` (hipótesis a validar en laboratorio).

---

## 0. Resumen ejecutivo (veredicto)

| Pregunta | Veredicto | Base |
|---|---|---|
| ¿El autoregistro ARS es la vía correcta para que un DVR/XVR Dahua "aparezca solo"? | **Sí.** Es device→server sobre TCP 9500, el dispositivo se configura con IP del servidor + 9500 + Device ID, y funciona sin P2P | `[EV]` wiki Dahua + strings netsdk.dll; coincide con `docs/P2P_RESEARCH.md:317-339` |
| ¿Nuestro listener 9500 hoy es funcional? | **Parcial / no funcional con hardware real.** Hay dos parsers (`e119-ars-protocol.js` + un parser legacy de 32 B en `index.js`), un framing está mal modelado y el registro se **borra del árbol al hacer logout**. Sin un DVR real nunca se validó de punta a punta | `[EV]` §2.3, §2.4 |
| ¿El cliente DSS participa del ARS? | **No.** El cliente (DPSDK.dll) no tiene código DHIP/DVRIP/ARS; ve el dispositivo sólo por REST (`device/page`, listas) | `[EV]` `docs/MASTER-STATUS.md:513`; 0 hits DHIP/DVRIP en DPSDK.dll (§3.1) |
| ¿P2P/Easy4IP se puede "servir" desde nuestro gateway? | **No se puede fingir.** El camino P2P del cliente es cliente→cloud Dahua→dispositivo (DPSDK→P2PDll); el servidor sólo aporta `connectType`/`stunEnable`. Sin cuenta/SN registrado en Easy4IP no hay P2P | `[EV]` §3.1–3.2 |
| Alternativa honesta para cámaras tras NAT | Relay propio RTSP→MediaMTX (agente en sitio) o WebRTC de MediaMTX. **Declarado explícitamente NO-P2P** | `[HYP]/diseño` §4-P2 |

Orden recomendado: **P0 ARS real** → **P0 ver en el cliente** → **P1 instrumentación+P2P contract** → **P2 relay propio**.

---

## 1. Qué existe ya en el repo (implementado vs stub)

### 1.1 Discovery / auto-add

| Pieza | Ubicación | Estado real |
|---|---|---|
| `discover/cost-time` | `src/index.js:1767-1773` → `e025-devices.js:662-685` | **Implementado pero es una sonda de UNA IP**: guarda en `DISCOVERED_DEVICES` y devuelve `costTime`. No hay escaneo de subred, ni multicast, ni SNMP/ARP |
| `discover/summary` | `src/index.js:1774-1780` → `e025-devices.js:687-722` | Real: incorpora el resultado del probe ONVIF (`probeOnvifDevice`, `e025-devices.js:278-333`) |
| `discover/detail` | `src/index.js:1781-1787` → `e025-devices.js:724-728` | Stub: `channels:[]`, `channelList:[]`, `capabilities:[]` |
| `discover/async/batch` | `src/index.js:1788` → `e025-devices.js:1212` | Stub |
| `discover/device/page` | `src/index.js:1977` → `e025-devices.js:855-945` | Implementado: filas registradas (`id=deviceCode`) + filas descubiertas (`id=DSC-ip:port`) |
| `discover/device/join/batch` (batchAdd) | `src/index.js:2115-2125` → `e025-devices.js:980-1052` | Implementado y con contrato fino (`results` sólo fracasos, códigos 110113/110262) |
| `discover/device/init` | `src/index.js:2126-2143` → `e025-devices.js:947-964` | Implementado |
| `discover/device/network/update` | `src/index.js:2144` | Stub `{success:true}` |
| `device/unauthorized/page` | `src/index.js:2078` → `e025-devices.js:1116-1118` | **Stub: siempre `{total:0, list:[]}`** ← aquí deberían salir los ARS (ver §4-P0.3) |
| `device/unauthorized/{add,delete}/batch` | `src/index.js:2079-2080` | Stub (`results:[]`) |
| Multicast / 239.255.x / SNMP discovery | — | **No implementado.** Sólo existe `multicastIp:'239.0.0.1'` como relleno del DTO de StartVideo (`index.js:2972,3043,3091`) y catálogos SNMP (`e024-catalogs.js:279`) |
| `addType` | — | **Sin evidencia en el repo** (el combo "Add Type" del diálogo Add Device del cliente no está mapeado) |

### 1.2 Autoregistro ARS

| Pieza | Ubicación | Estado |
|---|---|---|
| Parser/ACK "RE" (magic + `0x19930522` + JSON) | `src/e119-ars-protocol.js:40-142` | Implementado; ver discrepancias §2.3 |
| Listener TCP 9500 | `src/index.js:325-431` (legacy), `3496-3710` (servidor) | Implementado, **dos framings en el mismo socket** |
| Sesiones ARS en RAM | `index.js:346` `ARS_TCP_SESSIONS` | Sin persistencia; timeout 120 s (`index.js:3701-3707`) |
| Registro ARS REST (device→server) | `index.js:3397-3419` | Implementado (sin auth, como el real) |
| keepalive / unregister / list / device-info | `index.js:3421-3453` | Implementado (`list` desde el registro real, `device-info` casi todo hardcodeado) |
| Materialización en el árbol | `e025-devices.js:1930-1945` (`registerArsDevice`) → `createDeviceRecord` `444-489` | Implementado y **persistente** (`persistDevice`, `e025-devices.js:126-129`) |
| Provisión de stream del dispositivo ARS | `index.js:2101` `scheduleStreamProvisioning` → `e025-devices.js:139` `ensureDeviceStream` | Implementado (ONVIF→convención Dahua→MediaMTX), con guarda anti-loopback |
| BUG: al `logout`/desconexión se **borra** el dispositivo | `index.js:3548` y `3671` (`ARS_DEVICES.delete`), y el registro real queda huérfano | **Defecto P0** (un reinicio del DVR lo saca del árbol) |
| BUG: la contraseña del dispositivo nunca se guarda | `e025-devices.js:116-119` (strip `loginPass/password` al escribir `data/devices.json`) | El device ARS queda sin credencial tras reiniciar → sin stream. Decisión de producto en §4 |

### 1.3 P2P / Easy4IP

| Pieza | Ubicación | Estado |
|---|---|---|
| SOAP `getDeviceByDevSequence` real | `e025-devices.js:343-398` | **Implementado y honesto** (devuelve `returnEmpty` cuando el SN no está publicado) |
| Reachability de los 5 hosts del cloud | `e025-devices.js:405-441`; `index.js:3361-3370` | Implementado |
| `p2p/status` | `index.js:3297-3298` → `e025-devices.js:1966-1981` | Implementado; dice explícitamente que este build no se registra en el cloud |
| `device/p2p-register` / `-unregister` / `-list` | `index.js:3301-3392` | Implementado con lookup real; nunca finge éxito |
| `p2p/info`, `p2p/connect-type` | `e129-p1-coverage.js:50-51` | **Stub** (`connectType:'0'`, `p2pStatus:'0'`) ← es el hook real del cliente (§3.2) |
| `config/p2p`, `config/p2p/server/list` | `index.js:1734-1735` | Stub |
| Túnel PTCP/Tou | `poc/dss-v2-harness/p2p-probe/src/index.js:47` | **Stub** (`touHandshake` sólo loguea) |
| Capability | `index.js:2799,2802,2820` | `supportP2P:true`, `supportMulticast:true`, feature `p2p` — **publicidad sin implementación** |

**Resumen**: lo que falta no es "más código de P2P", es (a) cerrar el ARS con un dispositivo real y su contrato de aparición en el cliente, y (b) dejar de anunciar P2P como soportado.

---

## 2. Protocolo real de AUTOREGISTRO Dahua

### 2.1 Cómo lo hace el dispositivo `[EV] externo`

Dahua Wiki (DSS S2 / DSS Pro "Add Device Using Auto Register") y la guía de troubleshooting:

1. En el **dispositivo**: `Setup → Network → Register` → *Enable Auto Register*, **Server IP** = IP del DSS, **Port = 9500 (default)**, **Device ID** = nombre único definido por el operador. `[EV]` (dahuawiki; dahuatac "Auto register Offline troubleshooting")
2. En el **cliente DSS**: `Device → Add → Add Type: Auto Register`, y el equipo aparece listado.
3. Firewall: `TCP 9500` abierto hacia el servidor (misma fuente).
4. Confirmado en el propio repo: *"Puedes desactivar P2P y el autoregistro funciona igual"* (`docs/P2P_RESEARCH.md:337`) y ARS = device→server sin auth (`docs/NETWORK_PROTOCOLS.md:389-401`).

Corrección al enunciado de la tarea: **no es `0xa001` login / `0xa002` keepalive**. `0xa0 0x01` es el *challenge de login DVRIP* y `0xa0 0x05` el paquete de datos; el keepalive es el método JSON-RPC `global.keepAlive` dentro del paquete de datos. `[EV]` externo (mcw0/DahuaConsole `net.py`; dvrip-offline: cabecera fija de 32 B, `magic a0 05 00 60`, longitud en `+0x04`, contador en `+0x1b`).

### 2.2 Evidencia en el binario del cliente (sólo lectura)

Escaneo ASCII/UTF-16 con offsets (`netsdk.dll`, 28.240.384 B — es el SDK que usa el **servidor** DSS para hablar con dispositivos y el que implementa el rol *cliente* de ARS):

Offset de fichero (decimal, tal como lo emitió el escáner ASCII de `netsdk.dll`):

| Offset | Cadena | Qué prueba |
|---|---|---|
| 20342136 | `.\AutoRegister.cpp` | Existe un módulo ARS dedicado (mismo path que cita `e119-ars-protocol.js:3`) |
| 20384552 | `AutoRegister` | Nombre de módulo/clase |
| 20700768 | `AutoRegister connect more than 60 sec whitout login ,CloseConn ip : %s, port : %d` | Tras el `TCP connect` el dispositivo debe **loguearse en <60 s** o el cliente ARS cierra y reintenta |
| 20700864 | `AutoRegister service wait b4 more than 10 sec ,CloseConn ip : %s, port : %d` | El **servidor debe contestar en <10 s** |
| 20771776 / 20771920 | `CLIENT_SetAutoRegisterServerInfo [lDevHandle=%p, ARSIP=%s, ARSPort=%u, nRetry=%u.]` | La IP y el **puerto llegan por configuración** (ARSIP/ARSPort) + nº de reintentos |
| 25605611 | export `CLIENT_SetAutoRegisterServerInfo` | API pública del SDK |
| 20781104 | `CLIENT_ControlRegisterServer` | Control del registro (start/stop) |
| 20766080 | `CLIENT_GetDVRIPByResolveSvr [pchDVRIP, wDVRPort, sDVRName, wDVRNameLen, sDVRSerialLen, sGetIP]` | El servidor puede resolver un dispositivo **por nombre/serial → IP:puerto** |
| 20415368 / 20415384 / 20415400 | `DVRIP_TRANS`, `DVRIP_REGISTER`, `DVRIP_NET` | Tres flujos lógicos del autoregistro: **register / net (keepalive) / trans (config-media)** |
| 20480120 | `Failed to parse pTransInfo` | Payload *Trans* |
| 20480152 | `RegisterServer` | Campo `RegisterServer` del payload |
| 20480168 | `Failed to parse pRegisterInfo` | Payload *Register* |
| 20480200 | `Failed to parse pNetInfo` | Payload *Net* |
| 20422984 / 20423128 | `ProxyHttps`, `MachineAddress` | Campos del payload de registro (los mismos que `e119-ars-protocol.js:89-102`) |
| 20546968 / 20547080 | `MachineName`, `DeviceClass` (`getDeviceClass` @20535504) | Idem |
| 21681256 / 21729248 / 21729264 | `deviceClass`, `machineName`, `machineAddress` | Variantes camelCase (payload JSON alternativo) |
| 20481664 | `[{"ExtraFormat":[null,null,null],"MainFormat":[null,null,null],"SnapFormat":[null,null,null]}]` | **Plantilla literal** del JSON de registro (coincide con `e119-ars-protocol.js:7`) |
| 21623280 | `AutoRegister.registerTemp` | Nombre de la plantilla/registro temporal |

(Nota: los offsets son de fichero, no RVA; el escaneo es ASCII puro sobre el binario completo.)

Byte-scan de `9500` en **todo** `netsdk.dll`: **0 ocurrencias** ⇒ el puerto no está hardcodeado (lo inyecta el servidor vía `ARSPort`). Coherente con `e119-ars-protocol.js:16`.

### 2.3 Framing: dos plantillas reales en `.rdata` (hexdump)

Plantilla **DVRIP** @ file `0x1388648` (volcado verbatim):

```
0x1388640  00000000 01000000 44565249 50000000   <- "DVRIP\0\0\0" @0x1388648
0x1388650  22059319 01000000 641f5f01 00000000   <- +0x08 = 0x19930522, +0x0C = 1
0x1388660  00000000 05000000 6c1f5f01 90000000   <- +0x18 = 0, +0x1C = 5, +0x24 = 0x90 (144)
0x1388670  00000000 01000000 00000000 00000000   <- +0x28 = 0, +0x2C = 1
0x1388680  5b7b2245 78747261 466f726d ...       <- +0x38 = '[{"ExtraFormat":...'
```

Plantilla **DHIP** @ file `0x13988DC`:

```
0x13988D4  6174616c 656e0000 44484950 00000000   <- "DHIP\0\0\0\0" @0x13988DC
0x13988E4  00000000 22059319 05000000 e4706201   <- +0x08 = 0, +0x0C = 0x19930522, +0x10 = 5
0x13988F4  00000000 00000000 0b000000 0c716201   <- +0x18 = 0, +0x1C = 0, +0x20 = 0x0B
0x1398904  60000000 00000000 01000000 636c6965   <- +0x28 = 0x60 (96), +0x30 = 1, +0x34 = "clie…
0x1398914  6e742e6e 6f746966 79446576 496e6974   <- "…nt.notifyDevInitNext"
```

Conclusiones `[EV]`:

- **DHIP coincide exactamente** con `e119-ars-protocol.js:49-51` (cabecera 0x34, JSON en `+0x34`, len `+0x28`, flag `+0x30`, "5" en `+0x10`).
- **DVRIP NO**: el JSON arranca en **`+0x38`** (no `+0x30`); hay dos dwords extra en `+0x30/+0x34`. `e119-ars-protocol.js:56` localiza el JSON con `buf.indexOf(0x7b)` sin acotar, lo que puede dar un falso positivo si un campo de la cabecera contiene el byte `0x7B`.
- En **ambas** plantillas el "comando" vale **5** (`DVRIP +0x1C`, `DHIP +0x10`). El ACK actual usa `frame.command || 0x0001` (`index.js:3574`) ⇒ si el dispositivo habla la plantilla real, el ACK debería llevar `0x8005`. **Fix trivial: ecoar siempre el comando recibido.**
- **Discrepancia abierta (crítica)**: el DHIP "de calle" documentado por DahuaConsole es **cabecera de 32 B + JSON `{method, params, id, session}`** (login `global.login`, `global.keepAlive`, errores `268632079`/`401`), no 0x34. Las plantillas de `netsdk` (48/52/56 B) son estructuras internas de `.rdata`. **Hipótesis**: las plantillas son el *payload* ARS (register/net/trans) y el DHIP de 32 B es el transporte. Sólo un DVR real arbitra esto ⇒ **el parser debe ser tolerante a ambos (ver §4-P0.1)**, no elegir uno.

### 2.4 Qué debe responder el servidor `[EV]`+`[HYP]`

| Mensaje | Dirección | Contenido esperado (según evidencia) |
|---|---|---|
| `REGISTER` (`DVRIP_REGISTER`) | DVR→SRV | JSON con `DeviceID`/`SerialNo`/`DeviceType`/`DeviceClass`/`MachineName`/`MachineAddress`/`IPAddress`/`Port`/`ChannelNum`/`Firmware` (+ `ProxyHttps/ProxyPort`) |
| ACK registro | SRV→DVR | eco de comando (`cmd|0x8000`) + seq + `Ret:100` + `SessionID` + **`RegisterServer`/`RegisterPort`** + `KeepAliveSecond` — hoy en `e119-ars-protocol.js:136-142` `[HYP]` (formato no verificado contra hardware) |
| `NET` (keepalive) | DVR→SRV | JSON con el DeviceID y estado; `KeepAliveSecond: 60` es lo que el servidor publica |
| `TRANS` | DVR→SRV | formatos `ExtraFormat/MainFormat/SnapFormat` (la plantilla literal de §2.3) — **el ACK debe devolver un JSON válido**, no vacío: es lo único que hoy lanzaría `Ret:400` |
| `LOGOUT` | DVR→SRV | cierre limpio → debe marcar **offline**, no borrar |

### 2.5 Cómo lo muestra el cliente DSS `[EV]`+`[HYP]`

- `[EV]` El cliente **no habla ARS**: byte-scan propio en `DPSDK.dll` → 0 hits de `DVRIP`, `DHIP\0\0\0` y `9500` (ver §3.1); sólo tiene `DHIPC` (offset 21386116 = `0x1465384`) y las familias REST de dispositivos. (`docs/MASTER-STATUS.md:513`)
- `[EV]` Los métodos del servidor DSS relacionados son `vms.addUnAuthDevice`, `vms.updateUnAuthDevice`, `vms.deleteUnAuthDevice` (`src/data/rpc-method-catalog.txt:1845,1898,2020`) y `SaveUnAuthDevices`/`BatchAddUnauthorizedDevices` (`docs/COMPATIBILITY-MAP.md:22`) ⇒ hay una **lista de "no autorizados"** en el servidor, y el gateway ya expone la ruta vacía (`/device/unauthorized/page`, `index.js:2078`).
- `[HYP]` (a validar, es el contrato #1 abierto): el combo **"Add Type: Auto Register"** del diálogo Add Device lista los dispositivos que llegaron por 9500 y aún no fueron autorizados ⇒ esa lista es `GET /brms/api/v1.1/device/unauthorized/page`. No hay evidencia en el repo de qué request dispara ese combo: hay que capturarlo (§4-P1.3).
- `[EV]` Una vez materializado, el dispositivo ya aparece en `device/page`, `tree/devices`, `tree/channels` y estadísticas porque `registerArsDevice` crea un registro normal (`e025-devices.js:1930-1945`, `444-489`).

---

## 3. Easy4IP / P2P

### 3.1 Evidencia (DPSDK.dll, 17.078.880 B)

Offset de fichero (decimal):

| Offset | Cadena | Lectura |
|---|---|---|
| 13111816 | `config/p2p` | REST de configuración P2P |
| 13112024 / 13084296 | `config/p2p/server/list`, `GetP2PServerList failed, deviceCode[%s] iRet[%d]` | Lista de servidores P2P **por dispositivo** |
| 13084352 | `GetP2PDeviceInfo failed, deviceCode[%s] iRet[%d]` | Info P2P por dispositivo |
| 13405944 | `BRMS.Config.GetP2PServers` | **Método RPC** del servidor |
| 13112152 | `/p2p/info` | REST por dispositivo |
| 13204600 + 13204544 | `/p2p/connect-type`, `Dpsdk::CRestLogical::GetP2PConnectType` | **El cliente pregunta al servidor cómo conectarse** |
| 13290060 | `BRMS.Device.GetP2PConnectType` | Método RPC equivalente |
| 13275684 | `connectType`, `stumPort`, `stum` (typo del propio binario), `minRate` | Claves del DTO de StartVideo |
| 13447608 / 13456160 / 13457624 / 13457640 | `connectType`, `stunPort`, `stunEnable` | Claves del DTO de media |
| 13391952-13393256 | `CP2PServerManager`, `LoginP2PServer`, `StartP2PTraversal`, `GetDeviceInfoFromEasy4IP`, `ParseHttpBodyForEasy4IP`, `ParseDevInfo`, `AddP2PP2Mapping`, `DelP2PPortMapping` | Cadena completa del túnel |
| 13393056 / 13393312 | `getDeviceByDevSequence from WEB Service …`, `devSequence` | Lookup por SN |
| 13393600-13393712 | `<ns2:getDeviceByDevSequence xmlns:ns2='http://webservice.ddns.dahua.com/'>` … `<devSequence>%s</devSequence>` | Plantilla SOAP exacta del cloud |
| 16065144-16065680 | `www.easy4ip.com`, `www.easy4ipcloud.com`, `www.dahuap2p.com`, `www.dahuap2pcloud.com` | Hosts del cloud |
| 13392784 / 15625552 | `P2P_Connect[%d] failed!`, `P2P_Connect` (export) | El túnel lo ejecuta P2PDll dentro del cliente |
| 21386116 | `DHIPC` | — |

Byte-scan propio sobre `DPSDK.dll`: `DVRIP` → **0 hits**, `DHIP\0\0\0` → **0 hits**, `9500` → **0 hits** ⇒ **el cliente DSS no habla ARS** (coincide con `docs/MASTER-STATUS.md:513`; el
código ARS vive en `netsdk.dll`, que es la pata *servidor/agente*).

### 3.2 Quién habla con quién `[EV]`

```
DSS Client (DPSDK.dll)
  1. GET /p2p/connect-type (o BRMS.Device.GetP2PConnectType)  ──►  NUESTRO GATEWAY   [EV]
  2. SOAP getDeviceByDevSequence(SN)  ──►  www.easy4ip.com  (cloud Dahua)          [EV]
  3. PTCP/Tou (P2PDll + libTouProxy) → relay del cloud  ──►  cámara/NVR  [EV estructural]
  4. RTSP/DVRIP demuxado sobre el túnel local 127.0.0.1:<port>                       [EV]
```

**Por tanto el servidor NO está en el camino de medios P2P.** El gateway sólo decide `connectType`; el resto lo hace el cliente contra el cloud de Dahua. Consecuencias honestas:

- `[EV]` Con un SN no publicado en Easy4IP el cloud responde **200 con `<return/>` vacío** → el propio repo lo comprobó en vivo (`docs/NETWORK_PROTOCOLS.md:662`). Ese SN **nunca** abrirá P2P.
- `[HYP]` Para que una cámara P2P "aparezca y se vea" con el cliente oficial hacen falta **tres** cosas fuera de nuestro control: (1) la cámara registrada y online en Easy4IP, (2) que el cloud resuelva el SN a IP:puerto, (3) que el cliente pueda alcanzar el relay de Dahua. Nuestro gateway sólo puede (0) publicar el `deviceCode`/SN correcto y `connectType` adecuado.
- `[EV]` **Formato "SN@dominio" del deviceCode: NO verificado.** Las únicas apariciones de `%s@%s` en DPSDK.dll son de la zona curl/SIP (offsets de fichero 13008800, 13367888 `sip:%s@%s`, 13367920), no del código P2P. Lo confirmado es que la clave de lookup es `devSequence` = SN en claro (13393312) y que `deviceCode` es el id interno de dispositivo (13069664 `pDeviceCode`, 13290760 `deviceCode`).

### 3.3 Veredicto P2P

> **El P2P de Dahua es propietario y depende del cloud del fabricante y de secretos de aplicación embebidos en SmartPSS/DMSS/DPSDK. Este proyecto no los extrae ni los reutiliza (ADR-0004). Un servidor propio NO puede hacer que una cámara P2P "aparezca" ni streamear por P2P con el cliente oficial por sí solo.**

Alternativa honesta (sin fingir compatibilidad): **relay propio** — agente en el sitio que empuja RTSP a MediaMTX (`source: publisher` / `runOnInit` ffmpeg) o túnel WireGuard; salida RTSP/HLS/WebRTC por MediaMTX. Etiquetado en UI/API como `p2pSupported:"0"`, `relayType:"agent-rtsp"`.

---

## 4. Plan de implementación (priorizado)

### P0 — ARS funcional de punta a punta (1–2 días)

| # | Archivo | Cambio |
|---|---|---|
| P0.1 | **`src/e162-ars-protocol.js` (nuevo)** | Parser único y tolerante, absorbiendo `e119-ars-protocol.js`: (a) ASCII 8 B `DVRIP`/`DHIP` + `0x19930522`; (b) DHIP de 32 B `a0 05` + JSON-RPC; (c) `jsonAt` calculado **por plantilla** (`+0x38` DVRIP, `+0x34` DHIP) y, si no hay magic conocido, búsqueda de `{` acotada a `[0x10,0x40]`. `buildAck()` **ecoando el comando recibido** (`cmd|0x8000`), no `0x0001`. Exporta `detectFraming(buf)`, `parseRegisterFrame`, `buildRegisterAck`, `redactSecrets(json)` |
| P0.2 | `src/index.js:3496-3710` | Reemplazar los dos caminos por el módulo P0.1; **no borrar** el dispositivo en `logout`/`close`, sólo `status:"0"` + `offlineReason:"logout"` (`index.js:3548,3671,3693-3698`) |
| P0.3 | `src/e025-devices.js:1116` + `index.js:2078-2080` | `unauthorized/page` real: filas ARS no autorizadas; `unauthorized/add/batch` marca `authorized:true`, emite `DEVICE_ADDED` (`e039-mq-notify.js:538`) y devuelve `results:[]` (contrato E-030) |
| P0.4 | `src/e025-devices.js:139` | Garantizar stream del device ARS (ya existe) + test de que recibe `mediamtxPath` |
| P0.5 | `data/devices.json` (migración al cargar, `e025-devices.js:94-109`) | Campos nuevos con default: `addType` (`"manual"|"auto-register"`), `authorized:"1"`, `ars:{ lastSeen, keepAliveSecond, registerFromIp, framing }`. Sin migración destructiva |
| P0.6 | `src/test/e162-ars.test.js` (nuevo) | T1 DHIP 32 B + JSON → registro; T2 plantilla `DVRIP` (fixture hexdump §2.3) → parseo y `jsonAt=0x38`; T3 register→keepalive→logout conserva el device como offline; T4 `data/devices.json` no contiene `password`; T5 `unauthorized/page` con **todos los campos string** + `add/batch`; T6 fragmentación en 3 chunks + 2 peers simultáneos; T7 DoS (`payloadLen>1MiB` → destroy) |

**Credenciales**: hoy no se persisten (`e025-devices.js:116-119`). Se mantiene así por defecto (`P0`); un "vault" cifrado (AES-256-GCM, clave por env, sin escribir nada en el repo) es **P1 y requiere decisión del usuario**.

### P0 bis — Contrato de aparición en el cliente (bloqueante de aceptación)

Instrumentación mínima para cerrar el `[HYP]` §2.5 **sin adivinar endpoints**:

| # | Acción |
|---|---|
| P0.7 | `GET /brms/api/v1.1/device/ars/session/list` (nuevo, `auth`) → sesiones TCP activas (`clientIp, deviceId, framing, magic, lastSeen, keepAliveSecond, authorized`), todo string. Sólo diagnóstico/ops |
| P0.8 | Volcado del **primer frame crudo** por peer en `data/ars-raw/<ip>-<port>.bin` (máx. 8 KB, `redactSecrets()` aplicado, rotación a 20 ficheros). Es el dato que arbitra §2.3 |

### P1 — P2P: dejar de mentir y preparar la decisión

| # | Archivo | Cambio |
|---|---|---|
| P1.1 | `src/e129-p1-coverage.js:50-51` | `p2p/info` y `p2p/connect-type` reales: `{ connectType:"0", p2pStatus:"0", globalStatus:"0", serverCode:"", devSequence:"<sn>", stunEnable:"0", stunPort:"", relayType:"none", reason:"p2p_requires_dahua_cloud" }` (**todas string**) |
| P1.2 | `src/index.js:2799-2820` | `supportP2P:"0"` y quitar `p2p` de `features` mientras no exista camino real (hoy anuncia `supportP2P:true`) |
| P1.3 | `src/index.js:1734-1735` | `config/p2p` con `p2pEnable:"0"`, `openState:"0"`, `servers:[]`, `note:"self-hosted: no Dahua cloud registration"` |
| P1.4 | `src/test/e162-p2p.test.js` (nuevo) | T8 `p2p/info` y `connect-type` devuelven **todas las claves string** y `reason` explícito; T9 extender el test existente `brms.test.js:1741` con `p2pStatus:"unresolved"` cuando el cloud responde `<return/>` vacío; T10 snapshot del SOAP exacto (`e025-devices.js:343`) |
| P1.5 | **Experimento E-163** | Con captura en el gateway: (a) abrir `Add Device → Add Type: Auto Register` en el cliente oficial y registrar qué request emite; (b) `TCP 9500` de un DVR real y guardar `data/ars-raw/*.bin`; (c) `tcpdump`/`tshark` en el cliente al reproducir una cámara P2P con SN válido (ver `CAPTURA FILTRADA DSS.pcapng`, hoy sin analizar por falta de `tshark` en esta máquina) |

### P2 — Alternativa honesta para NAT

| # | Entrega |
|---|---|
| P2.1 | `tools/site-agent/` (nuevo, fuera de `src/`): contenedor en el sitio del cliente que publica `rtsp://<cam>:554/...` hacia `rtsp://<gw>:9100/<deviceCode>` (MediaMTX `source: publisher`) o levanta WireGuard. Sin credenciales en el repo (secretos por env) |
| P2.2 | Gateway: `POST /brms/api/v1.1/device/relay/register` `{ deviceCode, relayType:"agent-rtsp"|"wg", rtspUrl }` → `{ deviceCode, relayType, status:"1", rtspUrl }`; y `relayType` en `p2p/info` para que la UI muestre "relay propio" en lugar de "P2P" |
| P2.3 | (Sólo con decisión legal/negocio) integración real Easy4IP con **credenciales propias del cliente**, sin secretos de app de Dahua |

### Estado en `data/` (resumen)

| Fichero | Estado |
|---|---|
| `data/devices.json` | existente (`e025-devices.js:83`); + `addType`, `authorized`, `ars{}` (P0.5). Sin contraseñas |
| `data/ars-raw/` | nuevo (P0.8): primeros frames, redactados, ≤8 KB, máx. 20 |
| `data/orgs.json`, `data/alarms.json`, `data/views.json` | sin cambios |

### Endpoints nuevos/modificados — DTO con tipos **string**

```jsonc
// GET /brms/api/v1.1/device/unauthorized/page   (P0.3 — sustituye el stub)
{ "code":1000,"desc":"Success","data":{
  "pageNo":"1","pageSize":"20","totalCount":"1","total":"1",
  "pageData":[{
    "id":"ARS-<sn>","deviceCode":"ARS-<sn>","deviceId":"ARS-<sn>","deviceName":"XVR-4CH",
    "deviceIp":"10.0.0.9","devicePort":"37777","protocolType":"1","protocolName":"Dahua",
    "deviceType":"2","deviceCategory":"1","manufacturer":"Dahua","model":"","serialNumber":"<sn>",
    "channelNum":"4","online":"1","status":"1","onlineStatus":"1","initStatus":"1",
    "addType":"auto-register","source":"auto-register","authorized":"0",
    "registerFromIp":"10.0.0.9","lastSeenAt":"1762900000000","orgCode":"001"
  }],"results":[{ /* mismo objeto */ }],"list":[],"items":[],"totalCountStr":"1"
}}
// POST /brms/api/v1.1/device/unauthorized/add/batch   {"ids":["ARS-<sn>"]}
{ "code":1000,"data":{ "results":[], "failList":[], "list":["ARS-<sn>"], "total":"1", "success":true } }

// GET /brms/api/v1.1/p2p/info?deviceCode=ARS-<sn>      (P1.1)
{ "code":1000,"data":{ "connectType":"0","p2pStatus":"0","status":"0","globalStatus":"0",
  "serverCode":"","devSequence":"<sn>","stunEnable":"0","stunPort":"","relayType":"none",
  "reason":"p2p_requires_dahua_cloud" } }

// GET /brms/api/v1.1/device/ars/session/list            (P0.7, auth)
{ "code":1000,"data":{ "total":"1","sessions":[{ "clientIp":"10.0.0.9","deviceId":"<sn>",
  "framing":"DHIP32","magic":"DHIP","keepAliveSecond":"60","lastSeen":"1762900000000",
  "authorized":"0","online":"1" }] } }
```

---

## 5. Evidencia vs hipótesis (lista de cierre)

**Evidencia firme** `[EV]`: ARS = device→server TCP 9500, puerto inyectado por config (0 hits "9500" en netsdk); módulo `AutoRegister.cpp` + `CAutoRegister` + `CLIENT_SetAutoRegisterServerInfo(ARSIP,ARSPort,nRetry)`; timeouts 60 s login / 10 s respuesta; plantillas `DVRIP`/`DHIP` + `0x19930522` + JSON `ExtraFormat/MainFormat/SnapFormat`; flujos `DVRIP_REGISTER/NET/TRANS`; cliente **sin** ARS (0 hits DHIP/DVRIP en DPSDK); cliente **sí** pregunta `connectType`/`p2p/info` y hace el lookup SOAP `getDeviceByDevSequence` al cloud; `<return/>` vacío ⇒ SN no publicado; el gateway hoy anuncia `supportP2P:true` sin túnel.

**Hipótesis a validar** `[HYP]`: (1) formato exacto del ACK de registro (`Ret/SessionID/RegisterServer/KeepAliveSecond`); (2) que "Add Type: Auto Register" se alimente de `device/unauthorized/page`; (3) que el "5" de las plantillas sea el comando de registro; (4) que exista un framing DHIP de 32 B en 9500 (vs 0x34); (5) formato `SN@dominio` del deviceCode P2P (sin evidencia); (6) semántica de `connectType` (valores ≠"0").

**Límites de esta pasada**: sin DVR/XVR real; sin `tshark` en la máquina (el `CAPTURA FILTRADA DSS.pcapng` de 11,5 MB no se pudo filtrar); sin acceso al servidor DSS real (no hay `VMS_ARCMS.exe` en el repo, así que no hay implementación de referencia del lado servidor ARS).

---

## 6. Qué necesito del usuario para probarlo

1. **Un DVR/XVR Dahua en la red** (modelo + firmware) con acceso `admin`, que permita `Setup → Network → Register` apuntando a `<gateway>:9500` y un Device ID. Es el único árbitro de §2.3/§2.4.
2. **Confirmación de red**: `TCP 9500` del gateway alcanzable desde el DVR (sin NAT delante o con el puerto mapeado).
3. **Autorización** para que el gateway escriba `data/ars-raw/*.bin` (primeros frames redactados) y para abrir en el cliente oficial `Add Device → Add Type: Auto Register` mientras capturo los requests (cierra P0.7/P1.5).
4. **Para P2P**: un SN/equipo **realmente registrado en Easy4IP** con credenciales de la cuenta Dahua del cliente. Si no existe, cerramos P2P como "no soportado" y ejecutamos P2 (relay propio) — que es lo que recomiendo.
5. **Decisión de producto** sobre persistir credenciales de dispositivo cifradas (hoy no se guardan y el stream se pierde tras reiniciar).

---

### Fuentes externas citadas

- Dahua Wiki — *DSS S2 / Add Device Using Auto Register*: `https://dahuawiki.com/DSS_S2/User_Portal/Add_Device_Using_Auto_Register`
- Dahua Wiki — *Add Device Auto Register DSS Pro*: `https://dahuawiki.com/Template:DSS/Instructions/Add_Device_Auto_Register_DSS_Pro`
- Dahua Support — *How to add the device via auto register in DSS*: `https://portal.dahuatech.support/en/support/solutions/articles/80000963546`
- Dahua TAC — *Auto register Offline troubleshooting (port 9500)*: `https://dahuatac.zendesk.com/hc/en-gb/articles/12629085094674`
- mcw0/DahuaConsole — DVRIP/DHIP (`net.py`): `https://deepwiki.com/mcw0/DahuaConsole/3.2-dvrip-protocol`, `.../3.1-dhip-protocol`
- *dvrip-offline: Dahua ASA1222E-S — The wire protocol*: `https://zenithgenius.github.io/dahua-asa1222-dvrip-offline/analysis/protocol.html`
- bozzzzo/dahua-tools (DHIP en 5000/HTTP, DVRIP en 37777): `https://github.com/bozzzzo/dahua-tools`
