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
