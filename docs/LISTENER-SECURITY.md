# Matriz de listeners / contratos de red (auditoría DevOps 2026-11-08)

Fuente: subagente DevOps `ses_e46bd58b7ffe3V5NVN6XT2zaDx` (solo lectura + 2
sondas live: RTSP SETUP+PLAY, ARS fragmentado/len falso). Estado tras E-128.

| Puerto | Protocolo | Estado | Riesgo / nota |
|---|---|---|---|
| 11443 | HTTP API | OK sin TLS (lab) | MEDIA: `/event/push` sin auth → alarma falsificable; restringir por firewall |
| 1443 / 9443 | HTTPS API | OK, cert lab CN/SAN 10.10.20.120 (válido a 2027-11-01) | cliente con disablePeerVerification; renovar cert antes de 2027-11 |
| 9100 | RTSP relay → MediaMTX | OK live (SETUP+PLAY misma URL, 454KB RTP/3s) | ALTA corregida parcialmente: falta serializar SETUP/PLAY si el cliente pipelinea; CSeq se devuelve el del upstream; RTSP_SESSIONS sin TTL (replay LAN); buffers sin tope → ver e115 |
| 9500 | ARS TCP DVRIP/DHIP | OK tras E-128 | ALTA corregida: reensamblado de frames, cap payload 1MiB / buffer 4MiB, ACK con offsets RE (DVRIP 48B cmd@0x18 seq@0x1C len@0x24 flag@0x2C; DHIP 52B version@0x0C len@0x28 flag@0x30), keepalive/logout en ruta binaria. MEDIA pendiente: `session.authenticated` no exigido (SSRF suave vía IP registrado) |
| 5080 | SIP UDP | responde 200 OK a todo REGISTER | ALTA documentada: reflector sin rate-limit; falta SIP TCP 5080 y TLS 5060/5061 (DPSDK 0xc56d30/0xc56528) para INVITE intercom TLS |
| 18800 / 19800 | UDP alarm ingest | 18800 → `/event/push` sin auth; 19800 sin handler ni 'error' | falsificación de alarmas por LAN |
| 61616 | OpenWire (ActiveMQ) | TLS OK con keystore lab | admin/admin en 0.0.0.0 → firewall |
| 61613 | STOMP publisher interno | gateway publica a red docker | quitar mapeo host de 61613 (admin/admin texto plano) |
| 1883 | MQTT notify | broker propio sin auth/TLS; el cliente nativo se suscribe (MQConfig.mqtt) | envenenamiento de árbol por LAN (vms.addDev etc.); 70 de 88 topics suscritos aún sin publicar (ver REA residual) |
| mediamtx 8554 | RTSP interno | OK solo 127.0.0.1:9554 | — |
| mediamtx 1935/8888/8889 | RTMP/HLS/WS | **publicados en 0.0.0.0 sin auth** | ALTA: H.265 descargable sin credenciales → acotar a LAN confiable |
| mediamtx 9997 | API control | auth solo 172.18.0.0/16 | MEDIA: si la red docker cambia de subred, provisioning muere (clase E-116) → fijar subred o 172.16.0.0/12 |
| 554 / 37777 | RTSP/SDK nativos a dispositivos | NO hay proxy nativo | dispositivos ONVIF usan 8021/8554; documentado en NETWORK_PROTOCOLS.md |

## Contrato binario DVRIP/DHIP (RE, netsdk AutoRegister.cpp 0x01366578)
- DVRIP: magic `DVRIP\0\0\0` + version 0x19930522@+8, header 48B, JSON @+0x30;
  campos cmd@0x18 seq@0x1C len@0x24 flag@0x2C.
- DHIP: magic `DHIP\0\0\0` + 0@+8 + version@+0x0C, header 52B, JSON @+0x34;
  len@0x28 flag@0x30.
- Registro: JSON `client.register` con DeviceID/SerialNo/DeviceType/
  MachineAddress/IPAddress/Port/UserName/Password; ACK `Ret:100` +
  SessionID + RegisterServer/RegisterPort + KeepAliveSecond.
- Keepalive/logout por JSON method o cmd 0x0004/0x0005 (E-128).

## Pendientes de red (no bloquean al cliente ONVIF)
1. SIP sobre TCP/TLS (5080/5060/5061) para vtalk intercom.
2. 70 topics `brms.notify*`/`vms.notify*` sin publicar (lista en reporte REA residual).
3. Firewall de puertos 1883/61613/1935/8888/8889/11443/9500 (compose + host).
4. Rotación del journal `/app/data/logs/requests-*.log` (hoy append sin tope).
5. RTSP relay: serializar SETUP/PLAY, TTL en RTSP_SESSIONS, tope de buffers.

## Contrato WebSocket local de MSG.exe (REA 2026-11-08, ses_e45812db5ffe5zhZ2PvSWoNcvF)
- MSG.exe corre su **propio WSS local** (no es el WS del gateway): puerto libre
  vía `queryAvailablePort` (0x1f8f08), TLS con cert autofirmado
  `/Cache/cert.pem`+`key.pem` (0x1f8e00/0x1f8e10), anuncia el puerto al SDK con
  `SendWebsocketPort:%d` (0x1f5b80 → DPSDK 0xc40520).
- Handshake RFC6455 estricto: GET + `Connection: upgrade` + `Upgrade:
  websocket` + `Sec-Websocket-Version: 13` + `Sec-WebSocket-Key` (base64
  16B) → 101 con `Sec-WebSocket-Accept` = base64(SHA1(key+GUID
  258EAFA5-E914-47DA-95CA-C5AB0DC85B11)). Errores propios: 405/426.
- Protocolo de control (texto JSON):
  `{"hub":"methods","method":"subscribe|unsubscribe","methods":[{"method":...,"name":...}]}`
  (0x1f8978-0x1f8ab0). Push de eventos vía `NotifyNormalMsg`/`NotifyFrequentMsg`
  (0x1f8ba8/0x1f8c10) alimentado por la cola MQ local (`mq.alarm.msg.topic.*`
  0x1f6280-0x1f6328, per-user con el UserId de GetMqConfig).
- El gateway solo necesita su WS propio ya existente
  (`wss://host:1443/brms/api/v1.0/event/ws?token=...` → WELCOME).

## 554 / 37777 — conclusión REA (cerrado)
- Son **puertos outbound hacia el dispositivo**, no listeners del gateway:
  554 = RTSP default a cámaras Dahua nativas (DPSDK 0xe75edc tabla .data,
  PluginFactory 0x19a9bb4); 37777 = SDK nativo Dahua al dispositivo
  (PluginFactory 0x19a9f2c). Dispositivos ONVIF no usan intercom ni rewind en
  plataforma (`ONVIF protocol access devices do not support intercom.`
  PluginFactory 0x1a95d20). **No se abre listener en 554 ni 37777**; el video
  entra por el relay RTSP 9100 y el registro por ARS 9500.
