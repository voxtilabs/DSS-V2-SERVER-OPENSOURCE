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
