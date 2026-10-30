# ARCHITECTURE.md — Arquitectura inicial de DSS V2

## 1. Principio rector

Construir un VMS modular donde **cada módulo es sustituible** y donde la frontera con lo propietario
(SDK De Dahua, protocolo P2P no documentado) es una capa aislada. El sistema debe funcionar degraded
con elementos ausentes, y escalar horizontalmente varios módulos.

## 2. Vista de módulos (MVP)

```
                        ┌──────────────────────────────────────────────────┐
                        │                  API Gateway (Go)                 │
                        │  REST /api/v1  •  WebSocket  •  TLS  •  rate-lim. │
                        └───────┬───────────────┬──────────────┬───────────┘
                                │               │              │
            ┌───────────────────▼──┐   ┌────────▼─────────┐   ┌▼──────────────────┐
            │ Auth & User Manager  │   │  Event Engine     │   │   Web Client       │
            │ usuarios/roles/ses.  │   │ alarmas/eventos   │   │ React+TS (WS+WebRTC)│
            └──────────────────────┘   └────────▲─────────┘   └───────────────────┘
                                                │ (publica)
┌────────────────────┐   ┌────────────────────┴─────┐   ┌────────────────────────────┐
│  Device Manager    │   │       Video Engine        │   │     Recording Engine        │
│ inventario NVR/IPC │   │ RTSP/RTP→distribución     │   │ segmentos, índices, retención│
└─────────┬──────────┘   │ sin transcodificación     │   └─────────────┬──────────────┘
          │              └────────────▲─────────────┘                 │
          │                           │                               │
┌─────────▼───────────────────────────┴───────────────────────────────▼──────────────┐
│                                 P2P CONNECTOR (C++)                                             │
│                       única frontera con lo propietario (NetSDK/libP2P)                          │
│                    sesiones, keepalive, reconexión, estado Online/Offline                        │
└───────────────────────────────────────────────────────────────────────────────────────────────┘

Infra común: PostgreSQL (inventario/estado/eventos), Redis opcional, métricas (Prometheus opc.)
```

## 3. Equivalencias con DSS Pro (EV-001)

| DSS Pro | DSS V2 | Nota |
|---|---|---|
| CMS (Central Management) | Auth/User Manager + API Gateway | núcleo de sesión y control |
| DMS (Device Mgmt) | Device Manager + P2P Connector | inventario + conexión |
| SS (Storage) | Recording Engine | grabación centralizada |
| MTS (Media Transmission) | Video Engine | distribución de streams |
| ARS (Auto Register) | Device Manager (función registrar por SN) | re-registro P2P |
| ADS (Alarm Dispatch) | Event Engine | alarmas/eventos |
| PTS (Picture Transfer) | Event Engine (attachments) | snapshots de eventos |
| OSS (Object Storage) | Recording Engine (backend de storage, clean S3-like) | opcional en MVP |

## 4. Decisiones destacadas (link a ADRs)

- **C++** para el conector (integración nativa con NetSDK) y **Go** para servicios de gestión → ADR-0002.
- **PostgreSQL** para inventario/eventos/usuarios; **Redis** solo para estado efímero → ADR-0007.
- **Web RTC vs. HLS/WebSocket-MJPG:** elegirse por prueba sobre 100/300 canales (ADR-0008, pendientes).
- Sin GPU: no hay transcodificación en la huella base (ADR-0006).

## 5. Modelo de datos preliminar (MVP)

- `organizations(id, name, parent_id)`
- `devices(id, org_id, type[nvr|ipc], vendor, model, firmware, serial_number, connection_mode[p2p|ip], status, last_seen)` — SN único por org.
- `channels(id, device_id, index, name, stream_type, resolution, codec)`
- `credentials(id, device_id, username, secret_cipher_alg, secret_ciphertext)` — options; nunca plaintext (SECURITY).
- `sessions(id, user_id, issued_at, expires_at, revoked_at, ip_hash)` — auditoría.
- `events(id, device_id, channel_id, type, payload_json, created_at)` + índice temporal.
- `recordings(id, device_id, channel_id, start_at, end_at, container, storage_path, checksum)`.

## 6. Estados del conector (state machine)

```
     init ────► disconnected ────► connecting(p2p/ip) ────► connected
                   ▲                 │                       │
                   │   backoff       └─ error(autenticación o red)│
                   └─────────── reconnecting ◄───────────────────┘
```

- `connected > N s sin latido` → `reconnecting` (backoff exponencial, max jitter).
- Todo cambio de estado se publica al Event Engine y se persiste (auditoría).

## 7. API Gateway — superficie inicial (revisión en Fase 2)

```
POST /api/v1/auth/login | /logout | /refresh
GET  /api/v1/devices | /devices/:id | /devices/:id/channels
POST /api/v1/devices (add by SN+creds, cifradas)
GET  /api/v1/streams/:channelId (señalización WebRTC/WS)
GET  /api/v1/recordings?from=…&to=…&channel=…
GET  /api/v1/events (WS topic /ws/events)
GET  /api/v1/users | /roles | /orgs   (admin-only)
```

Detalle definitivo al diseñar cada módulo; nunca implementar endpoints no adheridos a evidencia.

## 8. Seguridad por diseño

Ver `docs/SECURITY.md` — controladores TLS, criterio por API, auditoría, y frontera de red.

## 9. Escalabilidad

Cada módulo despliegable por separado (containers); el conector puede multi-instancia (shard por
dispositivos). Diseño objetivo 100/300/500/1000 canales; numéricos en `docs/PERFORMANCE.md`.
