# ROADMAP.md — Fases y puertas de avance

Regla del proyecto: **no se inicia una fase sin evidencia que apruebe la puerta de la anterior.**

---

## Fase 0 — Investigación y fundación (ACTUAL)

Objetivo: bases técnicas verificables.

| Tarea | Estado |
|---|---|
| Inspección de entorno dev (Win: git/python/node/docker) | HECHO |
| Investigación documental oficial (DSS/NetSDK/DoLynk/Partner) | HECHO (ledger EV-001..13) |
| Definición de arquitectura, roadmap, seguridad, rendimiento, decisiones | HECHO |
| Análisis estático DSS Client/Server .exe con REA | Pendiente E-006 |
| Capturas de laboratorio protocolo Client↔Server | Pendiente E-001 |
| Validación NetSDK Linux x64 en Ubuntu 24.04 | Pendiente E-002 |
| Observación cloud P2P + fases DoLynk | Pendiente E-003 |
| Inventario API oficial DSS V8 | Pendiente E-004 |

**Puerta 0→1:** informe de evidencia firmado en `docs/RESEARCH.md` + al menos una conexión de video
empezada con método identificado (NetSDK o alternativo), documentada en E-002.

## Fase 1 — PoC: DSS V2 P2P CONNECTOR

Objetivo: demostrar conectividad real, video real.

Deliverables:
- Binary conector (C++) con estado y métricas exposed vía HTTP interno.
- Prueba end-to-end: NVR remoto detrás de NAT → video en el server.
- Registro persistit auditoria de intentos/estados.

**Criterio de aceptación (del prompt maestro):** un NVR remoto ubicado detrás de NAT debe poder
conectarse a Ubuntu por el método validado, y debe recibirse video real. Nada de fake-RTSP local
vendido como P2P.

## Fase 2 — Núcleo VMS mínimo

- Device Manager (CRUD, inventario, credenciales cifradas).
- Video Engine (distribución, multiplico clientes).
- Recording Engine (segmentar, índice temporal, retención, recuperación).
- Event Engine (alarmas, historial).
- Auth & User Manager (usuarios/roles/organizaciones, sesiones).
- API Gateway (REST + WS, TLS, rate lim).
- Tests automatizados por módulo; despliegue Ubuntu 24.04 con docker-compose.

**Puerta 2→3:** demo completa con ≥2 organizaciones, ≥8 canales reales, alarm activa, playback con
seek correcto.

## Fase 3 — Web Client

- React+TS: dashboard, inventario, live, multiview, playback, alarmas, admin.
- Video: WebRTC si supera prueba (latencia/compatibilidad); fallback HLS/WS*.

**Criterio:** operador no técnico completa toda la operación sin manual.

## Fase 4 — Escala y robustez

- Líneas 100 → 300 → 500 → 1000 canales con benches reales.
- Multi-instancia con shard, failover, backups, monitoreo.
- Revisar `docs/PERFORMANCE.md` con datos reales, no presunciones.

## Fase 5 — Compatibilidad DSS Client (opcional, aislada)

- Solo si E-004/E-001 arrojan un protocolo/API alcanzable de forma limpia.
- Componente separado `dss-compat-adapter`, sin acoplamiento core; acceso controlado.

---

Principios transversales: cambios pequeños; cada PR pasa CI; documentación actualizada en el mismo
commit; si algo bloquea, se registra exactamente qué (en RESEARCH.md) con alternativas pendientes.
