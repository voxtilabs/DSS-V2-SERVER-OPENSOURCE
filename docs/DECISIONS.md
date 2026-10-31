# DECISIONS.md — Decisiones arquitectónicas (ADR)

Formato: ADR-XXXX · Status · Fecha · Contexto · Decisión · Consecuencias.

---

## ADR-0001 — Modularidad como requisito
- Status: aceptada · Fecha: 2026-10-30
- Contexto: el proyecto necesita reemplazar gradualmente DSS Pro (V7/V8, EV-001); cada servicio del
  appliance tiene funcionalidad separable.
- Decisión: ocho módulos desacoplados (ver `docs/ARCHITECTURE.md`), cada uno deployable aislado con
  contrato de API.
- Consecuencias: cada frontend consume módulos por su API; migración parcial posible.

## ADR-0002 — Stack: C++ para conector, Go para servicios
- Status: aceptada · Fecha: 2026-10-30
- Contexto: NetSDK es una librería nativa C (EV-004); Go brinda servicios rápidos de desarrollar con
  buena concurrencia para APIs/dat, evitando GC en el video path.
- Decisión: conector C++ (carga NetSDK), Device/Gateway/etc. en Go; interfaz definida por gRPC/REST
  interno.
- Consecuencias: dos toolchains; tests separados; cross-compile Linux x64. Cuidar glibc en Ubuntu
  24.04 para el conector.

## ADR-0003 — Licencias y límites de ingeniería inversa
- Status: aceptada · Fecha: 2026-10-30
- Contexto: la meta requiere entender protocolos propietarios (P2P, DSS Client↔Server) pero hay
  EULA/legislación aplicable; REA excluye cracking (su propio disclaimer).
- Decisión: análisis solo sobre instalaciones propias con licencia válida; sin elusión de la
  activación; sin redistribución de binarios; sin extraer secretos incrustados; publicación solo de
  hallazgos de protocolo/documentación de interoperabilidad.
- Consecuencias: algunos descubrimientos no se documentan si su naturaleza es "cómo romper"; rutas
  propietarias pueden bloquear manera formal → registrado con alternativas (P2P_RESEARCH §2).

## ADR-0004 — No reutilización de secretos de app De Dahua
- Status: aceptada · Fecha: 2026-10-30
- Contexto: los PoCs comunitarios (EV-005/EV-006) incidieron en credenciales fijas delegadas a
  SmartPSS/DMSS frente a la nube De Dahua.
- Decisión: DSS V2 no incluye esos identificadores ni credenciales en código. Cualquier acceso a la
  nube de Dahua con credenciales de aplicación requiere (a) credenciales
  propias obtenidas de Dahua o (b) revisión legal + solo laboratorio.
- Consecuencias: ruta D (reimplementación de P2P) restringida; prioridad a ruta oficial (A/B/C).

## ADR-0005 — Postgres + Redis opcional
- Status: aceptada · Fecha: 2026-10-30
- Contexto: DSS V7 usa MySQL (EV-002) pero MySQL no es requisito del proyecto; necesitasmos
  integridad/transaction para events + búsquedas temporales.
- Decisión: PostgreSQL para recursos persistentes; Redis para estado efímero/semáforo (opcional en
  MVP); nada en documentación de producción a modo.

## ADR-0006 — Sin GPU en la fase inicial
- Status: aceptada · Fecha: 2026-10-30
- Contexto: sin transcodificación ni IA en el MVP, GPU es inútil (instrucción del mandate).
- Decisión: CPU-only; WEB RTC passthrough RTP, plugins para decode en el client (WebRTC).
- Consecuencias: menor capex; revisión cuando se incorpore mote-deteción o transcodificación.

## ADR-0007 — Web Client propio + adaptador DSS opcional
- Status: aceptada · Fecha: 2026-10-30
- Contexto: compatibilidad con DSS Client no garantizada (EV-007/EV-008); Web Client necesario.
- Decisión: React+TS; todo flujo de operación vía API Gateway; adaptador DSS separado solamente si
  hay evidencia de una extensión limpia.

## ADR-0008 — Evidencia como gorila de verdad
- Status: aceptada · Fecha: 2026-10-30
- Contexto: proyecto basado en investigación de protocolos; requiere hechos y reproducibilidad.
- Decisión: `docs/RESEARCH.md` como registro único con clasificación de confianza obligatoria; este
  repositorio nunca versiona evidencia cruda (solo local, ver política de evidencia en README).


## ADR-0009 — Conector P2P: implementación propia sobre PTCP/Tou con PoC MIT como referencia
- Status: aceptada · Fecha: 2026-10-30 · Contexto: EV-031 (P2PDll decompilado: libTouProxy, 8 exports, puerto local tunelado) y EV-032 (lookup easy4ip por HTTPS/SOAP en DPSDK).
- Decisión: no redistribuir ni integrar P2PDll.dll (licencia, ADR-0004); reimplementación propia del lookup cloud (HTTPS+SOAP) + túnel PTCP/Tou + forwarding de puerto local, usando el PoC MIT dh-p2p (EV-006) como referencia técnica abierta. Fases: A (lookup + PTCP), B (fallback relay), C (exposición dentro del servidor DSS V2).
- Consecuencias: control y auditoría del cable propios; los detalles de protocolo pendientes se resuelven en E-008 con captura dinámica sobre SN legítimo de laboratorio; en paralelo el servidor DSS V2 debe cumplir ya el subconjunto BRMS/MTS de EV-029/EV-030 para servir al Client original.


## ADR-010 — PoC BRMS Gateway y P2P Probe como código ejecutable en el repo
- Status: aceptada · Fecha: 2026-10-30 · Contexto: EV-037 (contratos completos), EV-038/039 (scaffolding PoC).
- Decisión: mantener `poc/dss-v2-harness/` como código fuente del proyecto (MIT), con tests automatizados en CI. El Mock Gateway valida la compatibilidad con el Client original sin ejecutar binarios Dahua; el P2P Probe documenta el contrato SOAP/PTCP para futura reimplementación (ADR-0009).
- Consecuencias: CI ejecuta `npm test` en ambos submódulos en cada push; la cobertura de handshake MD5 y endpoints es obligatoria para merge.
## ADR-011 — PoC Harness como código de referencia en repo (MIT)
- Status: aceptada · Fecha: 2026-10-31 · Contexto: EV-042/043/048 (PoC funcional con tests).
- Decisión: mantener `poc/dss-v2-harness/` como código fuente del proyecto (licencia MIT), con `npm test` obligatorio en CI. El Mock Gateway valida compatibilidad DTO 1:1 con Client original; el P2P Probe documenta el contrato SOAP/PTCP para futura reimplementación nativa (ADR-0009).
- Consecuencias: CI ejecuta `npm test` en `brms-gateway/` y `p2p-probe/` en cada push; cobertura de handshake MD5, DTO contracts y alarm UDP es obligatoria para merge.
## ADR-012 — PTCP/Tou Reimplementation in Node.js for PoC
- Status: aceptada · Fecha: 2026-10-31 · Contexto: EV-049/050 (vtable + state machine documentados).
- Decisión: reimplementar protocolo PTCP/Tou en Node.js (`poc/dss-v2-harness/p2p-probe/`) usando `dgram` (UDP) + máquina de estados explícita, en lugar de binding a `libTouProxy.dll` (licencia, ADR-0004).
- Detalles: handshake `HELLO/CHALLENGE/RESPONSE` sobre UDP, `createLocalPort` bind `127.0.0.1`, keepalive 30s, forwarding bidireccional `dgram`. JSON `jsonDevInfo` para device info.
- Consecuencias: control total del cable, auditoría posible; requiere validación con SN legítimo en laboratorio (E-011).

## ADR-013 — WebSocket + Mock RTSP en brms-gateway
- Status: aceptada · Fecha: 2026-10-31 · Contexto: EV-052 (MTS/RTSP + WebSocket events).
- Decisión: añadir servidor WebSocket (`ws`) en `brms-gateway` para eventos tiempo real y mock RTSP 9100 con validación token para compatibilidad MTS.
- Detalles: WebSocket endpoint `/event/ws` broadcast eventos UDP 18800; mock RTSP valida `?token=` y responde `OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN` con SDP H.265 mock.
- Consecuencias: permite probar cliente DSS contra gateway mock sin hardware real; `docker-compose.yml` para despliegue reproducible.
