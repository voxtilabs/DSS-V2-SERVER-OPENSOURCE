# DSS V2 OPEN SOURCE

Plataforma VMS (Video Management System) independiente, escalable y de código abierto para administrar dispositivos Dahua (y gradualmente otros fabricantes), **sin depender de una instalación licenciada de Dahua DSS Professional**.

> Estado actual: **Fase 0 — Investigación y fundación** (ver `docs/ROADMAP.md`).
> Regimen de trabajo: evidencia primero, código después. Ver `docs/RESEARCH.md`.

## Principios rectores

1. Investigar antes de implementar. Ninguna hipótesis se convierte en afirmación técnica sin verificación.
2. No inventar protocolos, endpoints, puertos ni APIs. Toda afirmación lleva clasificación de confianza:
   `CONFIRMADO · PROBABLE · HIPÓTESIS · NO VERIFICADO · DESCARTADO`
3. Priorizar documentación oficial y SDK legítimos. Ingeniería inversa solo sobre equipos y software propios / autorizados.
4. No eludir licencias, autenticación, cifrado ni controles de acceso. No reutilizar secretos/credenciales de software propietario.
5. Componentes independientes separados de componentes propietarios (regla de frontera).
6. No destruir ni modificar la infraestructura DSS original (el appliance DSS7016D de producción NO es banco de pruebas).
7. Cada módulo con pruebas automatizadas; cambios pequeños, verificables y reversibles.
8. Nunca simular resultados para aparentar progreso.

## Objetivo mínimo viable (MVP)

> Un NVR Dahua ubicado detrás de NAT, registrado por número de serie, debe poder conectarse desde Ubuntu Server 24.04 con un conector propio (P2P Connector) por un método **validado**, y debe recibirse video real. Voz y datos reales; nada de simulación en producción.

## Estructura del repositorio

```
DSS V2 OPEN SOURCE/
├── README.md                    ← este archivo
├── LICENSE                      ← licencia del proyecto (nota SDK: ver abajo)
├── .gitignore
├── docs/                        ← documentación obligatoria del proyecto
│   ├── ARCHITECTURE.md          ← arquitectura inicial propuesta
│   ├── ROADMAP.md               ← fases, puertas de avance (gates)
│   ├── RESEARCH.md              ← registro central de evidencias (ledger)
│   ├── DAHUA_COMPATIBILITY.md   ← SDK, versiones, matriz de compatibilidad, licencias
│   ├── P2P_RESEARCH.md          ← investigación P2P (ruta oficial vs. protocolo observado)
│   ├── DSS_CLIENT_RESEARCH.md   ← protocolo cliente-servidor DSS, APIs de integración
│   ├── NETWORK_PROTOCOLS.md     ← protocolos y puertos observados/documentados
│   ├── SECURITY.md              ← modelo de amenazas y controles
│   ├── PERFORMANCE.md           ← modelo de ancho de banda, almacenamiento, escalado
│   └── DECISIONS.md             ← ADRs (decisiones arquitectónicas)
├── experiments/                 ← experimentos planificados y ejecutados
│   ├── TEMPLATE.md              ← plantilla de informe de experimento
│   ├── E-001-capturas-lab/      ← capturas de tráfico (DSS Client, NVR, DSS Server)
│   ├── E-002-netsdk-linux/      ← validación de NetSDK Linux x86_64 en Ubuntu 24.04
│   ├── E-003-p2p-cloud/         ← observación del servicio P2P en producción (pasivo)
│   ├── E-004-dss-integration-api/ ← API oficial de integración de DSS V8
│   └── E-005-poc-p2p-connector/ ← primera prueba de concepto del conector
├── research/
│   └── evidence/                ← material de evidencia (capturas, logs, fichas). NUNCA a git.
├── components/                  ← código fuente por módulo (solo se crea cuando hay evidencia)
│   ├── p2p-connector/           ← C++ (SDK nativo) + Go (servicios) — placeholder hasta Fase 1
│   ├── device-manager/
│   ├── video-engine/
│   ├── recording-engine/
│   ├── event-engine/
│   ├── auth-user-manager/
│   ├── api-gateway/
│   ├── web-client/
│   └── dss-compat-adapter/      ← experimento aislado; nunca dependencia del núcleo
```

## Stack objetivo (provisorio, ver `docs/DECISIONS.md`)

- **Device/P2P layer:** C++ (integración NetSDK nativo), servicios de gestión en **Go**.
- **Persistencia:** PostgreSQL (inventario/estado/eventos), **Redis opcional** (estado efímero).
- **Video:** transmisión sin transcodificación (FFmpeg/GStreamer en "tubería ligera").
- **API:** REST + WebSocket en gateway único con TLS.
- **Web Client:** React + TypeScript; video vía WebRTC cuando corresponda (verificado experimentalmente).
- **Target de despliegue:** Ubuntu Server 24.04 LTS.

## Política de almacenamiento de evidencia y SDK

- Las capturas, logs y datos de dispositivos NUNCA se publican en git (`research/evidence/` está en `.gitignore`).
- Los binarios del SDK oficial de Dahua nunca se commitean en este repositorio: se almacenan de forma privada, con registro de versión, SHA-256 y fuente en `docs/DAHUA_COMPATIBILITY.md`.
- Cualquier material de terceros (PoCs comunitarios) se trata como pista de investigación con cita, no como base de producción.

## Cómo se trabaja una tarea (metodología del agente)

1. Inspeccionar repo → 2. leer `RESEARCH.md`/`DECISIONS.md` → 3. definir objetivo → 4. diseñar → 5. implementar → 6. probar → 7. documentar evidencia → 8. informar. Si algo no se puede completar, se documenta exactamente qué bloquea y qué alternativas existen.
