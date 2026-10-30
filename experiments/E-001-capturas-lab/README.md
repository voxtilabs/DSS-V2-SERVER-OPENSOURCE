# E-001 — Capturas de laboratorio: DSS Client ↔ DSS Server y dispositivos

Estado: PLANIFICADO (requiere acceso al laboratorio)

## Objetivo
Documentar el comportamiento de red real de DSS Client contra un DSS Server en laboratorio, y del
NVR frente al appliance. Nada de capturas en producción.

## Pre-requisitos
- Red de laboratorio aislada (switch administrable + port mirroring o NIC con analysis port).
- Server DSS (instalado con licencia/trial) + PC Windows con DSS Client + NVR Dahua de prueba.
- Wireshark instalado; reloj sincronizado (NTP interno).

## Procedimiento
Seguir `docs/DSS_CLIENT_RESEARCH.md` §Playbook fase 3. Capturar cada operación POR SEPARADO
(iniciar/parar la captura alrededor de cada acción; nombrar archivos `op-NN-<situación>.pcapng`):

1. inicio-client    2. login-success    3. lista-dispositivos
4. live-view-1ch    5. multiview-4ch    6. playback-seek
7. nvr-desconectado 8. nvr-reconectado  9. alarma-(movimiento)

## Qué extraer de cada captura
- IP origen/destino, puertos, protocolos (TCP/UDP/TLS), duración, frecuencia, tamaño de paquetes.
- DNS consultado. Conexiones persistentes (keepalive detection).
- Servicios identificados (matched vs. tabla EV-002 de V7).
- Indicadores de cifrado (TLS handshake? versión? cert).

## Entregables
- `research/evidence/E-001/*.pcapng` + notas (fuera de git).
- Actualización de: `docs/NETWORK_PROTOCOLS.md`, nuevas fichas en `docs/RESEARCH.md`.

## Criterio de éxito
Tráfico de cada operación mapeado a servicio/puerto con lado servidor identificado, y el conjunto de
puertos replicable (dos corridas sie el mismo resultado).
