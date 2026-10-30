# E-003 — Observación del P2P cloud y alternativas oficiales

Estado: PLANIFICADO

## Fase A — Observación pasiva (produccion débil no intrusiva)
- Capturar DNS/hosts del NVR mientras regist SN en nube P2P (config por IT, sin alterar producción).
- Correlate dominios: easy4ip.com / dahuap2p.com / otros (coincider con EV-006).
- Capturar una sesión P2P de un cliente autorizado con device PROPIO (SmartPSS/DMSS en lab) para
  caracterizar el túnel: UDP vs TCP vs relay (solo tamaño/frecuencia, sin descifrar contenido).
- Registro: `research/evidence/E-003/…` + actualizar `docs/NETWORK_PROTOCOLS.md`.

## Fase B — Ruta oficial (DoLynk / Partner)
- Consultar Dahua (partner/maestro regional) por: (1) programa Partner DSS Integration (EV-008),
  (2) disponibilidad de SDK Linux P2P oficiallicensed (NDA si aplica), (3) OpenAPI de DoLynk Dev
  (EV-009) y su aplicabilidad a NVR enterprise detrás de NAT.
- Documentar respuestas con fuente oficial y fecha.

## Criterio de éxito
- Lista verificada de endpoints cloud observados por dispositivo PROPIO y de la ruta oficial
  viable (o certificación documentada de su inexistencia).
