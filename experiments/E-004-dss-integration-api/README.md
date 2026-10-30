# E-004 — Inventario de la API oficial de integración de DSS V8

Estado: PLANIFICADO

## Objetivo
Determinar qué expone de forma oficial un server DSS V8 para integraciones de terceros (HTTP API,
SDKs, plugins), como línea base de compatibilidad y como referencia de lo que DSS V2 debe cubrir.

## Pasos
1. Obtener documentación oficial de la API de integración (control vía cuenta partner o
   distribución oficial; referencia suplemental: EV-007).
2. En laboratorio con DSS V8 (licencia de prueba): validar los endpoints clave:
   - autenticación/tokens, lista devices/canales, live (URL/WEs), playback (URL/funciones),
     eventos/alarms, gestión usuarios/organizaciones.
3. Comparar con la tabla de funcionalidades del Web Client.

## Entregables
- `docs/DSS_CLIENT_RESEARCH.md` tabla nueva "Superficie oficial V8 vs Web Client".
- Verdicts de viabilidad del `dss-compat-adapter` preliminar.

## Criterio de éxito
Ficha API con endpoints confirmados (curl reproducible con tokens de prueba) o conclusión
documentada de que la API no está disponible publicly.
