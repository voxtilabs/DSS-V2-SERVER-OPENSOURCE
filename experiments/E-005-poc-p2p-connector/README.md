# E-005 — PoC: DSS V2 P2P CONNECTOR

Estado: PLANIFICADO — arranca cuando E-002/E- entregan un método de conexión validado.

## Objetivo (criterio del prompt maestro)
> Un NVR remoto ubicado detrás de NAT debe poder conectarse desde Ubuntu con el método VALIDADO,
> y debe recibirse video real.

## Diseño del PoC (según método validado)
| Caso | ¿Existe método validado? | Plan |
|---|---|---|
| 1 | NetSDK con RUTA P2P activa (E-002 positivo) | Conector C++ sobre NetSDK directo |
| 2 | Ruta oficial externa (DoLynk/Partner, E-003-B) | Conector via OpenAPI oficial |
| 3 | Sin ruta oficial → laboratorio | Cliente propio de P2P basado en hallazgos reproducidos,
     SIN secretos De Dahua; alcance: demo técnica con revisión legal previa |

## Alcance del PoC (componente Go + binario C++)
- Inicialización / registro SN / autenticación / conexión / estado online-offline / consulta de
  canales / recepción de video / desconexión / reconexión / registro de errores / métricas.
- REST interno :8089 con estado (Prometheus-text), logs con auditoria por intento.
- NADA de RTSP local vendido como "P2P": el resultado debe acreditar la ruta usada.

## Reglas
- Credenciales dispositivo: usuario+password SIEMPRE; guardadas cifradas (AES-GCM).
- Cada intento P2P con Backoff exponencial y techo; jamás saturar la nube.
- Métrica "path": p2p-native | p2p-relay | vpn-fallback | direct — un stream sin tag de path es un
  defecto; no lo entregue.

## Criterio de aceptación (para registrar el ÉXITO en RESEARCH.md)
1. NVR detrás de NAT en red doméstica sin IP pública.
2. Server Ubuntu 24.04 en datacenter/red distinta (no mismo ISP que el NVR).
3. Conexión sustentada ≥ 30 min con reconexión automática tras cable del WAN del NVR.
4. Video real: reconocimiento con ffprobe (codec/resolución) + checksum visual (2 frames diferentes).
5. Reporte con evidencia (captura, logs) en research/evidence/E-005/ y status FINAL aquí.
