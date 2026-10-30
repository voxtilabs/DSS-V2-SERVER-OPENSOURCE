# PERFORMANCE.md — Modelo de rendimiento y escalado

Regla: nunca dimensionar "por cantidad de cámaras" a ciegas. Todo cálculo usa bitrate real del canal.
Los valores por defecto de este documento son **estimaciones de diseño**: se sustituyen por
mediciones reales en cada fase (E-002/E-003/benches) y se registran con fecha.

## 1. Modelo de ancho de banda (planificación)

Supuestos iniciales (calificar en laboratorio):
- Sub-stream 720p H.264 ≈ 1–2 Mbps
- Main-stream 1080p H.264 ≈ 2–4 Mbps
- Main 4MP H.265 ≈ 2–4 Mbps
- Main 4K H.265 ≈ 6–12 Mbps

Ejemplo inicial (100 canales de main-stream 1080p con 4 Mbps estimados):
- Grabar todos: 100 × 4 Mbps = 400 Mbps de entrada ≈ 50 MB/s ≈ 4.0 TB/día.
- Consecuencia hardware: NIC de 1 Gbps es insuficiente si se graba todo → plan 10 GbE.
- Re-emisión: 5 operadores × 4 tiles ≈ 80 Mbps de salida del Media/Video Engine.

## 2. Modelo de almacenamiento

```
espacio (bytes) = canales × bitrate_Bps × retención_s
                 = canales × (Mbps × 125000) × (días × 86400)
```
Ejemplo: 100 ch × 4 Mbps (500 kB/s) × 30 días ≈ 129.6 TB.

Estrategias de reducción (por definir con evidencia): grabación por eventos, conversión a H.265,
retención escalonada, QP fijo en cámaras.

## 3. Concurrencia y CPU

- Sin transcodificación en el MVP: distribución RTP directo a WebRTC/HLS cuando sea posible.
- Objetivo inicial: 300 canales provisionados, 30 activos, 10 operadores × 4 tiles en vivo.
- CPU esperada del stack Go (API/eventos) + C++ (conector): por medir en E-005/Fase 2 — no se
  presumen valores.

## 4. Escalado multi-servidor

Fase 4: shards conector (p. ej. 100–200 dispositivos por instancia), réplicas de lectura en DB,
brókers regionales para video. Despliegue inicial con docker-compose; Kubernetes opcional después.

## 5. Registro de benches

Todo benchmark se persiste en `research/evidence/bench-YYYYMMDD.md` con: fecha, hardware, versión,
y workflow de prueba. Este documento solo cita resultados medidos; no se publican suposiciones como
mediciones.
