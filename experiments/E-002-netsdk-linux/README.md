# E-002 — Validación de NetSDK Linux x64 en Ubuntu 24.04

Estado: PLANIFICADO

## Objetivo
Probar mediante código propio (C++): ¿el NetSDK oficial para Linux funciona en Ubuntu 24.04 x86_64
contra nuestro NVR (login, canales, video, eventos)? ¿Expone algún entrypoint P2P utilizable?

## Pre-requisitos
- Ubuntu Server 24.04 LTS (VM o bare-metal).
- Binarios NetSDK Linux-x64 oficiales obtenidos por canal legítimo; registrar SHA-256 y fuente en
  `research/evidence/sdk-manifest.md` (fuera de git).
- NVR de laboratorio accesible por red; credenciales de prueba.

## Pasos
1. Proyecto mínimo `components/p2p-connector/netsdk_probe/` (compile con CMake) cargando `libdhnetsdk.so`.
2. Secuencia API mínima: `CLIENT_Init` → `CLIENT_LoginEx2` → `CLIENT_QueryDevInfo`/channels →
   `CLIENT_RealPlay` (guardar 10 s de stream) → `CLIENT_Logout` → `CLIENT_Cleanup`.
3. Grep del header `dhnetsdk.h` (y `dhconfigsdk.h`) con términos `P2P|PTCP|Easy4IP|Cloud|EMSpecCap`
   para inventariar funciones relacionadas; verificar firma/comportamiento solo con dispositivos PROPIOS.
4. Test repetido en loop (50 veces): tasa de éxito, latencia login, re-conexión tras latidos fallidos.

## Entregables
- Reporte en este directorio + actualización de `docs/DAHUA_COMPATIBILITY.md` (matriz) y de EV-004.

## Criterio de éxito
- Login y `RealPlay` funcionan y se reciben framestream H.264/H.265 reales (ffprobe valida stream).
- Resultado P2P documentado (positivo o negativo con error específico).
