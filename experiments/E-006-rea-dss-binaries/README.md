# E-006 — Ingeniería inversa de DSS Client / DSS Server (.exe) con REA

Estado: EN EJECUCIÓN — inventario estático del DSS Client COMPLETADO (sin ejecución de
binarios); M-002 (Server V8.008) registrado; extracción estática del Server pendiente.

## Marco de cumplimiento
- Se analizan únicamente binarios obtenidos de instaladores oficiales de Dahua con licencia propia.
- Objetivo: interoperabilidad y documentación de protocolo (resolver §3 de DSS_CLIENT_RESEARCH).
- Prohibido: extraer claves/credenciales, bypassear activación, redistribuir binarios. Solo se
  publican hallazgos de PROTOCOLO/ARQUITECTURA, nunca dumps ni direcciones para explotación.
- Los .exe y sus dumps viven en `research/evidence/E-006/samples/` (fuera de git) con SHA-256.

## Setup de REA (Node 22+ local)
```bash
npx -y rea-agents@latest setup     # registra MCP + instrucciones para Claude Code/Codex...
rea --help
```
Análisis nativo (decompilación, `list_strings`) requiere un provider (Hopper / Ghidra / IDA /
Kuna). Sin provider corre (verificado en sesión 2026-10-30): `inspect_pe_imports`,
`inspect_pe_certificates`, `inspect_pe_load_config`, `inspect_pe_resources`,
`inspect_sqlite_database`, `inspect_native_exports`, `analyze-javascript-application`.

## Pasos
1. Registrar muestras (DSS Client instalador ejecutables, Server installer/services):
   SHA-256, versión, fuente (URL oficial), fecha — en `research/evidence/samples-manifest.md`.
2. Clasificación inicial con REA:
   - ¿Electron/nsis/Qt? → `analyze-javascript-application` (aplica si es JS/ASAR).
   - Imports PE de cada .exe (NetSDK? WinDivert? Crypto library? MySQL client?), cert Authenticode.
3. Mapeo de servicios servidor: procesos por servicio CMS/DMS/MTS/SS/… (EV-001) con los .exe reales.
4. Rastrear entrypoints de red (WinSock APIs; endpoints/puertos; SSL pinning si lo hay) y la capa de
   autenticación (login: hash challenge? token? cert?).
5. Cotejar con capturas (E-001): correlato estático ↔ dinámico.
6. Publicar: `docs/DSS_CLIENT_RESEARCH.md` (arquitectura del Client, endpoints, estado auth) +
   `docs/NETWORK_PROTOCOLS.md` (protocolo observado) con fichas EV nuevas en RESEARCH.md.

## Estado

### Toolchain (2026-10-30) — LISTO para la fase estática
- **REA v6.8.0** instalado con Node 26.13.0 dedicado (`C:\Users\bruno\Tools\dssv2\`), registrado
  como MCP en OpenCode V2.2.4 (`~/.config/opencode/opencode.jsonc`; backup `.rea.backup`) —
  `opencode mcp list`: `✓ rea connected` · catálogo: **229 herramientas MCP / 175 comandos CLI**.
- **Ghidra 12.1.4 instalado y healthy** (`C:\Users\bruno\Tools\dssv2\ghidra\ghidra_12.1.4_PUBLIC`,
  zip NSA oficial, SHA-256 `DDAC49F9…D4DB`; JDK 25.0.2 aceptado). Strings nativos y
  decompilación operativos vía CLI (`rea search` / `rea decompile`), validados con el
  launcher del Client (EV-022). Hopper/IDA/jadx/Kuna siguen sin configurar (innecesarios).
  Nota MCP: el servidor REA hereda el entorno al arrancar — **reiniciar OpenCode** para que
  el MCP vea `GHIDRA_INSTALL_DIR` (User env ya fijada).
- **frida** quedó con su post-install bloqueado por política npm (`allowScripts`): pendiente de
  aprobar solo si se necesitan sesiones dinámicas. No afecta esta fase.
- Evidencia: `research/evidence/E-006/rea-setup-20261030.md` (fuera de git) · EV-014 en RESEARCH.md.

### Clasificación estática del DSS Client (2026-10-30) — COMPLETADA
- **Veredicto (EV-016)**: Qt 5.15.13 C++ nativo Win64 + CEF embebido (Chromium 109.0.5414.120;
  `libcef.dll` 185.9 MB) + 15 módulos `*Logical.dll` cargados vía `QPluginLoader`.
  **No Electron, no .NET.**
- **Shell (EV-017)**: instalador NSIS PE32 x86 con pkcs7; extracción estática (7-Zip 26.05
  portable): 1254 archivos / 678 MB. `Version.xml` → `OverseasClient` / branch
  `release-20241213-AIO8.6.0` / commit `e5b1e036de4e…` / build 2025-03-07.
- **Hallazgo (EV-018)**: `ClientFramework` (23.6 MB, sin extensión) es una **base SQLite 3.54.0**
  de registro de plugins/UI — 9 tablas inspeccionadas a nivel esquema (sin filas).
- **Superficie SDK (EV-019)**: `netsdk.dll` v3.5.6.68586 (2034 exports) · `DPSDK.dll` (1363) ·
  `configsdk.dll` (5) · `P2PDll.dll` (8 exactas: P2P_Init/Connect/…). `DSS Client.exe` y
  `netsdk.dll` **sin firma**; el instalador sí lleva pkcs7.
- Bundle de evidencia: `research/evidence/dss-evidence-local.json` +
  `research/evidence/E-006/dssclient-static-inventory-20261030.md` (fuera de git).

### Material
- **DSS Client**: instalador oficial disponible localmente — SHA-256
  `A0138D2ED3228F0F75A37C5E72C126B9CD8F727F7516CB5744BEC691D42792C9` registrado en
  `research/evidence/samples-manifest.md` (fuera de git; nunca versionar el binario).
- **DSS Server**: M-002 verificado (EV-020). Shell del instalador caracterizado (EV-021):
  stub PE32 x86 ~205 KB (imphash-md5 `5e48fbae…`, con `ole32`) + **overlay propietario**
  (magic `93 FB 69 5A`, 1.73 GB) **firmado por Dahua** (DigiCert G4, cadena verificada
  localmente; leaf CN="Zhejiang Dahua Technology Co., Ltd."). Pendiente: decodificar el
  overlay + inventario interno de servicios (sin ejecución).

