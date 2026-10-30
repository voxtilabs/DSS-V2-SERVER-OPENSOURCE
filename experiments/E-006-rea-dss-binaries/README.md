# E-006 — Ingeniería inversa de DSS Client / DSS Server (.exe) con REA

Estado: PLANIFICADO —kit: REA (https://github.com/morluto/rea, MIT) como MCP/CLI de análisis.

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
Análisis nativo moderno requiere un provider (Hopper / Ghidra / IDA / Kuna) — instalar el que
corresponda según `rea.tools` docs. Para PE estático rápido no se requiere provider
(`inspect_pe_imports`, certificados, `analyze-javascript-application`, strings).

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
- **Motores nativos no configurados** (Ghidra/Hopper/IDA/jadx/Kuna): sin ellos corre todo el
  inventario estático (imports PE, certificados, load config, recursos, strings, overview,
  Electron/ASAR). El análisis profundo nativo (decompilación) requiere Ghidra 12.1.x + JDK ≥21
  instalados por el operador (en Windows REA ≥4.1 incluye bundle nativo; frontera P0 experimental).
- **frida** quedó con su post-install bloqueado por política npm (`allowScripts`): pendiente de
  aprobar solo si se necesitan sesiones dinámicas. No afecta esta fase.
- Evidencia: `research/evidence/E-006/rea-setup-20261030.md` (fuera de git) · EV-014 en RESEARCH.md.

### Material
- **DSS Client**: instalador oficial disponible localmente — SHA-256
  `A0138D2ED3228F0F75A37C5E72C126B9CD8F727F7516CB5744BEC691D42792C9` registrado en
  `research/evidence/samples-manifest.md` (fuera de git; nunca versionar el binario).
- **DSS Server**: instalador pendiente de obtener — descargar el instalador oficial
  (DSS Ultimate V8.8 en dahuasecurity.com) y registrar igualmente en el manifest (M-002).

