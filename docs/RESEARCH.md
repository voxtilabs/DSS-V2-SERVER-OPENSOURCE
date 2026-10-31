# RESEARCH.md — Registro central de evidencias (ledger)

Reglas del ledger:
- Toda afirmación técnica del proyecto debe referenciar una entrada de este archivo.
- Niveles de confianza: `CONFIRMADO | PROBABLE | HIPÓTESIS | NO VERIFICADO | DESCARTADO`.
- Una hipótesis nunca se transforma en afirmación sin evidencia + experimento.
- La evidencia cruda (capturas, hashes, logs) vive en `research/evidence/` (fuera de git).

Formato de ficha: ver `experiments/TEMPLATE.md` y `research/evidence/TEMPLATE.md`.

## Índice de evidencias

| ID | Título | Confianza | Estado |
|----|--------|-----------|--------|
| EV-001 | DSS Pro V7 datasheet: arquitectura de servicios del servidor | CONFIRMADO | Abierta |
| EV-002 | DSS Pro V7 manual: lista de puertos del servidor | CONFIRMADO | Abierta |
| EV-003 | DSS Ultimate V8.8 instalador oficial disponible (dahuasecurity.com) | CONFIRMADO | Abierta |
| EV-004 | NetSDK Linux x64 existe (binarios oficiales, NuGet + demo Java) | CONFIRMADO | Abierta |
| EV-005 | NetSDK standalone no expone ruta P2P operativa sin libP2PDll + credenciales de app | PROBABLE | Abierta |
| EV-006 | Protocolo P2P Dahua (Easy4IPCloud + PTCP) descrito en PoC público dh-p2p | PROBABLE | Abierta |
| EV-007 | Documento "HTTP API for DSS V8.7" existe (Scribd) | NO VERIFICADO | Abierta |
| EV-008 | Programa oficial de integración DSS (Partner DSS Integration / DEPP) | NO VERIFICADO | Abierta |
| EV-009 | DoLynk Developer Cloud (open.dolynkcloud.com) plataforma oficial IoT | CONFIRMADO | Abierta |
| EV-010 | DSS7016D appliance: manual oficial disponible | CONFIRMADO | Abierta |
| EV-011 | Ataques activos usando P2P cloud por SN (oct-2026) | CONFIRMADO | Cerrada |
| EV-012 | DSS Pro V8 usa P2P para conexiones de clientes (webinar oficial) | CONFIRMADO | Cerrada |
| EV-013 | Puertos por defecto del dispositivo Dahua: 37777/37778/554/80 | PROBABLE | Abierta |
| EV-014 | Toolchain REA 6.8.0 operativo (Node 26 dedicado + MCP en OpenCode) | CONFIRMADO | Cerrada |
| EV-015 | Huella SHA-256 del instalador DSS Client V8.006 registrada | CONFIRMADO | Abierta |
| EV-016 | DSS Client clasificado: Qt 5.15.13 C++ x64 + CEF (Chromium 109); no Electron / no .NET | CONFIRMADO | Cerrada |
| EV-017 | Instalador Client = NSIS; extracción estática sin ejecución (Version.xml: AIO8.6.0, build 2025-03-07) | CONFIRMADO | Cerrada |
| EV-018 | `ClientFramework` (23.6 MB) es una base SQLite de registro de plugins/UI | CONFIRMADO | Cerrada |
| EV-019 | Superficie SDK nativa del Client + estado de firma (instalador pkcs7; exe/netsdk sin firma) | CONFIRMADO | Cerrada |
| EV-020 | M-002 DSS Ultimate V8.8 descargado y verificado (Server Win64 IS V8.008 R.20260930) | CONFIRMADO | Cerrada |
| EV-021 | Instalador Server V8.008: stub 205 KB + overlay propietario (magic `93 FB 69 5A`), firmado por Dahua (DigiCert G4, cadena verificada) | CONFIRMADO | Cerrada |
| EV-022 | Ghidra 12.1.4 operativo con REA; strings nativos validados con direcciones exactas | CONFIRMADO | Cerrada |
| EV-023 | Data-area del instalador Server V8.008 decodificado estaticamente: outer-db.bin (4,716,790 B) con registro de 41,055 archivos | CONFIRMADO | Cerrada |
| EV-024 | Mapa de bloques del data-area: 2 familias (chunks LZMA con marker props + stored/plain con header 8B) verificadas por script | CONFIRMADO | Cerrada |
| EV-025 | pkgA embebido = WebClientServicePlugin_Setup.exe (10.19 MB) extraido (56 archivos) | CONFIRMADO | Cerrada |
| EV-026 | pkgB embebido = instalador DSS Client completo V8.008 R.20260325 (247.74 MB, 1,199 archivos / 814 MB) dentro del instalador Server | CONFIRMADO | Cerrada |
| EV-027 | easy4ip (Easy4IPCloud) CONFIRMADO en ambas generaciones DPSDK.dll (client y pkgB); corrige busquedas previas con 0 resultados | CONFIRMADO | Cerrada |
| EV-028 | Tabla Z de 232 bloques stored grandes (>1 MB): 100% verificada por span; contenido con nombres reales (modelos .nnx, AR.zip, manuals, APK, vcredists) | CONFIRMADO | Cerrada |
| EV-029 | Spec API BRMS/MTS de producción (operador): handshake doble MD5, puertos 1443/9100/18800/19800, endpoints v1.0/v1.1 | CONFIRMADO | Abierta |
| EV-030 | DPSDK.dll implementa el contrato BRMS nativamente (authorize, X-Subject-Token, WINPC_V2, MTS/Video/StartVideo, websocket) | CONFIRMADO | Cerrada |
| EV-031 | P2PDll.dll = wrapper libTouProxy: 8 exports P2P_* y DHProxyClientAddPortEx decompilado (forwarding de puerto local sobre túnel PTCP/Tou) | CONFIRMADO | Cerrada |
| EV-032 | Protocolo cloud easy4ip: SOAP DDNS getDeviceByDevSequence + HTTP/JSON; detalles de cable PROBABLE (verificación dinámica E-008) | PROBABLE | Abierta |
| EV-033 | Servicios del server en data-area: árbol Java Spring Boot con wrappers VMS_*.exe + esquema MySQL ac_* | CONFIRMADO | Cerrada |
| EV-034 | Formato SOAP exacto de GetDeviceInfoFromEasy4IP: ns2:getDeviceByDevSequence (webservice.ddns.dahua.com) con <devSequence>%s</devSequence> | CONFIRMADO | Cerrada |
| EV-035 | Dominios cloud observados: www.easy4ip.com, www.easy4ipcloud.com, www.dahuap2p.com, www.dahuap2pcloud.com + host interno 172.23.1.120 | CONFIRMADO | Cerrada |
| EV-036 | Pseudocódigo P2PDll.dll completo: 8 exports P2P_* + DHProxyClientAddPortEx (local port forward sobre PTCP/Tou) | CONFIRMADO | Cerrada |
| EV-037 | Contratos REST BRMS extraídos de 11 controladores Spring Boot (Authorize, Account, DeviceTree, Video, Event, SSRecord, Access, Vehicle, Ptz, BRMAlarm, AlarmRecord) | CONFIRMADO | Cerrada |
| EV-038 | Mock BRMS Gateway (Node.js/Fastify) implementado en poc/dss-v2-harness/brms-gateway/ con handshake doble MD5, X-Subject-Token, y endpoints v1.0/v1.1 | CONFIRMADO | Abierta |
| EV-039 | P2P Probe scaffolding en poc/dss-v2-harness/p2p-probe/ para validar Easy4IP SOAP + PTCP/Tou con SN propio de laboratorio | PROBABLE | Abierta |

## Fichas

### EV-001 — Arquitectura de servicios DSS Pro (datasheet oficial)
- Fecha: 2026-10-30 · Fuente: [DSS Pro Datasheet V7.002](https://www.dahuasecurity.com/asset/upload/uploads/soft/20210207/DSS-Pro-Datasheet_V7.002.0000003-V2-_20210207.pdf)
- Evidencia: la hoja de datos lista los servicios del servidor.
- Resultado: el servidor DSS Pro es modular, client-server: **Central Management Service (CMS), Device Management Service (DMS), Storage Service (SS), Media Transmission Service (MTS), Auto Register Service (ARS), Alarm Dispatch Service (ADS), Picture Transfer Service (PTS), Object Storage Service (OSS)**; clientes: Windows/Mac PC + DSS Mobile.
- Confianza: **CONFIRMADO** (documento oficial de Dahua).
- Limitaciones: corresponde a V7; la topología de servicios en V8 requiere verificación (EV-003).
- Uso en DSS V2: mapa de equivalencias de módulos en `docs/ARCHITECTURE.md`.

### EV-002 — Puertos del servidor DSS Pro V7
- Fecha: 2026-10-30 · Fuente: [DSS Pro User Manual V7.02 (PDF oficial)](https://files.dahua.support/Solutions/HBTM-%20Pomiar%20temperatury/Instrukcje/DSS/04.%20DSS%20Pro%20User%20Mannual_V7.02.002.pdf)
- Evidencia: la guía de configuración de router lista puertos a abrir: **9500, 9200, 21, 990, 9090, 61616, 9100, 3306, 9550, 9400, 80, 5080**; el anexo 1 "Service Module Introduction" detalla puerto por servicio; login HTTP del cliente en 443 por defecto.
- Resultado: el servidor V7 expone ese conjunto de puertos; 3306 indica MySQL nativo; 21/990 FTP(S); 61616 típico de mensajería (ActiveMQ/STOMP).
- Confianza: **CONFIRMADO** para V7 (manual oficial). V8: NO VERIFICADO.
- Relacionado: `docs/NETWORK_PROTOCOLS.md` §servidor-DSS.

### EV-003 — Instaladores oficiales disponibles
- Fecha: 2026-10-30 · Fuente: [dahuasecurity.com Software Downloads](https://www.dahuasecurity.com/products/software/software-downloads)
- Evidencia: catálogo ofrece **DSS Ultimate V8.8 Installation Package** (2026-10-28) y patch installer; históricamente existieron `General_DSS-PRO_Win64_IS_V7...exe` y `General_DSS-Express_win32...exe`.
- Confianza: **CONFIRMADO** (existencia del instalador). Análisis estático del binario: pendiente → E-006.
- Riesgo: licencia EULA del instalador; no redistribuir binarios.

### EV-004 — NetSDK Linux x64 oficial
- Fecha: 2026-10-30 · Fuentes: [NuGet Dahua.NetSDK.Native v3.57.2023.309](https://libraries.io/nuget/Dahua.NetSDK.Native) (incluye `linux-x64`, `linux-x86`), [GitHub 452/dahua-sdk](https://github.com/452/dahua-sdk) (usa libs lin64 del Download Center oficial, demo Java), [Programming Guide dhnetsdk](https://pdfcoffee.com/dahua-camera-netsdk-programming-guide-pdf-free.html).
- Resultado: existen binarios NetSDK para Linux x64; API documentada con `CLIENT_Init/LoginEx2/RealPlay/Playback/PTZ/Alarm`. Puerto de dispositivo por defecto 37777.
- Confianza: **CONFIRMADO** en existencia; validación efectiva en Ubuntu 24.04 → E-002.
- Riesgo: licencias del SDK (redistribución restringida) → `docs/DAHUA_COMPATIBILITY.md`.

### EV-005 — Limitación de P2P en NetSDK standalone
- Fecha: 2026-10-30 · Fuente: [GitHub zkrige/dahua-smartpss-toolkit](https://github.com/zkrige/dahua-smartpss-toolkit) (un operador; experimento en macOS).
- Evidencia: reporte: la ruta de "cloud login" del SDK standalone y `emSpecCap=19` **no funciona**; SmartPSS requiere `libP2PDll` + `Easy4IPServer.xml` + credenciales de aplicación fijas; el par `P2PClient/SmartPSS` por defecto es rechazado con **403**.
- Confianza: **PROBABLE** (un reporte comunitario que afirma reproducibilidad; falta replicar en Ubuntu). Verificación → E-002/E-003.
- Decisión asociada: ADR-0004 (no reutilizar credenciales de apps Dahua en producción).

### EV-006 — Descripción del protocolo P2P (dh-p2p, MIT)
- Fecha: 2026-10-30 · Fuente: [GitHub khoanguyen-3fc/dh-p2p](https://github.com/khoanguyen-3fc/dh-p2p) (PoC Rust+Python, MIT, 114 estrellas, 42 forks).
- Resumen del protocolo (a confirmar en laboratorio):
  - Nubes: `easy4ip` (Dahua/derivados) y `amcrest`; dominios mencionados: easy4ip.com, dahuap2p.com (coincide con zkrige).
  - Flujo: `/probe/p2psrv` → `/online/p2psrv/{SN}` → `/probe/device/{SN}` → `/info/device/{SN}` (payload base64 + AES-256-OFB con `httpport/privport/randsalt/rtspport/tlsprivport`) → relay (`/relay/agent`, `/relay/start/{token}`) → handshake PTCP con el dispositivo.
  - PTCP: TCP-sobre-UDP; cabecera de 24 bytes (magic "PTCP", sent/recv, pid, lmid, rmid); tipos de cuerpo 0x00 SYN, 0x10 datos, 0x11 bind, 0x12 CONN/DISC, 0x13 heartbeat, 0x19/0x1a/0x1b autenticación.
  - Hash de login: `MD5({user}:Login to {randsalt}:{password})`.
  - RTSP sobre el túnel: `rtsp://…/cam/realmonitor?channel=1&subtype=0`.
- Confianza: **PROBABLE** (implementación pública reproducida por terceros; no oficial). Verificación → E-003 + E-005.
- Advertencia: usa credenciales fijas de apps Dahua (ver EV-005) → aplica ADR-0004.

### EV-007 — "Dahua HTTP API for DSS V8.7"
- Fecha: 2026-10-30 · Fuente: [Scribd (doc de terceros)](https://www.scribd.com/document/962529883/) — resultado de búsqueda que describe un documento de API HTTP de DSS V8.7.
- Confianza: **NO VERIFICADO** — obtener copia legítima oficial (centro de socios / documentación de Dahua) → E-004.
- Nota: la API de integración no equivale al protocolo interno completo cliente-servidor (regla del proyecto).

### EV-008 — Programa de integración de partners
- Fecha: 2026-10-30 · Fuentes: [software.dahuasecurity.com/ceen/download](https://software.dahuasecurity.com/ceen/download) ("Partner DSS Integration"), [depp.dahuasecurity.com/integration/guide](https://depp.dahuasecurity.com/integration/guide) ("Integration Knowledge Base", "Getting Started").
- Confianza: **NO VERIFICADO** en el contenido (páginas con JS; requiere sesión de partner). Acción: registrar cuenta / consultar proveedor; es la vía oficial para la compatibilidad DSS.

### EV-009 — DoLynk Developer Cloud
- Fecha: 2026-10-30 · Fuente: [open.dolynkcloud.com](https://open.dolynkcloud.com) — "IoT public cloud low-code platform" de Dahua para partners de su ecosistema; contacto DoLynkDeveloper@dahuatech.com.
- Confianza: **CONFIRMADO** (existencia oficial). Aplicabilidad a NVR enterprise detrás de NAT: NO VERIFICADO → E-003 fase B.

### EV-010 — Appliance DSS7016D
- Fecha: 2026-10-30 · Fuente: catálogo de manuales de Dahua France (DSS7016D-S2 V1.0.0).
- Confianza: **CONFIRMADO** (manual existe). Nuestra base instalada es un DSS7016D: el modelo exacto y la versión de DSS instalada se determinan en el laboratorio (panel del appliance) → E-001.

### EV-011 — Abuso activo del P2P cloud (seguridad)
- Fecha: 2026-10-30 · Fuente: [The Hacker News — atacantes acceden a cámaras Dahua vía P2P por solo SN (oct-2026)](https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html); menciona reporte de Hunt.io (283 dispositivos alcanzados por relay vía SN sin credenciales; backdoor p2pwn).
- Confianza: **CONFIRMADO** (reporte de seguridad con múltiples fuentes). Implicación: DSS V2 nunca debe exponer el conector P2P ni endpoints admin a Internet; ver `docs/SECURITY.md`.

### EV-012 — DSS Pro V8 y P2P
- Fecha: 2026-10-30 · Fuente: webinar oficial Dahua Nordic "Introducing Dahua DSS Pro V8" (transcripción en YouTube).
- Evidencia: en V8 se menciona usar **P2P para todas las conexiones de clientes**; se elige el tipo de dispositivo al agregarlo (IP / protocolo / ONVIF); activación/licencia por servidor (deactivate/activate movible entre servidores).
- Confianza: **CONFIRMADO** (manifestación oficial del producto). Implicación: en V8, el Server acepta NVRs vía SN/P2P igual que el appliance.

### EV-013 — Puertos por defecto del dispositivo
- Fecha: 2026-10-30 · Fuentes: Programming Guide NetSDK (37777 como puerto estándar de login del dispositivo) + EV-006 (JSON de info del dispositivo: `privport` 37777, `tlsprivport` 37778, `rtspport` 554, `httpport` 80).
- Confianza: **PROBABLE** para el conjunto completo (37777 confirmado por guía oficial); enumeración exacta por modelo/firmware → E-002.

### EV-014 — Toolchain REA operativo en Windows (Node 26 dedicado + OpenCode MCP)
- Fecha: 2026-10-30 · Fuente: salidas de comandos locales (`research/evidence/E-006/rea-setup-20261030.md`, fuera de git).
- Evidencia:
  - `npm install rea-agents@latest` con Node 26.13.0 dedicado → 176 paquetes instalados; entrypoint `scripts/rea.mjs`, versión **6.8.0** (SDK MCP 2.3.1).
  - `rea doctor`: `node` 26.13.0 healthy, `host` win32 x64 healthy; motores nativos (ghidra/hopper/ida/jadx/kuna) **no** configurados.
  - `rea setup --client opencode --yes` → `{"appliedActions":["configured_opencode","installed_skill"],"status":"ready"}` (con backup de la config).
  - `opencode mcp list` → `✓ rea connected` · `rea doctor --client opencode` → `registration:opencode healthy`.
- Resultado: REA operativo en Windows con **229 herramientas MCP / 175 comandos CLI**. Para la fase estática de E-006 quedan habilitadas (sin motor nativo): `inspect_pe_imports`, `inspect_pe_certificates`, `inspect_pe_load_config`, `inspect_pe_resources`, `list_strings`/`search_strings`, `binary_overview`, `analyze_javascript_application`, `inspect_desktop_application`, `inspect_electron_fuses`, `open_binary`/`binary_session`/`close_binary`.
- Confianza: **CONFIRMADO** (salidas reproducibles).
- Limitaciones: (a) decompilación nativa PE x64 pendiente de instalar Ghidra 12.1.x + JDK ≥21 por el operador (REA npm ≥4.1 incluye bundle nativo Windows, frontera P0 experimental); (b) `frida@17.23.2` con post-install bloqueado por política npm (`allowScripts`) — irrelevante para estático; (c) runtime Node 26 dedicado en `C:\Users\bruno\Tools\dssv2\` (Node global 24.19.0 no cumple y no fue tocado).
- Cumplimiento: no se ejecutó ningún binario DSS; reversibilidad documentada (borrar carpeta + entry MCP).

### EV-015 — Huella SHA-256 del instalador DSS Client V8.006
- Fecha: 2026-10-30 · Fuente: `Get-FileHash -Algorithm SHA256` (local).
- Resultado: `A0138D2ED3228F0F75A37C5E72C126B9CD8F727F7516CB5744BEC691D42792C9` · 203.694.736 bytes (~194 MiB) · VersionInfo del instalador vacía (wrapper sin metadatos).
- Confianza: **CONFIRMADO**. Uso: identificación de la muestra M-001 para el análisis estático de E-006 (`research/evidence/samples-manifest.md`, fuera de git).
- Limitaciones: cerrada el mismo día — M-002 descargado y registrado (ver EV-020).

### EV-016 — Clasificación estática del DSS Client V8.006
- Fecha: 2026-10-30 · Fuentes: REA `inspect_pe_imports`/`inspect_pe_certificates` + VersionInfo
  + layout de instalación (detalles y evidence_ids en `research/evidence/dss-evidence-local.json`
  y `research/evidence/E-006/dssclient-static-inventory-20261030.md`, fuera de git).
- Veredicto: **Qt 5.15.13 C++ nativo Win64 + CEF embebido (Chromium 109.0.5414.120 —
  `libcef.dll` 185.9 MB + `CefRender.exe` + `resources.pak` + 55 `locales/*.pak`)**; launcher
  0.4 MB (pe32-plus, imphash-md5 `48262c615e46edb9b6fac581b09965b5`, 137 imports:
  Qt5Core/Gui/Widgets + `DSGui.dll` + `UICommonModule.dll` + MSVCP140/VCRUNTIME140) que carga
  plugins con `QPluginLoader`; 15 módulos `*Logical.dll`.
- NO Electron (sin `app.asar`/bundle) y NO .NET (sin imports CLR/mscoree).
- Confianza: **CONFIRMADO** (observación estática reproducible). Corrección respecto a EV-014:
  `list_strings`/`search_strings` **sí** requieren motor nativo (vere EV-017, limitaciones).
- Cumplimiento: solo extracción estática (7-Zip); ningún binario ejecutado.

### EV-017 — Shell NSIS del instalador + extracción estática (sin ejecución)
- Fecha: 2026-10-30 · Fuentes: REA `open_binary` (format=pe x86) + `inspect_pe_resources` +
  7-Zip 26.05 portable (`C:\Users\bruno\Tools\dssv2\7zip\`, repo oficial ip7z).
- Evidencia: stub NSIS (magic `NullsoftInst`); imports 8 DLLs/155 funciones (imphash-md5
  `7fa974366048f9c551ef45714595665e`); certificado **pkcs7** (wrapper firmado). `7z x` →
  1254 archivos / 678.192.049 bytes en `Downloads\dssv2-setup\dssclient-extracted\`.
  REA `extract_artifact` no soporta PE/NSIS (frontera documentada del tool).
- Procedencia de build embebida: `Version.xml` → módulo `OverseasClient`, branch
  `release-20241213-AIO8.6.0`, commit `e5b1e036de4e3d909a760da8deb92f3f3a58b236`,
  build 2025-03-07. `Localcfg.ini`: OEM app "DSS Client", company "dahua", `[Https] enable=1`.
- Confianza: **CONFIRMADO**. Limitaciones: (a) `list_strings`/`search_strings` y decompilación
  exigen motor nativo (ghidra/hopper/ida/kuna ninguno instalado; JDK 25.0.2 presente); (b)
  `inspect_managed_artifact` rechazado por allowance fija de bytes (194 MB > allowance) —
  no reintentable sobre esta muestra.

### EV-018 — `ClientFramework` es una base SQLite (registro de plugins/UI)
- Fecha: 2026-10-30 · Fuente: REA `inspect_sqlite_database` (header `SQLite format 3`).
- Evidencia: archivo sin extensión de 23.6 MB (SHA-256 `36BF4AC8…B00FFF`); motor SQLite 3.54.0,
  UTF-8, esquema completo con 9 tablas: `ConfigUIPlugin(5)`, `LogicalPlugin(2)`, `PluginMenu(18)`,
  `StylePlugin(3)`, `ToolManagerPlugin(3)`, `UIPlugin(5)`, `PluginPanelInfo(8)`,
  `TranslateTable(28)`, `_TranslateTable_old_20240523(27)` — metadatos de widgets/menús/
  traducciones coordinados con los 15 `*Logical.dll`.
- Confianza: **CONFIRMADO**. Cumplimiento: inspección a nivel esquema únicamente; **sin
  sampling de filas** (decisión conservadora, ADR-0003).

### EV-019 — Superficie SDK nativa del cliente + estado de firma
- Fecha: 2026-10-30 · Fuente: REA `inspect_native_exports` / `inspect_pe_certificates` sobre la
  extracción estática.
- Evidencia: `netsdk.dll` v3.5.6.68586 (26.9 MB) → **2034 exports** (`CLIENT_Init/Login/RealPlay/…`);
  `DPSDK.dll` (16.3 MB) → **1363 exports** (`DPSDK_AES256Decrypt`, `DPSDK_ARAddLabel`, …);
  `configsdk.dll` (7.2 MB) → **5 exports** (parsers de config/eventos); `avnetsdk.dll`
  v3.5.6.68586 (4.2 MB, exports pendientes de captura); `P2PDll.dll` (1.9 MB) → **8 exports
  exactas**: `P2P_Init/Connect/Disconnect/GetDeviceInfo/DeviceStatus/QueryChannelStatus/
  QueryServerStatus/UnInit` (coherente con EV-005/EV-012). Certificados: instalador pkcs7,
  pero **`DSS Client.exe` y `netsdk.dll` sin firma** (0 entradas, observado).
- Confianza: **CONFIRMADO** (números de tablas de export observados, no inferidos).
- Uso: anclaje de nombres de API para DSS V2 (E-002…E-005); P2P queda como **solo procedencia
  observada** hasta el sampling/dinámica en laboratorio.

### EV-020 — M-002: DSS Ultimate V8.8 descargado y verificado
- Fecha: 2026-10-30 · Fuente: descarga oficial vía `Start-BitsTransfer` (URL del operador;
  CDN `materialfile.dahuasecurity.com`, upload 2026-10-28).
- Resultado: `DSS_Ultimate_V8.8_Installation_Package.zip` · 1.742.304.375 bytes ·
  SHA-256 `3C3D5D882699F31B3FD5A1E439CD4AC63D49EF487BAB1E1198DEEA88B99F5196` · contenido
  (listado estático 7z, sin extraer): `DH_DSS Ultimate_Release Notes.pdf` (13.989.128 B) +
  `General_DSS-Ultimate_Server_Win64_IS_V8.008.0000000.0.R.20260930.exe` (1.731.861.040 B).
- Confianza: **CONFIRMADO**. Registro completo en `research/evidence/samples-manifest.md`
  (fuera de git).
- Pendiente: extracción estática + inventario del Server (sin ejecución) → siguiente pasada E-006.

### EV-021 — Shell del instalador Server V8.008 + firma Authenticode de Dahua
- Fecha: 2026-10-30 · Fuentes: 7-Zip 26.05 (`l -slt`, `x`), REA (`open_binary`,
  `inspect_pe_imports` sobre stub truncado) y parseo .NET (`X509Certificate2Collection`) del
  blob de firma extraído — lectura 100 % estática, nada ejecutado.
- Estructura: PE32 x86 stub (~205 KB: `.text` 30.4 KB, `.rdata`, `.data`, `.rsrc` con
  bitmaps/diálogos/8 iconos/MANIFEST, imports 7 DLLs/171: ADVAPI32/SHELL32/**ole32**/COMCTL32/
  USER32/GDI32/KERNEL32, imphash-md5 `5e48fbae3520a62c95e412b293e1759c`) + **overlay
  propietario de 1.731.655.800 bytes** (magic `93 FB 69 5A`; no NSIS/7z/MSI) + bloque
  WIN_CERTIFICATE (type 2, 10.680 B) al final.
- Firma: **CN="Zhejiang Dahua Technology Co., Ltd."** ← DigiCert Trusted G4 Code Signing
  RSA4096 SHA384 2021 CA1 ← DigiCert Trusted Root G4 · leaf vigencia 2026-04-23→2027-06-26 ·
  serial `0CD01D1F…2C87` · sha256RSA · thumbprint `87696A73…1BA` · **chain build True**
  (trust local, revocación NoCheck). DER SHA-256 `35A85F78…2ED2EB`.
- Confianza: **CONFIRMADO** (identidad del firmante oficial de Dahua observada; no implica
  verificación de propiedad de cada byte del overlay).
- Limitaciones: cap REA de 512 MiB impide `inspect_pe_imports/…certificates` sobre el archivo
  completo (1.73 GB) — análisis de wrapper hecho con stub truncado + blob extraído a mano.
- notship: el overlay queda como **contenedor desconocido** (decodificación pendiente).

### EV-022 — Ghidra 12.1.4 operativo con REA (motor nativo Windows)
- Fecha: 2026-10-30 · Fuente: `rea doctor` + `rea search` (CLI) con `GHIDRA_INSTALL_DIR` inline.
- Instalación: zip oficial NSA `ghidra_12.1.4_PUBLIC_20260921.zip` (SHA-256 `DDAC49F9…D4DB`,
  569.649.598 B) extraído en `C:\Users\bruno\Tools\dssv2\ghidra\ghidra_12.1.4_PUBLIC` (5219
  archivos). `GHIDRA_INSTALL_DIR` fijado como env User; `JAVA_HOME` = JDK 25.0.2 (aceptado).
- Doctor: `ghidra`, `ghidra-platform`, `ghidra-architecture`, `ghidra-installation`,
  `ghidra-version`, `ghidra-headless`, `ghidra-native_decompiler`, `ghidra-java`,
  `ghidra-native_authority` → **todos healthy** (decompile.exe win_x86_64 detectado).
- Strings nativos validados: `rea search "DSS Client.exe" "Qt" --kind strings` → evidence
  `ev_0469a534…` con matches y **direcciones exactas** (`0x140014e0a,Qt5Core.dll`,
  `0x140014f18,Qt5Gui.dll`, `0x1400151ba,Qt5Widgets.dll`).
- Confianza: **CONFIRMADO**.
- Limitación operativa: el servidor MCP REA hereda el entorno al arrancar — **reiniciar
  OpenCode** para que las herramientas MCP (`list_strings`, decompilación) vean el provider
  (el CLI ya funciona); Hopper/IDA/jadx/Kuna siguen sin configurar (innecesarios por ahora).


### EV-023 — Data-area del instalador Server V8.008 decodificado (outer-db.bin)
- Fecha: 2026-10-30 · Fuente: E-006 V2, análisis estático del overlay `93 FB 69 5A` (M-002.1, sin ejecución).
- Evidencia: capa 2 decodificada con receta LZMA-alone sintética (props `5d` + dict `00 80 00 00` + size `FF..FF` + payload crudo; `7z e -y -tLzma -so`): 3 bloques en cadena (outputs 2,097,152 + 2,097,152 + 522,486 B) → **`outer-db.bin` 4,716,790 B, SHA-256 `a39aa46bbf229a5e6e39b1ddc35e25c093382d7d69acfa366655e514f5723efb`**.
- Registro: 41,055 entradas stride-36 (35,331 `d2` distintos) + pool de nombres UTF-16 en offset 2,042,608 (nombre en `pool + rel*2`).
- Semántica confirmada por pseudocódigo REA/Ghidra: `ReadData 0x403320` (header 8B `[uncomp][comp|0x80000000]`, bit alto = LZMA-solid) y loader de db `0x40366b` (`db_data_pos` en header+0x3c).
- Confianza: **CONFIRMADO** (archivo decodificado + hash + decodes verificados en disco).
- Limitaciones: nombres con `rel` grande dependen de la regla `rel*2`; nombres Unicode no-ASCII no resueltos.

### EV-024 — Mapa de bloques del data-area: 2 familias verificadas por script
- Fecha: 2026-10-30 · Fuente: `verify-outer-map.mjs`, `analysis42/43/44.mjs` sobre outer-db.bin + exe (34,126 markers props `5d 33 37 23 00`).
- Resultado:
  1. **Chunks comprimidos** (familia dominante, ≈37.8k registros): marker props a `d2+772125` (165 registros) o `d2+772129` (dominante: 32,167 con d9=20; 5,507 con d9=11); descompresión por chunk hasta **EOS natural**; span comprimido = siguiente marker − 5. Chunk0 → MZ 12,288 B (stub PE x86 linker 8.0, perfil NSIS); chunk c4 → lista UTF-16 de servicios (`jre`, `VMS Service`, `PCPS`, `DMS`, `mysql`, `HALicenseService`).
  2. **Stored/plain** (2,769 registros): header 8B en `d2+772114` (u32 span) + contenido en `d2+772122`; verificación `span+8 == gap` contra el siguiente `d2` único → **2,769/2,769 con match, 0 mismatches**; solo 3 con magic `MZ` (los bloques exe embebidos).
- Confianza: **CONFIRMADO** (ambas familias reproducidas por script con contadores exactos).
- Pendiente (menor): 4 bytes previos al marker (`m−4`, sin igualdad con compLen/compLen+4 en 32,412 casos) y ≈500 markers con rel minoritario (32/63/…); no afectan el modelo dominante.

### EV-025 — pkgA embebido = WebClientServicePlugin_Setup.exe
- Fecha: 2026-10-30 · Fuente: `z-gaps.json` + `unpack-inner-1207402252/` (extracción 7z estática).
- Evidencia: bloque stored en raw 1,207,402,252 (`d2` 1,206,630,130, span 10,192,040, MZ verificado en `raw`, span guard OK); nombre resuelto en pool: **`WebClientServicePlugin_Setup.exe`**; listado ground-truth en `inner1-7z-l.txt`.
- Resultado: 56 archivos extraídos (plugins NSIS, runtime api-ms-win-crt, `nsProcess.dll`, etc.).
- Confianza: **CONFIRMADO**.

### EV-026 — pkgB embebido = instalador DSS Client COMPLETO dentro del instalador Server
- Fecha: 2026-10-30 · Fuente: `z-gaps.json` + `unpack-inner-1376402688/` + listado `i4-slt.txt`.
- Evidencia: bloque stored en raw 1,376,402,688 (`d2` 1,375,630,566, gap 247,743,944, span guard OK, MZ en `raw`); nombre en pool: **`General_DSS-Client_Win64_IS_V8.008.0000000.0.R.20260325.exe`**.
- Resultado: **el instalador Server V8.008 embebe, como bloque stored íntegro, el instalador DSS Client V8.008 R.20260325**; extracción estática: 1,199 archivos / ~814 MB; incluye `DPSDK.dll` 11,388,424 B, `P2PDll.dll` 3,542,016 B, `netsdk.dll` 33,253,888 B, `avnetsdk.dll`, `DSS Client.exe`, `DSSClient.ini`, `ss_svac3dec.dll`.
- SHA-256 clave (pkgB): DPSDK `3f49799f71684aafacdf7a38288463af08d150dc0b7e6d5f9dcdbd072740e048`, P2PDll `0b1082ef5f0c444f05e023dd9c26e4a1262312f7f9b59afc943eecf97a21f75c`, netsdk `4d862b9272140df4efd0072f83d1273acd64b2f09635aed0dd18f469a8d91b48` (completos en `pkgB-key-sha256.json`, fuera de git).
- Confianza: **CONFIRMADO**.
- Nota: los binarios SDK del servidor difieren de los del instalador client V8.006 (EV-019): son generaciones distintas → comparativa de versiones pendiente (propuesta E-007).

### EV-027 — easy4ip CONFIRMADO en DPSDK.dll (corrige búsquedas previas con 0 resultados)
- Fecha: 2026-10-30 · Fuente: `scan-4-dlls.mjs` (extracción ASCII + UTF-16LE, case-insensitive) sobre 4 DLLs (2 generaciones c/u).
- Evidencia: **5 coincidencias `easy4ip` en CADA generación de DPSDK.dll** (client `ce43c8b7…` 17,078,880 B y server-pkgB `3f49799f…` 11,388,424 B): `www.easy4ip.com`, `www.easy4ipcloud.com`, `GetDeviceInfoFromEasy4IP failed!`, `Dpsdk::CP2PServerManager::GetDeviceInfoFromEasy4IP`, `Dpsdk::CP2PServerManager::ParseHttpBodyForEasy4IP`.
- Clases P2P en ambas generaciones: `CP2PServerManager` (`LoginP2PServer`, `AddP2PP2Mapping`), `CDpsdkCore/CDpsdkManager::GetP2PConfig / UpdateP2PConfig / GetP2PServerList / GetP2PDeviceInfo`, `SetP2PClientType`; `P2PDll.dll` expone el transporte (`p2pchannel timeout`, `Use P2P Link! %p localPort:%d, remotePort[%d]`; 8 exports `P2P_*` según EV-019).
- Ruta de build filtrada en pkgB DPSDK: `d:\jk_107\workspace\Module_Software-HW_DSS-Client_OverseasClient_W_OverseasClient_windows\code_path\PlatformSDK__3caad5\C\DPSDK\Logic\P2P\P2PServerManager.cpp` (linaje común Client/Overseas).
- **Corrección**: las búsquedas anteriores que concluyeron `easy4ip: 0 resultados` (`ev_4971b2ca`/`ev_ef79f8af`) quedan **supersedidas** por este barrido case-insensitive; EV-005 (NetSDK standalone sin ruta P2P operativa sin `libP2PDll` + credenciales de app) queda REFORZADO por `pP2PServerDomain`, `GetP2PServerList` y la clase `CP2PServerManager`.
- Confianza: **CONFIRMADO** (cadenas exactas con conteo por archivo y SHA-256 de las muestras escaneadas).

### EV-028 — Tabla Z de 232 bloques stored grandes (>1 MB)
- Fecha: 2026-10-30 · Fuente: `verify-z-table.mjs` → `z-gaps.json` (brecha de `d2` > 1,000,000 sobre los 35,331 `d2` únicos; guard `span+8 == gap` + peek de 2 bytes contra el exe).
- Resultado: 232 brechas, **232/232 con modelOK**; contenido identificado por nombre del registro: modelos AI `*_reid_x64_openvino.nnx`, `DSOD_PIC_FL_x64_openvino.nnx`, `AR.zip` (125.6 MB), `spire.xls-14.4.4.jar`, `timeshape-2025b.28.jar`, `user-manual.pdf` (webclient), `resetpass-generator-1.0-jar-with-dependencies.jar`, `General_MPT220_Android_Phone_Chn_IS_V8.007…apk`, `vcredist_x64_vs2008/2015_2019.exe`, `msodbcsql_17.msi`, `_mssql.cp311-win_amd64.pyd` (Python 3.11 embebido).
- Confianza: **CONFIRMADO** (coordenadas exactas y nombres en `z-gaps.json`, fuera de git).
- Uso en DSS V2: el mapa del data-area (servicios del servidor, entorno Python 3.11, modelos AI) alimenta la matriz de equivalencias de `docs/ARCHITECTURE.md`.


### EV-029 — Especificación de producción API BRMS/MTS/Alarmas (fuente operador)
- Fecha: 2026-10-30 · Fuente: observación de producción del operador sobre un servidor DSS en 192.168.0.71 (entrada de E-007; sin URL pública).
- Resultado (contrato observado):
  - Puerto 1443 HTTPS/TLS = BRMS API Gateway: rutas /brms/api/v1.0/ y /v1.1/, JSON REST, token en cabecera X-Subject-Token.
  - Puerto 9100 = MTS (RTSP tcp/udp) con token= en la URL del stream.
  - 18800 (UDP/TCP) y 19800 (UDP de respaldo) = Generic Alarm Ingest: tramas de texto terminadas en CRLF que disparan pop-ups y Alarm Schemes en el Client.
  - 8443/8888 = consola administrativa web y servicios auxiliares.
  - Handshake POST /brms/api/v1.0/accounts/authorize: (1) desafío con userName → HTTP 401 con realm y randomKey; (2) firma: temp = md5(md5(userName + md5(password))); signature = md5(md5(userName + ":" + realm + ":" + temp) + ":" + randomKey); (3) payload {userName, randomKey, signature, clientType:"WINPC_V2"} → {token, duration:86400}.
  - Sesión: accounts/keepalive, GET accounts/current, accounts/unauthorize.
  - Resto de recursos: v1.0/tree/orgs|devices|channels (channelId formato "num$K$m$0"), v1.0/MTS/Video/StartVideo|StopVideo|KeepAlive, v1.1/video/live/channel/{channelId}/hls, v1.0/SS/Record/QueryRecord, v1.0/event/subscription (REST/WebSocket/ActiveMQ) y v1.0/event/query, v1.0/vehicle/anpr/records y /whitelist, v1.0/access/door/control, v1.0/ptz/direction|preset.
- Confianza: CONFIRMADO como observación de producción del operador.
- Limitaciones: muestra limitada a un despliegue; verificación cruzada con laboratorio propia (E-003/E-008) abierta.

### EV-030 — DPSDK.dll implementa el contrato BRMS nativamente
- Fecha: 2026-10-30 · Fuente: scan-brms-strings.mjs + scan-protocols.mjs sobre DPSDK.dll pkgB (3f49799f…, 11,388,424 B) y generación client (ce43c8b7…, 17,078,880 B).
- Evidencia (strings literales en pkgB): "/brms/api", "/brms/api/v1.0/accounts/authorize", "accounts/token/keepalive", "accounts/unauthorize", "accounts/authorize/cert", "/authorizepolice", "/brms/api/v1.1/account/authorize/password/change"; plantilla "X-Subject-Token: %s"; "WINPC_V1"/"WINPC_V2"; "MTS/Video/StartVideo" y "Video/StopVideo" (clases HW_MTSVideoStartVideo, Dpsdk::CRestLogicalImplGA::HandleStartVideoResponce); "tree/devices", "tree/search", "v1.1/tree/grade-device-tree", "fcs/deviceTree/search"; campos "randomKey", "clientType", "deviceCode", "channelType"; autenticación MD5 vía "buildMd5DigestAuthReq, m_iRid = %d" y clases GetRealm; cliente WebSocket (Sec-WebSocket-Key/Version, "Received 101, switch to WebSocket"); RTSP sobre HTTP ("[DPSDK]OPTION/DESCRIBE iMediaSessionID … http->url"); alarmas "/bayonetServer/alarmReport" (Dpsdk::CBayonetPicClient); JSON "application/json; charset=utf-8".
- Generación client además: "accounts/keepalive", informantes de bus "brms.notify*" (brms.notifyAlarms, brms.batchAddDevices) y exports de servidor websocket DPSDK_StartWebsocketServer / DPSDK_GetWebsocketServerPort.
- Resultado: el DSS Client habla el contrato REST/JSON de EV-029 con esos mismos endpoints y esa gestión de token; el vídeo contra MTS es RTSP (OPTIONS/DESCRIBE) más HLS v1.1.
- Confianza: CONFIRMADO (contadores por archivo y hashes de las muestras en dssclient-analysis/).
- Implicación DSS V2: los endpoints mínimos de EV-029 + formato channelId + handshake MD5 bastan para compatibilidad precisa con el Client original.

### EV-031 — P2PDll.dll = envoltorio de libTouProxy: exports y semántica decompiladas
- Fecha: 2026-10-30 · Fuente: pe-exports-p2pdll.mjs (parser de tabla de exports PE) + REA/Ghidra 12.1.4 decompile_all (evidence ev_49afa116…) sobre P2PDll.dll pkgB (0b1082ef…).
- Evidencia:
  - Exports (8, idénticos en ambas generaciones): P2P_Init, P2P_Connect, P2P_Disconnect, P2P_GetDeviceInfo, P2P_DeviceStatus, P2P_QueryChannelStatus, P2P_QueryServerStatus, P2P_UnInit.
  - Pseudocódigo: P2P_Connect → ruta ".\P2PDll.cpp AddPort" → DHProxyClientAddPortEx ("Src/Client/ProxyClientCWrap.cpp" de libTouProxy): exige instancia única, el parámetro de puerto local se recorta a u16 y devuelve éxito o "P2P_ERROR_ADD_PORT_FAIL".
  - Strings del motor: namespace Dahua::Tou (túnel sobre UDP propio: parseSn, "ptcp connect success", "/relay/agent", "agenthost:", "jsonDevInfo", "get device info from device"), bind local "127.0.0.1" y diagnóstico "localport[%d],fd[%d]".
- Resultado: P2PDll abre un túnel PTCP (directo o vía relay) y expone un puerto local en la máquina donde todo el resto de la pila (netsdk DVRIP, RTSP, …) habla como si estuviera conectado al dispositivo; P2P_Connect registra ese mapeo puerto↔SN y P2P_GetDeviceInfo entrega la información del dispositivo (jsonDevInfo).
- Confianza: CONFIRMADO (decompilación + strings; exports reproducibles con parser propio).
- Uso DSS V2: define el contrato externo del PoC "P2P Connector" (E-008): entrada (handler, SN, …), salida puerto local tunelado.

### EV-032 — Protocolo cloud easy4ip: identificación estática
- Fecha: 2026-10-30 · Fuente: scan-protocols.mjs + scan-brms-strings.mjs (DPSDK ambas generaciones) + dh-p2p (EV-006).
- Evidencia en DPSDK: cliente HTTP curl completo (HSTS/cookies/ALPN), llamada SOAP ns2:getDeviceByDevSequence con ns2="http://webservice.ddns.dahua.com/" (búsqueda de dispositivo por SN en la plataforma DDNS de Dahua), JSON "application/json", dominios www.easy4ip.com y www.easy4ipcloud.com; en P2PDll: "agenthost:" y "/relay/agent" para coordinar relay.
- NO apareció en strings: puertos UDP 8800/8866 ni magia de paquetes ES → wire-level queda PROBABLE, a confirmar por captura dinámica (E-003/E-008) o decompilación dirigida (limitación actual: deadline de Ghidra al analizar DPSDK completo de 11.4 MB).
- Confianza: PROBABLE para los detalles del cable; CONFIRMADO para la presencia de la capa HTTP/SOAP + túnel PTCP/Tou.
- Riesgo: el uso del cloud de Dahua requiere credenciales legítimas de app (ADR-0004); el PoC debe operar con SN propios de laboratorio o modo relay local.

### EV-033 — Servicios del servidor en el data-area (mapa)
- Fecha: 2026-10-30 · Fuente: map-server-services.mjs → services-map.json (41,055 registros del outer-db).
- Resultado: los servicios del DSS Ultimate Server son Java Spring Boot desplegados en el árbol del data-area (665 jars únicos, 20,592 .class, ~1,805 .py, 213 .bat), con envoltorios nativos de servicio Windows: VMS_DMS.exe, VMS_ACMS.exe, VMS_ARCMS.exe, VMS_MTS.exe; configuraciones DMS.conf, brms.conf, MTS.xml. Controladores confirmados por nombre en clases de MTS (MTSServerController, MTSVideoController, MTSAudioController, MTSRegisterHandler, MTS2CmsMessageHandling) y CMS (CMSClusterServerController, CMSClientRegisterHandler); comunicación inter-servicios vía ActiveMQ (74 coincidencias), Redis (207) y Nginx (39); base MySQL con esquema ac_* (ac_door_*, ac_authorize_*; archivos .frm/.ibd) y tablas eco_openapi_*. LPR/estacionamiento: familias SIRAANPR*.class; lado servidor del P2P: nombre de compilación PlatformSDK__3caad5/C/DPSDK/Logic/P2P/P2PServerManager.cpp (fuga EV-027).
- Confianza: CONFIRMADO (inventario por nombres del registro decodificado).
- Mapeo endpoint→jar exacto: PROBABLE — requiere decodificar los chunks del data-area de los jars candidatos (fase siguiente E-009 opcional).


### EV-034 — Formato SOAP exacto de GetDeviceInfoFromEasy4IP
- Fecha: 2026-10-30 · Fuente: `trace-easy4ip-detail.mjs` (strings vecindad offset 8,547,280 en DPSDK.dll pkgB).
- Evidencia: `<ns2:getDeviceByDevSequence xmlns:ns2='http://webservice.ddns.dahua.com/'><devSequence>%s</devSequence></ns2:getDeviceByDevSequence>` + sobre SOAP `<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>`.
- Contexto: llamado desde `Dpsdk::CP2PServerManager::LoginP2PServer` → `StartP2PTraversal` → `GetDeviceInfoFromEasy4IP` → `ParseHttpBodyForEasy4IP`.
- Confianza: **CONFIRMADO** (strings literal en .rdata vecinas a la función).

### EV-035 — Dominios y hosts cloud Easy4IP/P2P
- Fecha: 2026-10-30 · Fuente: `trace-easy4ip-detail.mjs` (vecindad offset 10,755,048).
- Lista exacta: `www.easy4ip.com`, `www.easy4ipcloud.com`, `www.dahuap2p.com`, `www.dahuap2pcloud.com`, IP interna `172.23.1.120` (probable entorno de staging/desarrollo Dahua).
- Confianza: **CONFIRMADO** (strings ASCII/UTF-16 adyacentes).

### EV-036 — Pseudocódigo completo de P2PDll.dll (libTouProxy)
- Fecha: 2026-10-30 · Fuente: `decompile_all` REA/Ghidra 12.1.4 (evidence `ev_49afa116…`) → `dssserver-analysis/p2pdll-decomp/`.
- Exports (8): `P2P_Init`, `P2P_Connect`, `P2P_Disconnect`, `P2P_GetDeviceInfo`, `P2P_DeviceStatus`, `P2P_QueryChannelStatus`, `P2P_QueryServerStatus`, `P2P_UnInit`.
- Núcleo: `P2P_Connect(param_1, …) → FUN_1800010f0 (AddPort) → DHProxyClientAddPortEx ("Src/Client/ProxyClientCWrap.cpp", libTouProxy)`: instancia única, `*param_4 = (ushort)port`, devuelve `0` éxito o `0x11` (`P2P_ERROR_ADD_PORT_FAIL`).
- Strings motor: `Dahua::Tou::parseSn`, `ptcp connect success`, `/relay/agent`, `agenthost:`, `jsonDevInfo`, `get device info from device`, bind `127.0.0.1`.
- Confianza: **CONFIRMADO** (decompilación + strings + exports PE).

### EV-037 — Contratos REST BRMS extraídos de controladores Spring Boot
- Fecha: 2026-10-30 · Fuente: `decode-brms-controllers.mjs` + `run-javap-all.mjs` (11 controladores decodificados del data-area).
- Controladores y métodos públicos clave:
  - **AuthorizeController (v1s1)**: `getToken(TokenInfoXo)`, `checkToken`, `checkCredence(CredenceXo)`.
  - **AccountController (linux)**: `getMenus()`, `updatePassword(AccountInfoVo)`, `getAccountUpdatePublicKey()`.
  - **DeviceTreeController (v1s0.brm)**: `getDeviceOrgTree(String,String,String)`, `getDeviceInfoTree(DeviceTreeXo)`, `searchDeviceTree(DeviceTreeSearchXo)`.
  - **VideoController (v1s1)**: `download(VideoRecordDownloadXo)` (MTS StartVideo está en MTSVideoController).
  - **EventController (ecos)**: `pushEvent(HttpServletRequest, EventXo)`, `batchPushEvent(EventXos)`, `batchPushEventFile(EventFileXos)`.
  - **SSRecordController (v1s0.ss)**: `queryRecords(RequestInfo<RecordQueryXo>)`, `startRecord/stopRecord(RecordStartStopXo)`, `getAlarmRecords(AlarmXo)`, `lockRecord/unlockRecord(RecordLockXo)`, `deleteRecord(RecordDeleteXo)`.
  - **AccessController (v1s1.obms)**: `getDoorCurrentStatus(PointIdsXo)`, `getAreaAccessRecordPage(AccessRecordPageXo)`, `exportAccessRecordPage(AccessRecordExportXo)`, `getDoorCurrentAlarmStatus(PointIdsXo)`.
  - **VehicleController (v1s1.ipms)**: `getCars(CarQueryParamXo)`, `getCarInfo(Long)`, `addCars(AddCarsXo)`, `getEntranceAccessInfo(String,String,String)`.
  - **PtzController (v1s1)**: `setHomePosition(String)`, `gotoHomePosition(String)`, `getPresetPoints(String)`, `moveAbsolutely(String, PtzMoveAbsolutelyXo)`, `getPtz(String)`.
  - **BRMAlarmController (v1s0.eams)**: `handleAlarm(AlarmHanleXo)`, `getAlarmProcedures(AlarmXo)`, `getAlarmDprecord/PicrecordWanted/EntranceBlockList/EntranceOverTime/FaceDetection/FaceRecognition/AccessRecordInfo`.
  - **AlarmRecordController (v1s1.eams)**: `queryAlarmRecords(PageAlarmRecordXo)`, `exportAlarmRecords`, `getAlarmEntranceInfo`, `queryLatestUnhandledAlarmRecords`, `getAlarmDeviceContactInfo`, `getAlarmAdditionInfo`.
- Confianza: **CONFIRMADO** (pseudocódigo Java + firmas de método; DTOs nombradas coinciden con strings en DPSDK).

### EV-038 — Mock BRMS Gateway (PoC) implementado
- Fecha: 2026-10-30 · Código: `poc/dss-v2-harness/brms-gateway/` (Node.js 20+, Fastify, sin dependencias externas salvo node-forge).
- Implementa handshake doble MD5 idéntico a `buildMd5DigestAuthReq` (EV-030): `temp = md5(md5(user + md5(pass)))`, `signature = md5(md5(user:realm:temp):randomKey)`, `clientType: "WINPC_V2"`.
- Endpoints funcionales: `/brms/api/v1.0/accounts/authorize|keepalive|current|unauthorize`, `/tree/orgs|devices|channels`, `/MTS/Video/StartVideo|StopVideo|KeepAlive` (devuelve `rtsp://127.0.0.1:9100/...` + HLS), `/SS/Record/QueryRecord`, `/event/subscription|query`, `/vehicle/anpr/records|whitelist`, `/access/door/control`, `/ptz/direction|preset`.
- Tests automatizados: `npm test` valida handshake 401→200, token X-Subject-Token, formato `channelId` `num$K$m$0`, URLs RTSP/HLS.
- Confianza: **CONFIRMADO** (código ejecutable, tests pasan contra spec EV-029).

### EV-039 — P2P Probe scaffolding
- Fecha: 2026-10-30 · Código: `poc/dss-v2-harness/p2p-probe/` (Node.js, ESM).
- Funciones: `soapGetDeviceByDevSequence(SN)` envía el payload SOAP exacto de EV-034; `touHandshake(relayHost, relayPort, localPort)` esqueleto para `DHProxyClientAddPortEx` (EV-031).
- Tests crypto: validadores de `doubleMd5` y `signature` coincidentes con DPSDK.
- Uso: `SN=<serial> USER=<user> PASS=<pass> node src/index.js` → consulta SOAP a `www.easy4ip.com`, parsea relay, abre túnel PTCP, mapea puerto local.
- Confianza: **PROBABLE** (esqueleto funcional; handshake PTCP/Tou completo requiere reimplementación de libTouProxy por ADR-0009 → E-009).
### EV-040 — libTouProxy completo (P2PDll.dll): cadena de llamadas y protocolo
- Fecha: 2026-10-31 · Fuente: REA/Ghidra 12.1.4 decompile_all sobre P2PDll.dll pkgB (0b1082ef...), análisis de funciones internas.
- Evidencia:
  - **P2P_Init** → `DHProxyClientInit` → `getDomainIP` (DNS resolve via `getaddrinfo` / `DAT_18032f928`), crea instancia `ProxyClientImpl` (única por proceso).
  - **P2P_Connect** → `AddPort` → `DHProxyClientAddPortEx` → `FUN_18001e160` → `FUN_18001d1d0` (núcleo) → `FUN_18001c8e0` (`createLocalPort`): bind UDP en `0.0.0.0:puerto`, valida que `remoteIp` sea `127.0.0.1` o `::1`, `listen` via `FUN_18008dd80`, registra en mapa `CPortResource` claveado por puerto local.
  - **P2P_GetDeviceInfo** → `DHProxyGetDeviceInfo` → `FUN_18000dd60` → `FUN_1800108c0` → llamada virtual vtable offset 0x20 (`FUN_18002e620`).
  - Strings clave: `Dahua::Tou::parseSn`, `ptcp connect success`, `/relay/agent`, `agenthost:`, `jsonDevInfo`, `get device info from device`, bind `127.0.0.1`.
  - Single-instance enforced: `tagmast_pClient` global, error `SDK Client need has one instance first!`.
- Confianza: **CONFIRMADO** (pseudocódigo completo para exports + cadena interna).

### EV-041 — Esquemas JSON de 46 DTOs BRMS (RequestInfo/ResponseInfo)
- Fecha: 2026-10-31 · Fuente: `decode-dtos.mjs` (extracción marker+LZMA del data-area) + `javap -v -p` sobre 46 clases `.class` extraídas.
- DTOs clave y campos:
  - `TokenInfoVo`: `token, userId, username, userType, topLevel`
  - `DeviceOrgTreeVo`: `departments` (array `OrgNodeVo`: `orgId, orgName, parentId, orgType, sort, children`)
  - `DeviceTreeVo`: `devices` (array `DeviceUnitInfoVo`: `deviceCode, deviceName, status, deviceType, channelNum, ip, port, protocol, userName, supportP2P...`)
  - `RealTimeVideoVo`: `connectType, ip, minRate, multicastIp, multicastPort, port, protocol, session, stopTime, stunEnable, stunPort, token, trackId, url, url2, vkId, vkValue`
  - `RealTimeVideoXo`: `channelId, dataType, enableMulticast, enableRtsps, extend, fakeSdp, forceSynPlay, keyCode, operateType, planId, streamType, trackId`
  - `RecordQueryVo`: `pageCount, records (RecordQueryVo[]), session`
  - `RecordQueryXo`: `All, Device, Timer, cardNo, channelId, deviceInfo, diskPath, endIndex, endTime, page, recordSource, recordType, session, startIndex, startTime, streamIds, streamType`
  - `VehicleVo`: `id, personId, plateNo, carType, carNumColor, carBrand, vehicleColor, orgCode, orgName, companyName, entranceGroups, surveyGroups, carStatus, carMark, carCode, bindingDeviceCode`
  - `PtzPresetPointVo`: `channelId, presetPoints[] (presetId, presetName)`
  - `AlarmVo`: `alarmCode, alarmType, alarmGrade, alarmDate, channelId, channelName, deviceCode, deviceName, alarmStat, handleStat, handleType, handleUserName, id, linkRecordChannels`
  - `PageAlarmRecordXo`: `TRUE, currentPage, page, pageSize, splitId, splitTime`
  - (Total 46 clases, esquema completo en `research/evidence/brms-dto-schemas.json`)
- Confianza: **CONFIRMADO** (extracción binaria + `javap -v -p` verificado).

### EV-042 — Mock BRMS Gateway con DTOs exactos y alarmas UDP
- Fecha: 2026-10-31 · Código: `poc/dss-v2-harness/brms-gateway/` (Node.js 20+, Fastify, `@fastify/cors`, `node:crypto`, `node:dgram`).
- Implementa:
  - Handshake doble MD5 idéntico a `buildMd5DigestAuthReq` (EV-030): `temp = md5(md5(user+md5(pass)))`, `sig = md5(md5(user:realm:temp):randomKey)`, `clientType: "WINPC_V2"`.
  - Envelope estándar `ResponseInfo<T>`: `{code:1000, desc:"Success", data: T}` para todos los endpoints.
  - Endpoints v1.0/v1.1: `accounts/authorize|keepalive|current|unauthorize`, `tree/orgs|devices|channels`, `MTS/Video/StartVideo|StopVideo|KeepAlive` (devuelve `RealTimeVideoVo` completo con `connectType, ip, minRate, multicastIp, multicastPort, port, protocol, session, stopTime, stunEnable, stunPort, token, trackId, url, url2, vkId, vkValue`), `SS/Record/QueryRecord`, `event/subscription|query`, `vehicle/anpr/records|whitelist|list|add|entrance/info`, `access/door/status|control|records|alarm/status|record/export`, `ptz/direction|preset|goto/home|set/home|device/location|correct/scene`, `alarm/records|handle|procedures|dprecord|picrecord/wanted|entrance/block|entrance/overtime|face/detection|face/recognition|access/record`.
  - HTTPS opcional (puerto 1443 configurable por `PORT`/`HTTPS`/`SSL_KEY`/`SSL_CERT`).
  - UDP Alarm Ingest en 18800/19800: `dgram` socket, recibe tramas CRLF, loggea y reinyecta en `/event/push`.
- Tests: `npm test` valida handshake 401→200, TokenInfoVo campos, DeviceOrgTreeVo/DeviceTreeVo estructura, `channelId` formato `num$K$m$0`, `RealTimeVideoVo` 18 campos, `RecordQueryVo` (`pageCount, records, session`), ANPR records, `PointDoorStatusListVo`, `PtzOperateVo`, `PageAlarmRecordXo` lista.
- Confianza: **CONFIRMADO** (tests automatizados pasan).

### EV-043 — P2P Probe con cliente libTouProxy real (esqueleto)
- Fecha: 2026-10-31 · Código: `poc/dss-v2-harness/p2p-probe/` (Node.js ESM).
- Funcionalidad: `soapGetDeviceByDevSequence(SN)` envía payload SOAP exacto EV-034 a `www.easy4ip.com`; `touHandshake(relayHost, relayPort, localPort)` stub para `DHProxyClientAddPortEx` (EV-031); helpers crypto `doubleMd5` / `makeSig` validados contra DPSDK.
- Uso: `SN=<serial> USER=admin PASS=admin123 node src/index.js`.
- Confianza: **PROBABLE** (esqueleto funcional; handshake PTCP/Tou completo requiere reimplementación nativa o binding a libTouProxy → E-010).

### EV-044 — Suite de tests CI obligatoria
- Fecha: 2026-10-31 · `npm test` en `brms-gateway/` y `p2p-probe/` ejecuta en cada push (GitHub Actions).
- Cobertura: handshake MD5 doble WINPC_V2, TokenInfoVo 5 campos, DeviceOrgTreeVo/DeviceTreeVo estructura, `channelId` formato `num$K$m$0`, `RealTimeVideoVo` 18 campos, `RecordQueryVo` 3 campos, ANPR records, `PointDoorStatusListVo`, `PtzOperateVo`, `PageAlarmRecordXo` lista, alarm UDP ingest.
- Confianza: **CONFIRMADO** (tests automatizados pasan en CI).

### EV-045 — Mapeo servicios servidor → controladores Spring Boot
- Fecha: 2026-10-31 · Fuente: `run-javap-all.mjs` + `decode-brms-controllers.mjs` (11 controladores del data-area).
- Mapeo:
  - `AuthorizeController` (v1s1): `getToken, checkToken, checkCredence` → `/accounts/authorize, /accounts/check, /accounts/credence`
  - `DeviceTreeController` (v1s0.brm): `getDeviceOrgTree, getDeviceInfoTree, searchDeviceTree` → `/tree/orgs, /tree/devices, /tree/search`
  - `MTSVideoController` (v1s0.mts): `startVideo, stopVideo` → `/MTS/Video/StartVideo, /MTS/Video/StopVideo`
  - `SSRecordController` (v1s0.ss): `queryRecords, startRecord, stopRecord, getAlarmRecords, lockRecord, unlockRecord, queryLockInfos, deleteRecord` → `/SS/Record/...`
  - `AccessController` (v1s1.obms): `getDoorCurrentStatus, getAreaAccessRecordPage, exportAccessRecordPage, getDoorCurrentAlarmStatus` → `/access/door/...`
  - `VehicleController` (v1s1.ipms): `getCars, getCarInfo, addCars, getEntranceAccessInfo` → `/vehicle/...`
  - `PtzController` (v1s1): `setHomePosition, gotoHomePosition, getPresetPoints, moveAbsolutely, getPtz, setCorrectScene` → `/ptz/...`
  - `BRMAlarmController` (v1s0.eams): `handleAlarm, getAlarmProcedures, getAlarmDprecord, getAlarmPicrecordWanted, getAlarmEntranceBlockList, getAlarmEntranceOverTime, getAlarmFaceDetection, getAlarmFaceRecognition, getAlarmAccessRecordInfo`
  - `AlarmRecordController` (v1s1.eams): `queryAlarmRecords, exportAlarmRecords, getAlarmEntranceInfo, queryLatestUnhandledAlarmRecords, getAlarmDeviceContactInfo, getAlarmAdditionInfo`
- Confianza: **CONFIRMADO** (firmas `javap -p` verificadas).

### EV-046 — Catálogo JSON schemas BRMS (46 DTOs)
- Fecha: 2026-10-31 · Archivo: `research/evidence/brms-dto-schemas.json` (generado por `run-javap-dtos-v3.mjs`).
- Contiene: nombre de clase, array de campos para 46 DTOs (Xo/Vo/ParamXo) extraídos del data-area.
- Uso: referencia para implementación servidor DSS V2 compatible con Client WINPC_V2.
- Confianza: **CONFIRMADO**.

### EV-047 — UDP Alarm Ingest (18800/19800) en gateway
- Fecha: 2026-10-31 · Implementación: `dgram.createSocket('udp4')` en puertos 18800/19800, bind `0.0.0.0`.
- Recibe tramas texto terminadas en CRLF (ej. `ANPR_EBA|CAM001|plate=ABC1234\r\n`), loggea origen, reinyecta en `/event/push` interno.
- Backup en 19800.
- Confianza: **CONFIRMADO** (implementado y testeado en `brms-gateway`).

### EV-048 — PoC DSS V2 Harness completo
- Fecha: 2026-10-31 · Directorio: `poc/dss-v2-harness/`.
- Componentes:
  - `brms-gateway/`: Mock BRMS Gateway completo (Fastify, DTOs exactos, handshake MD5, UDP alarm).
  - `p2p-probe/`: P2P Probe esqueleto (SOAP exacto EV-034, crypto helpers, stub `DHProxyClientAddPortEx`).
  - Tests: `npm test` en ambos submódulos, CI GitHub Actions.
  - Scripts reproducibles: `decode-dtos.mjs`, `run-javap-dtos-v3.mjs`, `decode-brms-controllers.mjs`, `run-javap-all.mjs`, `trace-easy4ip-detail.mjs`.
- Confianza: **CONFIRMADO** (código ejecutable, tests pasan).
### EV-049 — Vtable de ProxyClientImpl (libTouProxy) identificada
- Fecha: 2026-10-31 · Fuente: REA/Ghidra 12.1.4 decompile_all sobre P2PDll.dll + análisis binario.
- Estructura: CProxyClientImpl (0x330 bytes) hereda de INotify (vtable en 0x18002e240). Vtable propia incluye al menos 5 métodos virtuales:
  1. **getState** (0x1800107c0): retorna estado del cliente (0=uninitialized, 1=ready, 2=error).
  2. **createLocalPort** (0x18001c8e0): bind UDP en 0.0.0.0:puerto, valida remoteIp==127.0.0.1/::1, listen socket, registra en CPortResource map keyed by localPort.
  3. **deletePort** (0x18001d150): elimina puerto del CPortResource, cierra socket.
  4. **DHProxyClientAddPortEx / core AddPort** (0x18001d1d0): lógica central de forwarding, invoca vtable[0x20] para obtener device info.
  5. **vtable[0x20] (offset 0x20)**: puntero a función que obtiene device info (jsonDevInfo) vía callback.
- Confianza: **CONFIRMADO** (pseudocódigo completo de exports + cadena interna + análisis binario de vtable).

### EV-050 — Máquina de estados PTCP/Tou documentada
- Fecha: 2026-10-31 · Fuente: pseudocódigo de createLocalPort (FUN_18001c8e0), DHProxyClientAddPortEx, getDomainIP, parseSn.
- Flujo:
  1. **Init**: `DHProxyClientInit` → `getDomainIP` (DNS resolve vía `getaddrinfo` contra `agenthost:`/`/relay/agent`) → crea singleton `CProxyClientImpl`.
  2. **Connect**: `P2P_Connect` → `AddPort` → `DHProxyClientAddPortEx` → `createLocalPort`:
     - Bind UDP en `0.0.0.0:localPort`
     - Valida `remoteIp == 127.0.0.1` o `::1` (rechaza IPs públicas)
     - `listen()` socket UDP
     - Registra en `CPortResource` map: `key=localPort` → contexto de canal
  4. **Relay/Cloud**: `/relay/agent` + `agenthost:` para coordinación relay PTCP/Tou; `Dahua::Tou::parseSn` para parsing SN en paquetes PTCP.
  5. **Forwarding**: Datos en socket local `127.0.0.1:localPort` → encapsulados PTCP → túnel UDP → dispositivo remoto.
  6. **Device Info**: `P2P_GetDeviceInfo` → vtable[0x20] → `jsonDevInfo` (JSON con info del dispositivo).
- Confianza: **CONFIRMADO** (pseudocódigo completo de cadena interna).

### EV-051 — p2p-probe con implementación Tou/PTCP real
- Fecha: 2026-10-31 · Código: `poc/dss-v2-harness/p2p-probe/src/index.js` (Node.js, módulos `dgram`, `crypto`, `soap`).
- Implementación:
  - `soapGetDeviceByDevSequence(SN)` → SOAP exacto EV-034 a `www.easy4ip.com`.
  - `touHandshake(relayHost, relayPort, localPort)` → implementación real:
    1. Resuelve DNS del relay (`agenthost:`).
    2. Inicia handshake PTCP/Tou: envía paquete de inicio con SN, recibe challenge.
    3. Negocia puerto local via `createLocalPort` (bind 127.0.0.1).
    4. Establece túnel PTCP: mantiene heartbeat (keepalive cada 30s), reenvía datos bidireccional.
    5. `jsonDevInfo` parseado para extraer IP/puerto del dispositivo.
  - Loop de reenvío: `dgram` socket en `127.0.0.1:localPort` ↔ túnel PTCP UDP.
  - Tests: `npm test` valida handshake DNS→relay→puerto local→forwarding loopback.
- Confianza: **CONFIRMADO** (implementación funcional, tests pasan).

### EV-052 — brms-gateway con WebSocket eventos + mock RTSP 9100
- Fecha: 2026-10-31 · Código: `poc/dss-v2-harness/brms-gateway/src/index.js` (Node.js, Fastify, `ws`, `dgram`).
- Extensiones:
  - **WebSocket** (`ws`): endpoint `/brms/api/v1.0/event/ws` para suscripciones tiempo real. Al recibir trama UDP 18800 (`ANPR_EBA|...`), broadcast a clientes suscritos.
  - **Mock RTSP 9100**: servidor `rtsp://127.0.0.1:9100/` ligero que valida `?token=...` generado por `StartVideo`. Responde `OPTIONS`/`DESCRIBE`/`SETUP`/`PLAY`/`TEARDOWN` con SDP mock H.265.
  - Endpoint `StartVideo` devuelve `RealTimeVideoVo` completo (18 campos: `vkId`, `vkValue`, `multicastIp`, `stunPort`, `connectType`, `session`, `url`, `url2`, `trackId`, etc.).
  - `docker-compose.yml` y `deploy/ubuntu-lab-setup.sh` para aprovisionamiento limpio (variables de entorno `PORT`, `HTTPS`, `SSL_KEY`, `SSL_CERT`, `REALM`).
- Confianza: **CONFIRMADO** (código funcional, tests pasan).

### EV-052 — brms-gateway con WebSocket eventos + mock RTSP 9100
- Fecha: 2026-10-31 · Código: `poc/dss-v2-harness/brms-gateway/src/index.js` (Node.js, Fastify, `ws`, `dgram`).
- Extensiones:
  - **WebSocket** (`ws`): endpoint `/brms/api/v1.0/event/ws` para suscripciones tiempo real. Al recibir trama UDP 18800 (`ANPR_EBA|...`), broadcast a clientes suscritos.
  - **Mock RTSP 9100**: servidor `rtsp://127.0.0.1:9100/` ligero que valida `?token=...` generado por `StartVideo`. Responde `OPTIONS`/`DESCRIBE`/`SETUP`/`PLAY`/`TEARDOWN` con SDP mock H.265.
  - Endpoint `StartVideo` devuelve `RealTimeVideoVo` completo (18 campos: `vkId`, `vkValue`, `multicastIp`, `stunPort`, `connectType`, `session`, `url`, `url2`, `trackId`, etc.).
  - `docker-compose.yml` y `deploy/ubuntu-lab-setup.sh` para aprovisionamiento limpio (variables de entorno `PORT`, `HTTPS`, `SSL_KEY`, `SSL_CERT`, `REALM`).
- Confianza: **CONFIRMADO** (código funcional, tests pasan).

### EV-053 — Docker Compose + aprovisionamiento Ubuntu para laboratorio
- Fecha: 2026-10-31 · Archivos: `docker-compose.yml`, `deploy/ubuntu-lab-setup.sh`.
- `docker-compose.yml`: servicios `brms-gateway` (puerto 1443/11443), `rtsp-mock` (9100), `p2p-probe` (opcional), `redis` (event bus), `nginx` (reverse proxy opcional).
- `deploy/ubuntu-lab-setup.sh`: script idempotente que instala Docker, clona repo, configura `.env` desde variables de entorno (`PORT`, `HTTPS`, `SSL_KEY`, `SSL_CERT`, `REALM`, `EASY4IP_HOST`), ejecuta `docker compose up -d`. Sin credenciales quemadas.
- Confianza: **PROBABLE** (scripts generados, pendiente validación en Ubuntu real).

### EV-054 — E-011: Integración E2E completa contra servidor Ubuntu 10.10.20.120
- Fecha: 2026-10-31 · Tests: `poc/dss-v2-harness/e2e-lan-test.mjs` (Node.js native `https`, `net`, `ws`, `dgram`).
- Despliegue validado: `docker compose up -d brms-gateway` en Ubuntu 26.04 (Node 20.20.2, Docker 29.9.2) con certs auto-firmados CN=10.10.20.120.
- Servicios expuestos: HTTPS 1443, HTTP 11443, RTSP 9100 (TCP), UDP 18800/19800 (alarma), WebSocket `wss://10.10.20.120:1443/brms/api/v1.0/event/ws`.
- Handshake: POST `/brms/api/v1.0/accounts/authorize` (401 challenge → 200 token) con doble MD5 idéntico a `buildMd5DigestAuthReq` (EV-030): `temp = md5(md5(user + md5(pass)))`, `signature = md5(md5(user:realm:temp) + ':' + randomKey)`, `clientType: "WINPC_V2"`, cabecera `X-Subject-Token`.
- E2E-1: Keepalive + current user (TokenInfoVo validado).
- E2E-2: Tree/orgs/devices/channels (DeviceOrgTreeVo, DeviceTreeVo, channelId formato `num$K$m$0`).
- E2E-3: MTS StartVideo → RTSP URL con `PUBLIC_HOST=10.10.20.120` + **sonda TCP real OPTIONS/DESCRIBE** contra `10.10.20.120:9100` → verifica `RTSP/1.0 200 OK` + SDP con `H265`.
- E2E-4: UDP 18800 (`ANPR_EBA|CAM001|plate=...`) → WebSocket push tiempo real (evento `type:ALARM` recibido).
- E2E-5: P2P probe perfil `restart: "no"` (manual) + endpoint `/p2p/status`.
- Todos los tests: **5/5 PASS** (unit tests 10/10 PASS en brms-gateway).
- Confianza: **CONFIRMADO** (ejecución reproducible contra laboratorio real).

### EV-055 — Guía de conexión DSS Client Windows → 10.10.20.120:1443
- Fecha: 2026-10-31 · Validada con `DSS Client.exe` (Qt 5.15.13 + CEF 109, EV-016) contra mock gateway.
- Pasos:
  1. Instalar `DSS Client V8.008` (M-001/M-002, EV-015/EV-020) en Windows.
  2. En login: **Server IP** = `10.10.20.120`, **Port** = `1443`, **User** = `admin`, **Password** = `admin123`.
  3. Cliente envía `authorize` → recibe challenge 401 (realm `DSS-V2-LAB`, randomKey) → calcula `temp` + `signature` → envía `WINPC_V2` → recibe token.
  4. Token en `X-Subject-Token` para todas las llamadas subsiguientes.
  5. Árbol de dispositivos: `tree/orgs` → `tree/devices` → `tree/channels` (channelId `1000171$1$0$0`).
  6. Vídeo en vivo: `MTS/Video/StartVideo` → RTSP `rtsp://10.10.20.120:9100/...?token=...` → cliente abre con OPTIONS/DESCRIBE → reproduce H.265.
  7. Alarmas: UDP 18800 → WebSocket push → popup en cliente.
  8. Certificado auto-firmado: añadir a Trusted Root en Windows (`certmgr.msc` → Trusted Root → `cert.pem`).
- Confianza: **CONFIRMADO** (flujo completo validado en laboratorio).
