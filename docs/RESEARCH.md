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
