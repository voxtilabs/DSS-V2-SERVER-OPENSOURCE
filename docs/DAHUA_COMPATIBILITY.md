# DAHUA_COMPATIBILITY.md — SDKs oficiales, versiones y licencias

## 1. NetSDK (SDK oficial de integración a dispositivos)

| Aspecto | Estado | Evidencia |
|---|---|---|
| Existe versión Linux x86_64 | **CONFIRMADO** (NuGet `Dahua.NetSDK.Native` v3.57.2023.309 incluye `linux-x64`; vías históricas con libs lin64 por Download Center) | EV-004 |
| API cubre login/canales/video/playback/PTZ/alarma | CONFIRMADO por Programming Guide (`CLIENT_Init/LoginEx2/RealPlay/PlaybackByFile/…`) | EV-004 |
| Puerto estándar de dispositivo | 37777 (privport) | EV-004/EV-013 |
| P2P integrado en el SDK standalone | **NO OPERATIVO** según reporte (requiere `libP2PDll` + credenciales de app) | EV-005 |
| Lenguaje de integración en DSS V2 | C++ directo (FFI hacia .so) | ADR-0002 |

### Reglas del proyecto sobre el SDK
1. Los binarios del SDK **nunca** se commitean. Se descargan del canal oficial, se registran con
   Sha-256 y fecha en `research/evidence/sdk-manifest.md` (fuera de git), carpeta local avalada.
2. Este repositorio no redistribuye el SDK: quien clone necesita obtenerlo por su propia vía legal.
3. Cualquier envoltorio (wrapper) que escribamos vive en `components/p2p-connector/vendor/…` con notas
   de integración, sin incluir el binario nativo.

## 2. Matriz de compatibilidad objetivo (por llenar en E-002)

| Dispositivo | Modelo | Firmware | NetSDK login | Canales | RealPlay | Playback | Eventos |
|---|---|---|---|---|---|---|---|
| NVR de laboratorio | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## 3. Ecosistema de productos De Dahua (referencias)

| Producto | Rol en el ecosistema | Información |
|---|---|---|
| DSS Professional / Ultimate V8.x | VMS licenciado de referencia; puerta OpenAPI por definir | dahuasecurity.com, EV-003 |
| DSS Express | Variante de DSS para SMB | catálogo |
| DSS7016D appliance | producción actual (VMS embebido) | EV-010 |
| SmartPSS | client ligero para dispositivos (liga P2P `libP2PDll`) | EV-005 |
| DMSS / gDMSS | móviles con P2P por SN | EV-006 |
| DoLynk / Imou clouds | nube IoT de consumo (DoLynk Developer) | EV-009 |

## 4. Puntos de licencia y cumplimiento

- EULA del instalador: prohibida la ingeniería inversa salvo límites legal aplicable. Trabajamos con
  el "fair use"/excepción de interoperabilidad solo con ejecutables que la organización administra y
  analizando localmente; NO redistribuimos nada.
- No se requiere desactivar (bypass) la activación/licencia: nuestro laboratorio usa licencias de
  prueba y dispositivos propios. Nunca se elude, ni se publica cómo hacerlo (ADR-0003).
- SDK: redistribución restringida; mencionar a Dahua si el proyecto crece (vía Partner, EV-008).

## 5. Multi-fabricante (fase posterior)

Interoperabilidad Open: cualquier driver ONVIF/Generic-RTSP debe ser plugin separado; por ahora el
alcance es Dahua-first.
