# E-034/EV-084 — Provisión de stream por dispositivo: MediaMTX control API real

Fecha: 2026-11-03 · Gateway desplegado 10.10.20.120 · MediaMTX **v1.11.3**
(imagen local, Dockerfile oficial del repo) · verificación live 15/15.

## Problema

Toda provisión de `cam_<deviceCode>` fallaba en el gateway desplegado:

    [E034-STREAM] {... "source":"dahua-convention","configured":false}
    mediamtx: INF [RTSP] conn closed: path 'cam_xxx' is not configured

Tres causas raíz, diagnosticadas con trazas reales (nunca adivinadas):

1. **La API de control de MediaMTX estaba APAGADA** (puerto 9997 cerrado).
   El `mediamtx.yml` tenía `apiAddress: :9997` pero faltaba `api: yes`
   (por defecto la API no arranca).
2. **La API exige autenticación interna**. MediaMTX solo concede permisos de
   API a localhost por defecto; el brms-gateway entra desde la red docker
   (172.18.0.0/16) → 401 con `WWW-Authenticate: Basic`. Solución sin
   credenciales en el repo: `authInternalUsers` con `user: any`, `ips:
   [172.18.0.0/16]`, `permissions: [{action: api}]` (+ metrics). Formato real
   de v1.11.3: los entries de `permissions` son objetos `{action: ...}` (los
   strings crashean el binario con `json: cannot unmarshal string into ...
   AuthInternalUserPermission`).
   **IMPORTANTE (vecino aprendido en vivo)**: `publish/read/playback` deben
   permanecer ABIERTOS a toda IP (entry aparte con `ips: []`). La primera
   versión restringía `read` a la red docker y TODO DESCRIBE externo (LAN,
   donde vive el DSS Client nativo) respondía `401 Unauthorized` — verbalizado
   por el propio e2e (E2E-3: DESCRIBE 401 con `realm="IPCAM"` tras reparar la
   provisión). Solo api/metrics van por IP interna.
3. **Endpoints incorrectos en `configureMediaMTXPath`**. Router REAL de
   v1.11.3 (fuente: `internal/api/api.go` de la release):
       GET    /v3/config/paths/list          GET /v3/config/paths/get/<name>
       POST   /v3/config/paths/add/<name>
       PATCH  /v3/config/paths/patch/<name>  (alterar existente)
       POST   /v3/config/paths/replace/<name>
       DELETE /v3/config/paths/delete/<name> (NO existe /v3/paths/configure
              ni /v3/config/paths/remove)
   El código viejo llamaba a un endpoint inexistente → `configured:false`
   silencioso (searchPath catch devolvía false).

## ONVIF (la fuente RTSP de la cámara lab) — segundo hallazgo

`discoverOnvifStreamUri` devolvía null aunque la cámara es ONVIF operativa.
Causa exacta (SOAP crudo, diag desde el contenedor):

- La cámara sirve el servicio Media en **`/onvif/media_service`**, anunciado
  en su GetCapabilities (`<tt:Media><tt:XAddr>`); `/onvif/media` responde
  `<tds:wsdlResponse/>` vacía.
- **La cámara valida el SOAPAction completo por operación**: con
  `SOAPAction: "http://www.onvif.org/ver10/media/wsdl/GetProfiles"`
  responde 2946 B con `Profile_1`; con la action genérica
  ".../media/wsdl" contesta un envelope vacío de 359 B.
- Prefijos SOAP tipo `s:`/`tt:` → regexes namespace-agnósticos.

Fix implementado (flujo estándar ONVIF): GetCapabilities (device_service)
→ Media XAddr → GetProfiles en el XAddr anunciado → GetStreamUri con la
acción `.../GetStreamUri` + WSSE UsernameToken (PasswordDigest = 
base64(sha1(nonceB64 + password + created))) cuando hay credenciales.
Resultado verificado en vivo:

    discoverOnvifStreamUri('192.168.0.238', 8021)
      -> rtsp://192.168.0.238:8554/EBA1_LECTOR   (H.265, exacta a EV-013)

## Verificación final (live-verify.cjs contra el gateway desplegado)

15/15 OK: login 2 pasos, add ONVIF (probe real AI Sentinel/EBA1_LECTOR_FHD_H265),
device/page, árbol nativo departments+devices con DeviceInfoVo
(status=1, loginType=9, unitType=1), grade-device-tree, channel/list
(`code$1$0$0`), device/{code}, StartVideo →
`rtsp://10.10.20.120:9100/cam_<code>?token=...`, **DESCRIBE RTSP real →
RTSP/1.0 200 OK**, view-tree 2 viewInfos, cleanup (device AND MediaMTX path
removed vía DELETE). Registro queda vacío (solo dispositivos del operador).
