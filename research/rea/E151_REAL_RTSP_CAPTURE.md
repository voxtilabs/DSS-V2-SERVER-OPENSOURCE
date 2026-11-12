# E-151 — Captura REAL del protocolo (Frida sobre el cliente DSS en producción)

Método: Frida adjunto a **MDP.exe** (el proceso de media del DSS Client; la GUI
no habla RTSP). Hooks en `WS2_32.dll!send/recv/WSASend/WSARecv`. Server real:
`192.168.0.71:9100` (misma instalación que el 200: mismo `realm`).

## 1. Secuencia RTSP real (cliente -> server)

```
OPTIONS * RTSP/1.0
Content-Length: 0
CSeq: 119

SETUP rtsp://192.168.0.71:9100/mediaServer/monitor/param/cameraid=1000013%240%26substream=1?token=650307 RTSP/1.0
Content-Length: 0
CSeq: 113
Transport: RTP/AVP/TCP; interleaved=0-1;playmode=playback

PLAY  rtsp://192.168.0.71:9100/mediaServer/monitor/param/cameraid=1000013%240%26substream=1?token=650307 RTSP/1.0
Content-Length: 0
CSeq: 114
Session: 2990373496966;timeout=60

TEARDOWN (misma URL) CSeq: 115 Session: 2990373496966;timeout=60
```

## 2. Respuestas reales del server

```
RTSP/1.0 200 OK
Server: Dahua Rtsp Server/2.0
CSeq: 113
Session: 2990373496966;timeout=60
Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=007387F3
x-dynamic-rate: 1

RTSP/1.0 200 OK
Server: Dahua Rtsp Server/2.0
CSeq: 114
Session: 2990373496966
RTP-Info: url=;seq=27010;rtptime=21446370;ssrc=007387F3
Range: npt=0.000000-

RTSP/1.0 200 OK            (a un OPTIONS *)
Server: Dahua Rtsp Server/2.0
CSeq: 119
Session: 2990371744690
Public: OPTIONS,DESCRIBE,SETUP,PLAY,PAUSE,TEARDOWN,SET_PARAMETER,GET_PARAMETER
```

Detalles:
- URL = la que entrega el server, con forma
  `/mediaServer/monitor/param/cameraid=<id>%24<seq>%26substream=<n>?token=<6 dígitos>`
  (`%24` = `$`, `%26` = `&`). El cliente NO la modifica ni añade trackID.
- `Transport` del cliente incluye `;playmode=playback`.
- El server responde SIEMPRE `Server: Dahua Rtsp Server/2.0` y en SETUP agrega
  `;timeout=60`, `;ssrc=<8 hex>` y `x-dynamic-rate: 1`.
- No hay DESCRIBE ni SDP en ninguna parte del flujo.
- `OPTIONS *` periódico lleva CSeq y la respuesta trae `Session` + `Public` sin
  espacios.

## 3. Payload RTP: header privado Dahua "DHAV"

RTP estándar (V=2) con `PT=0x6a` (H.265) o `0xea` (H.264) y `SSRC` = el
anunciado en el SETUP. **El payload empieza con el header privado Dahua**:

```
44 48 41 56 | fc 00 00 00 | <counter u32 LE> | <u32 LE> | <unix seconds u32 LE> | ...
"DHAV"        flags          por-stream        ?          epoch (0x6ad8ae6a)
```

Ejemplos reales (payload desde el byte 0, tras el header RTP de 12 B):

```
DHAV fc000000 91ff2304 fb080000 6a aed86a 81fc0cbc 8000a05a 811e0c1e 94020100 00000001 0203d2b7...
DHAV fc000000 0b9a0000 f0210000 6b aed86a 26160874 88c7322b 33000000 00000001 460130...
DHAV fc000000 92ff2304 84150000 6a aed86a a2fc0c74 8000a05a 811e0c1e 94020000 00000001 0201d2df...
```

- `counter` (offset 8) es un contador del stream (consecutivo entre frames).
- offset 16 = timestamp Unix (segundos).
- Tras el header, el bitstream va en Annex-B (`00 00 00 01` + NAL):
  H.264 visto con `00 00 00 01 46 01 30` (SEI) y H.265 con `00 00 00 01 02 03 ...`
  (TRAIL_R). El largo exacto del header parece variar según codec
  (~32 B en H.264, ~36 B en H.265 en estas muestras).

Conclusión operativa: el cliente Dahua NO consume RTP "puro"; su pipeline
demuxea el header privado DHAV. Nuestro gateway (MediaMTX) entrega RTP estándar
con el H.265 crudo, sin ese header — candidato principal del "Operation failed"
del tile en nuestra red.

## 4. Pendiente

1. Decodificar el struct DHAV completo (REA sobre MDP.exe / DPSDK: xref de la
   cadena "DHAV") para sintetizarlo en el relay 9100 antes de cada payload RTP.
2. Verificar si `Server: Dahua Rtsp Server/2.0` hace que MDP espere DHAV
   (probar con y sin ese header contra nuestro gateway).
3. Comparar con el flujo cuando el cliente reproduce desde nuestro gateway.
