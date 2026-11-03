# E-038 — channelId real: bundle web de producción + server bytecode

Fecha: 2026-11-03 · Fuentes: `web-module/js/*` (bundle REAL 8.006 de
`/web/client-module/`) + bytecode del paquete servidor V8.008.

## 1. Bundle — UNIT_TYPE (device-JBrSmGvP.js, línea 2)

    UNIT_TYPE:{ENC:"1",DEC:"2",ALARM_IN:"3",ALARM_OUT:"4",TVWALLIN:"5",
    DOORCTRL:"7",VOICE:"8",POS:"11",VIRTUAL:"12",LED:"15",CVI_ALARM:"16",
    ALARM_BOX:"17",AL:"18",EAS:"21",SIRENOUT:"22",IP_SPEAKER:"23",UVSS:"24",
    BOX_ALARM_OUT:"26",RADAR:"43",LIFT_CONTROL:"50"}

## 2. Bundle — construcción del channelId (index-Cr8Ld85_.js)

    I.editDeviceInfo.deviceCode+"$"+xe.UNIT_TYPE.ENC+"$0$"+e.channelSeq
    -> <deviceCode>$1$0$<channelSeq>        (canal de vídeo, ENC=1)

Decoder / TV wall (index-BQObycDy.js):

    e.channel = e.code+"$2$0$"+e.seq        (unitType DEC=2)

Registro de ejemplo con vehículo real (index-BVkN0CUs.js):

    channelId:"1000016$1$0$6"               (channelSeq=6 del device 1000016)

## 3. Servidor — mismo layout

    com.dcc.admin.common.constants.device.UnitType  Encoder -> code "1"
    DeviceResourceEnum.getChannelResourceType(String channelId):
      ChannelIdUtils.isChannelId(channelId) -> getUnitType(channelId) ->
      UnitType.getByType(...)   => segmento 2 = unitType
    DeviceTreeController (676111183) llama ChannelIdUtils.getDeviceCode /
    splitChannelNodeCode.

## 4. Bug previo corregido

Antes: `channelId = <code>$<channelNo>$0$0` — el 2.º segmento llevaba el
NÚMERO de canal; un 2.º canal se parseaba como DECODER (unitType=2) y el
cliente enrutaba el vídeo/acciones al subsistema erróneo.
Ahora: `<code>$1$0$<channelSeq0>` (E-038) en TODOS los builders
(channelVo, allChannels, árbol nativo, channel/list, StartVideo, planes).

Formatos verificadão en vivo (127.0.0.1:11443): "D00712RD0005$1$0$0",
"ONVIF-0238$1$0$0" — todos con segmento 2 = "1".
