# E-037/E-038 — Extracción de DTOs del paquete real del servidor DSS V8.008

Fecha: 2026-11-03 · Fuente: `General_DSS-Ultimate_Server_Win64_IS_V8.008.0000000.0.R.20260930.exe`

## Método (100% del paquete, cero invención)

1. Índice de registros: `outer-db.bin` (dssserver-analysis) — ancla `u32==83886224`,
   nombre UTF-16 en `2042608 + rel*2`, offsets `d2` en `h+4/@8`, `d1` en `@44`.
   Herramienta: `%TEMP%\opencode\list-server-records.mjs` (41 055 registros).
2. Extracción por clase: bloque LZMA (marker `5d 33 37 23 00`) en `d2 + 772125`,
   header LZMA sintético {0x5d, 0x00800000, -1} y 7z `-tLzma -so`, después
   `javap -p` / `javap -v -p` (JDK 25). Herramientas:
   `extract-dto-by-d2.mjs`, `extract-server-dto.mjs`, `rec-header.mjs`.
3. Recursos (properties/xml): mismo pipeline con `dump-record2.mjs` (ventana
   LZMA por registro).

## DTOs recuperados (javap)

    com.dcc.admin.restapi.api.v1s0.vo.tree.DeviceOrgTreeVo
      private java.util.List<OrgNodeVo> departments;
    com.dcc.admin.restapi.api.v1s0.vo.tree.DeviceTreeVo
      private java.util.List<DeviceInfoVo> devices;
    com.dcc.admin.restapi.api.v1s0.vo.tree.OrgNodeVo{code, parentCode, name,
      orgType, modifyTime, deparmentsCount, domainId,
      List<OrgDeviceNodeVo> device, List<OrgChannelNodeVo> channel,
      sn, sourceType, sourceId, associateId, remark, authority}
      (OrgDeviceNodeVo/OrgChannelNodeVo = {id, sort})
    com.dcc.admin.restapi.api.v1s0.vo.tree.DeviceInfoVo (25 065 B):
      code,name,category,type,model,deviceModelStr,status,offlineReason,
      protocol,manufacturer,deviceIp,devicePort,registId,proxyIp,proxyPort,
      userName,password,callNumber,loginType,sn,alarmRecordPosition,
      capability,orgCode,units:[DeviceUnitInfoVo],sipId,sipPwd,
      bindingConfirmVtoDeviceCodes,unitEnable,buildingEnable,liftEnable,
      softwareVersion,hardwareVersion,domainId,modifyTime,isVideoNexus,
      timezone*,enableDst,dst*,serverCode,sourceType,sourceId,associateId,
      authority,solarBattery
    com.dcc.admin.restapi.api.v1s0.vo.tree.DeviceUnitInfoVo (29 382 B):
      unitType,unitSeq,assistStream,zeroChnEncode,ssServiceId,ptsServiceId,
      streamType,decodeMode,streamMode,conbineStatus,thirdPartyControl,
      voice*,dyn*,fingerPrintAuth,cardAuth,faceAuth,palmVeinAuth,userIsolate,
      unlockModes,parkingStatisticsMode,...,channels:[DeviceChannelInfoVo]
    com.dcc.admin.restapi.api.v1s0.vo.tree.DeviceChannelInfoVo:
      channelCode,channelName,channelSeq,status,sn,gpsX,gpsY,mapId,cameraType,
      channelType,remoteType,channelSubtype,cameraFunctions,multicast*,ipcIp,
      recordType,forPeopleCount,maxSplitNum,interfaceType,alarm*,signalType,
      accessType,pos*,dynCode,faceFunctions,keyCode,db33Code,intelliState,
      faceAnalyseType,videoSource,targetDetection,capability,domainId,floorNum,
      floorInfos,parentTargetSeq,streamType,parkingSpaceMode,orgCode,solarBattery

## Mapeos del DeviceTreeController (676111183, 37 350 B)

    @RequestMapping(value="/deviceOrg", method=GET) + @AuthCheck(menuCode PUBLIC)
    @RequestMapping(value="/devices", method=POST)  [poolUtf8 1156/1157]
    Ordena por `sort` (#185), construye channelInfos/deviceUnitInfos,
    ChannelIdUtils.getDeviceCode/splitChannelNodeCode/getUnitType,
    RolePrivilegeService.getPrivilegeChannelCodes.

## Constantes de dominio

    com.dcc.admin.common.constants.device.UnitType  (673661863):
      Encoder=1, Decoder=1? -> bipush/iconst constants; Encoder("//channel.video
      /"adm_dev_encoder_"), Decoder("channel.decoder","adm_dev_decoder_"), ...
    com.dcc.admin.common.constants.ChannelCategory (673593134):
      VideoChannel="1", ItcChannel="2", VideoItcChannel="3", PosChannel="4"
    com.dcc.omms.common.constants.LoginType (995431588):
      DIRECT_LOGIN=0 REGIST=6 PROXY_LOGIN=7 MCD=8 ONVIF=9 GB28181=10 P2P=14
      RTSP=15 (iconst/bipush + String hex codes)
    DeviceInfoUtil.getAddType (995643482): rtsp / onvif / gb28181 / regist /
      sn / ip / domain + regex IPv4 de Constants
    com.dcc.admin.common.constants.DeviceCategory (673595697): ENCODER_DEVICE,
      DECODER_DEVICE, ALARM_HOST, SCREEN, ITC_DEVICE, MATRIX_DEVICE,
      INTELLIGENCE_DEVICE, ACCESS_CONTROL, DYN_ENV, VOICE, TRANSCODER, ...
    DeviceResourceEnum (670071729).getChannelResourceType(String):
      ChannelIdUtils.isChannelId -> getUnitType -> UnitType.getByType

## Checkpoint

Todos los builder del gateway (`src/e037-native-tree.js`) derivan EXACTAMENTE de
estos nombres de campo: `departments`, `devices`, `device`, `channel`,
`unitType`, `channelCode`, `channelSeq`, `channelType="1"`, `loginType`,
`addType`. El alias web (`orgList`/`deviceList`) se añade ADICIONALMENTE, nunca
en lugar del contrato nativo.
