# E-037 — DPSDK.dll string pool: las claves que parsea el cliente nativo

Fecha: 2026-11-03 · Binario: `C:\DSS\DSS Client\DPSDK.dll` (real 8.006 WINPC_V2)
Herramienta: `%TEMP%\opencode\strings.mjs` + `findstr.mjs` (range scans del PE)

## RPC de árbol (asientos adyacentes clave — el parse key va INMEDIATO al method)

    0xcdcbe0  ResourceTreeGetDevices      | 0xcdcbf8 Resource.Tree.GetDevices
              previo: 0xcdcbb8 categories / 0xcdcbc8 containVirtualDevice
    0xcdd0f8  ResourceTreeGetDeviceOrg    | 0xcdd118 Resource.Tree.GetDeviceOrg
              0xcdd138 departments                        <<< CLAVE DEL PARSEO
    0xcdd1c8  ResourceDeviceGetDeviceByOrgCode | Resource.Device.GetDeviceByOrgCode
    0xcdd520  ResourceTreeGetDeviceTree   | 0xcdd540 Resource.Tree.GetDeviceTree
              vicino: 0xcdd510 privilegeCode / isParent / parentName
    0xcddce0  ResourceDeviceCreateDeviceOrg | Resource.Device.CreateDeviceOrg
    0xcddd90  ResourceDeviceGetDeviceOrg

## Claves del DTO (bloque 0xcacexx–0xcadxxx, mismo orden que javap)

    0xcacdc8 channelSeq / 0xcaccc8 unitSeq / 0xcacd00 unitType  (bloc parse alarmas)
    0xcad0a0 modifyTime / 0xcad0b0 deparmentsCount (typo REAL del servidor)
    0xcad094 orgs, 0xcad0d8 addOrgCode, deleteOrgCode, callNumber, units,
    0xcad170 serverCode, code, name, protocol, streamProtocol, encrypType,
    manufacturer, userName, password, type, category, model, deviceModelStr,
    secretKey, accessKey, isVideoNexus, deviceIp, devicePort, proxyIp,
    proxyPort, sipId, sipPwd, enableUnit, enableBuilding, enableLift, linkMode,
    bindingConfirmVtoDeviceCodes, softwareVersion, hardwareVersion,
    protocolVersion, loginType, timezoneId/Name/Offset, enableDst, dstType,
    dstBeginTime (month/week/day/time), dstEndTime, cameraType, cameraFunctions,
    faceFunctions, multicastIp/Port, ipcIp, remoteType, keyCode, db33Code,
    roadway, cartMax/MinSpeed, dollyMax/MinSpeed, direction, pcFlag,
    targetDetection, encoderChannelType, zeroChnEncode, parkingStatisticsMode,
    channelType, channelSubtype, maxSplitNum, decodeMode, conbineStatus,
    alarmLevel, parentTargetSeq, parentTargetName, subsystemSeq,
    thirdPartyControl, fingerPrintAuth, cardAuth, faceAuth, userIsolate
    0xcacf00-sequence: deviceCode, onlineStatus, capability, intelliState,
    deviceCodes, sleepMode, session, orgCode, orgName, remark, parentOrgCode,
    sort, domainId, sourceType, sourceId, associateId, sn, roleIds, authority,
    orgCodes, <NodeIDs><NodeID></NodeID></NodeIDs>, oldOrgCode, oldParentCode,
    parentCode, successfulCount, failedCount, operation

## RPC/derechas usuario

    0xcc80d0 menuPath1/menuName/menuIcon2/.../menuCode/isMenu/isDataScope
    0xcd9364 menuId/functionNodes/function (GetWebPort context)
    0xc9bfe5 "menu/....../available" CheckMenuAvailable / pFuncList /
      Dpsdk::CRestLogical::GetAvailableFunctions / v1.1/function/available/list

## Conclusión

El cliente nativo BUSCA `departments` tras `Resource.Tree.GetDeviceOrg`; el
gateway servía `orgList` -> árbol nativo vacío en Live View / Monitoring /
Storage aunque el SPA web mostrara el dispositivo (el bundle web lee
`deviceList`/`orgList`). La corrección E-037 sirve ambos conjuntos de claves.
