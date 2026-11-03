# E-035 — Catálogo real de menús/derechas: seed SQL del servidor (p_data.sql)

Fecha: 2026-11-03 · Fuente: registro `p_data.sql` del paquete V8.008
(dump-record2.mjs -> 986 137 bytes) + parser `parse-seed-sql.mjs`

## Tablas del seed (INSERT INTO contados)

    sys_code x3335 | sys_code_type x190 | sys_menu x86
    sys_role_menu_default_relation x235 | sys_menu_privilege x167
    adm_config x141 | sys_timezone x134 | adm_role_function x18
    adm_dev_privilege x8 | sys_role x2 | sys_organization x1
    sys_user x1 | sys_user_role x1 | sys_user_ext x1 | sys_version x2
    adm_role_privilege x2 | (+ caduces/veedores/tiempos)

## Claves lesídas

- sys_menu row 1: (1,'001','menu.basic.basicConfiguration',...,
  SYSTEM_CODE='2', MEMO='basicConfiguration', SORT=1, STAT=1, MAP_TYPE=2)
  -> menuCode=MENU_CODE ; menuNameKey=MENU_NAME (i18n) ; menuName=MEMO.
- sys_role_menu_default_relation: ROLE_TYPE 1 -> 86/86 menus (SUPER ADMIN),
  ROLE_TYPE 2 -> 81, ROLE_TYPE 3 -> 68. Aliases que faltaban en leveldb y los
  añadidos REALS: 001,002,003,004,010,002005004,002007002-4,003001002,
  004002003,004003002,004004004,004004005.
- adm_role_function: ROLE_ID=1 FUNCTION IN (1,2,3,5,6,8,9,10,11); ROLE_ID=2 el
  mismo set (18 filas). Codes validados contra el enum
  com.dcc.admin.restapi.common.constant.FunctionType (javap -c):
    record='1' recordLock='5' recordTips='6' ptzOperateAndConfig='2'
    ptzOperate='13' talk='3' liveView='8' playback='9' download='10'
    privacyMasking='11' syncTime='15' livePreview='17' deviceWeb='21'
    broadcast='23' playAudio='24' controlVolume='25' panoramicSplicing='27'
- adm_dev_privilege ROLE_ID=1: (8 liveView, 9 playback, 10 download,
  11 privacyMasking) NODE_TYPE=2 NODE_CODE='001' -> Live View/playback para
  todos los dispositivos del árbol raíz.
- sys_organization: ORG_CODE='001', ORG_NAME='root', ORG_TYPE='1', DOMAIN_ID
  '0' -> raíz REAL del gateway (antes "Root Org" inventado).
- sys_user: LOGIN_NAME='system' (hash md5 24815fb9...), no credenciales
  commiteadas en ningún repo.

## Limitación documentada (no adivinada)

- MENU_NAME localizado: las cadenas i18n (`menu.basic.basicConfiguration` -> ...)
  residen en la tabla MyISAM `func` del DB en runtime del instalador; su par
  `.MAD/.MAI/.frm` existe en el paquete pero el contenido extraído viene vacío
  (assign 8 KB). Se sigue 1:1 con el campo REAL `MEMO`.
- Catálogo `func` (functionCode->nombre/pid) mismo caso; se usa el enum
  Java EXTRAÍDO de bytecode como fuente de verdad.
- GetMenuRights: union(158 leveldb, 86 seed) = 172 códigos, todos REALS.
