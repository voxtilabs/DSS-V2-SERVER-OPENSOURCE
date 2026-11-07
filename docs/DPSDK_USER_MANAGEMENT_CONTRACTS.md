# DPSDK / UserLogical — User & Role Management JSON Contracts (DSS Client 8.006, WINPC_V2)

Fuente: ingeniería inversa de `DPSDK.dll` (SHA256 `CE43C8B7…C0D47`, imagebase `0x180000000`) y `UserLogical.dll` (`99D5086A…160D9`) con Ghidra/REA. Evidencia: RE-S101/E-104 (nov 2026). Offsets en formato RVA/file-offset.

## 0. Motor genérico de parsing (DPSDK.dll)

| pieza | RVA | file offset | rol |
|---|---|---|---|
| `FUN_1807512d0` | 0x7512d0 | 0x7506d0 | `addField(tabla, offset, type, key, isArray)` |
| `FUN_1807513e0` | 0x7513e0 | 0x7507e0 | `addChild(tabla, offset, size, key, isArray)` |
| `FUN_180754c60` | 0x754c60 | 0x754060 | aplica descriptor al JSON (JSON → slots) |
| `FUN_18074d390` | 0x74d390 | 0x74c790 | lee envelope y despacha al descriptor |
| `FUN_18074e3c0` | 0x74e3c0 | 0x74d7c0 | callback HTTP de respuesta |

**Semántica de `type`** (leída en `FUN_180754c60`):

| type | exige nodo JSON | slot | si el nodo no coincide |
|---|---|---|---|
| 0 | int (3) | 4 B | 0 |
| 1 | bool (0/1) | 4 B | — |
| **2** | **string (4)** | 8 B (`char*`) | **NULL silencioso, SIN coerción** |
| 3 | real | 8 B | — |
| 100 | array/objeto | recursión | rama objeto con contador NULL → `puVar16[2]` (riesgo null-deref) |

**Envelope obligatorio** (`FUN_18074d390`, literales `code`@0xcad104, `desc`@0xca3d4c, `data`@0xcaddc4):

```json
{ "code": 1000, "desc": "Success", "data": { … } }
```
- `code`: **int** (1000 = OK; 200 se normaliza a 1000).
- `desc`: string (si presente y no string → error −1).
- `data`: objeto/array (si presente y del tipo erróneo → error −1, no crash).
- Ningún header/estado HTTP: solo el cuerpo importa.

**Regla de oro**: solo la clave-raíz de la tabla descriptor se acepta (case-insensitive). Servir `data.list` cuando el nativo pide `data.results` ⇒ 0 filas sin error (y la UI espera datos que nunca llegan → cuelgue esperando).

## 1. Envelope-side del gateway

Nuestro `envelope(data, code=1000, desc='Success')` cumple: `code` entero 1000, `desc` string, `data` objeto. Los flags de los rows viajan SIEMPRE como `"1"/"0"` (string) — un número donde se espera string deja el campo NULL y el `atoi` del nativo lo vuelve 0.

## 2. Roles

### 2.1 `GET /brms/api/v1.1/role/list` (diálogo nativo)
- Cliente: `CRestLogical::GetUserRolesList` RVA 0x28e7e0; URL literal `v1.1/role/list` @0xc9c130.
- Parser `FUN_1806f2690` (0x6f2690): raíz **`results`** (array) + items (stride 0x28):
  `allowEdit`(+0x00), `id`(+0x08), `roleType`(+0x10), `roleName`(+0x18), `memo`(+0x20) — **strings**.
- `FUN_18028e7e0`: `allowEdit`/`roleType` → `atoi` → int; el resto `char[]`.
- Callback UserLogical `FUN_18005fa00` código `0x258d`: copia `id`(0x40), `roleName`(0xfa), `memo`(0x400) + dos int constantes (3, 0).
- **Sin `totalCount` en este descriptor.**
```json
{"code":1000,"desc":"Success","data":{"results":[
  {"id":"1","roleName":"Administrator","roleType":"1","allowEdit":"0","memo":"Built-in administrator"}
]}}
```

### 2.2 `GET /brms/api/v1.1/role/page`
- `CRestLogical::GetUserManagerRoles` RVA 0x29fb10; URL @0xc9cf00.
- Parser `FUN_1806c6280`: raíz **`pageData`** (array) + **`totalCount` string**; mismos 5 campos string.
```json
{"code":1000,"desc":"Success","data":{"pageData":[{…}],"totalCount":"2"}}
```

### 2.3 `GET /brms/api/v1.1/role/all/list`
- Mismo handler servido por el gateway; shape superpuesto (`pageData`+`results`+`list`).

## 3. Usuarios

### 3.1 `GET /brms/api/v1.1/user/page`
- Request `FUN_1806c88b0` (query, todo string): `username`, `online`, `groupId`, `hasFieldOfenableMPT`(bool), `enableMPT`, `pageSize`, **`roleIds`** (string, se envía tal cual, el cliente NO trocea), `page`, `userType`.
- Response `FUN_1806c8d20`: raíz **`pageData`** (array, item 0x58) + **`totalCount` string**.
- Item: `username`(+0x00), `online`(+0x08), `name`(+0x10), `enableMPT`(+0x18), `id`(+0x20), `roles[]`(+0x28; item 0x10 = `roleName`+0x00, `roleId`+0x08), `status`(+0x48), `userType`(+0x50) — **todos string**.
- Struct nativo 600 B: `status`/`online`/`userType` → `atoi`, `enableMPT` → bool, el resto `char[]`.
- SPA `index-BQObycDy.js@0x74c9` (userGroupView): lee `data.pageData` → `{value:e.id, label:e.username}`.
```json
{"code":1000,"desc":"Success","data":{"pageData":[
  {"id":"1","username":"admin","name":"Administrator","online":"1","status":"1",
   "userType":"1","enableMPT":"0","roles":[{"roleId":"1","roleName":"Administrator"}]}
],"totalCount":"2"}}
```
- **E-105: el payload de `user/page` es ESTRICTO.** No se sirven alias (`list/results/items/userList`, `total/page/pageNo/pageSize/pageCount`) ni hojas que sean arrays JSON (`roleIds:["1"]`, `roleNames:[…]`, `roleIdArray`, `roleNameArray`): el descriptor nativo declara **kind=2 (string) para todas las hojas** de la fila y sólo admite dos arrays en todo el cuerpo (`data.pageData` y `data.pageData[].roles`). El SPA `userGroupView` (`index-BQObycDy.js`) sólo lee `data.pageData[].id` y `data.pageData[].username`, ambos nativos, por lo que el payload estricto no rompe la web.
- `data.totalCount` = **número total de usuarios que casan** (string decimal), no el número de filas de la página. Ver §10.2: el nativo lo consume con `atoi` y lo pasa a `DSNumberPageCtrl::SetTotalCount` (paginador), mientras que el bucle de pintado está acotado por el tamaño real del vector (`pageData.length`).
- Body canónico (386 B) servido por el gateway tras E-105:
```json
{"code":1000,"desc":"Success","data":{
  "pageData":[
    {"id":"1","username":"admin","name":"Administrator","online":"1","enableMPT":"0","status":"1","userType":"1","roles":[{"roleId":"1","roleName":"Administrator"}]},
    {"id":"2","username":"operator","name":"Operator","online":"0","enableMPT":"0","status":"1","userType":"0","roles":[{"roleId":"2","roleName":"Operator"}]}
  ],
  "totalCount":"2"}}
```

### 3.2 `GET /brms/api/v1.1/user/:id`
- Mismo shape de fila que `pageData` (objeto plano).

### 3.3 `GET /brms/api/v1.1/user/group/list` y `/user/group-by-role-level/list`
- Parser `FUN_1806f6a10`: raíz **`results`** (array) de objetos `{groupName, groupId, users[] {userId, username}}` — strings.
- SPA `treeData-CLaOAgSP.js@0x66c`: `data.results[]`, `children = users[]`, etiqueta `groupName||username`.
```json
{"code":1000,"desc":"Success","data":{"results":[
  {"groupId":"1","groupName":"Default","users":[{"userId":"1","username":"admin"}]}
]}}
```

### 3.4 `GET /brms/api/v1.1/user/email/page` (diálogo de correo)
- SPA `index-C1zRFxk1.js@85138` / `index-BQObycDy.js@0x171e5`: lee **`data.pageData`** (si falta → `undefined` → TypeError → pantalla blanca).

## 4. Permisos por recurso

### 4.1 `GET /brms/api/v1.1/authority/resource/{id}/role/list`
- `CRestLogical::GetResourceRoles` RVA 0x28f220; URL `v1.1/authority/resource/`@0xc9c238 + `/role/list`@0xc9c258.
- Descriptor inline @0x28f220: raíz **`results`** = **ARRAY DE STRINGS (roleIds)**, cada uno → `char[0x40]` (stride 0x40). **No son objetos.**
```json
{"code":1000,"desc":"Success","data":{"results":["1","2"]}}
```
- El gateway sirve además `list/roleList/items/roles` con los objetos `{id, roleId, roleName, memo, checked, permission, operate, …}` (consumidores SPA/legado).

### 4.2 `PUT /brms/api/v1.1/authority/resource/{id}/role/update` (SetResourceRoles)
- Request `FUN_1806e3420`: **`roleIds` array de strings**, `resourceId` string, `resourceType` string.

## 5. Organización (combo del diálogo)

### 5.1 `GET /brms/api/v1.1/domain/organization/list`
- `CRestLogical::GetDomainOrganizations` RVA 0x291380; URL @0xc9c4e0.
- Parser `FUN_1806ccde0`: raíz `domainOrgExceeded`(string) + **`results[]`**: `domainOrgType`, `domainOrgDn`, `pId`, `domainOrgPath`, `domainOrgName`, `domainOrgCode` — strings.
```json
{"code":1000,"desc":"Success","data":{"domainOrgExceeded":"0","results":[
  {"domainOrgCode":"VIGILAB","domainOrgName":"VIGILAB","domainOrgPath":"VIGILAB",
   "domainOrgType":"1","domainOrgDn":"ou=VIGILAB","pId":"001"}
]}}
```

## 6. LDAP

### 6.1 `GET /brms/api/v1.1/config/ldap`
- `CRestLogical::GetLdapConfig` RVA 0x1f7370; URL @0xc91cd0. Parser `FUN_18064d140`: **sin clave envoltorio**, se aplica directo a `data`.
- Claves: `username`(+0x00), `port`(+0x08, `atoi`), `autoSynTime`(+0x10), `dn`(+0x18), `enable`(+0x20), `enableAutoSyn`(+0x28), `ssl`(+0x30), `server`(+0x38) — **strings**; `enable/enableAutoSyn/ssl` comparados con la cadena `"1"` (0xc7cb2c).
- SPA `index-BiUvY3rV.js@0xad65` lee las mismas claves (`port` numérico en el modelo).

## 7. Árbol de recursos/permisos

### 7.1 `GET|POST /brms/api/v1.1/tree/full/grade-device-tree` (+ `/tree/grade-device-tree`, `/search/list`, v1.0/v1.1)
- Descriptor `FUN_1806d33a0`: raíz `{domainId, associateId, orgName, orgCode, sourceId}` + `organizations[]` (`checked`/`hasChild`/`orgCode`/`orgName`/`pId`/…, strings) + `devices[]` (`checked`/`status`/`orgCode`/…) + `channels[]` (`checked`/`status`/`orgCode`/`channelId`/…).
- `checked` es **string** `"0"`/`"1"`. Los canales de un org van junto a los devices de ESE org (nunca huérfanos).
- Variante GET con `/full/` obligatoria (el diálogo de permisos la usa; sin ella caía en FALLBACK `{list:[],total:0}` y el árbol cargaba para siempre).

## 8. Riesgos de cuelgue documentados (por qué hay que servir `pageData`/`results`)

1. `FUN_180761920` ToString lanza `dsl::Json::LogicError("Type is not convertible to string")` si se llama sobre array/objeto; si sale del callback de respuesta sin catch → el hilo nunca completa → **AppHangB1**.
2. `FUN_18076a850 operator[](ArrayIndex)` lanza si el nodo no es array.
3. `FUN_180754c60` rama objeto (tipo 5): el contador deja `puVar16` NULL y se lee `puVar16[2]` → **null deref**.
4. Clave-raíz ausente o mal tipada ⇒ 0 filas sin error ⇒ la UI queda esperando datos ⇒ diálogo vacío/colgado (observado 00:07 UTC 2026-11-07: `role/page` sin `pageData`).
5. **Hoja con tipo equivocado** (número/bool/array donde el descriptor pide string, kind 2): el matcher `FUN_180754c60`/`FUN_180759540` **no coacciona**, deja el campo **NULL/0 en silencio** ⇒ fila lógica incompleta (roles vacío, `name` vacío) sin ningún error visible. El E-100 servía `roleIds:["1"]`/`roleNames:[…]` como arrays y omitía `name`/`enableMPT`/`roles[]` (§10.7).
6. **Espera infinita en el mutex recursivo propio de `UserLogical`** (`FUN_180014020` → `WaitForSingleObjectEx(hEvent, 0xffffffff, 0)`): sin comprobación de hilo propietario y con evento **auto-reset**, una reentrada o un *lost wake-up* deja el **hilo de UI** aparcado para siempre ⇒ **AppHangB1 sin `0xC0000005`** (§10.5). Lo toma el getter de una sola lectura `FUN_1800647d0` (`UserList` vtable `+0x58`) que el handler `FUN_180ac33a0` invoca al procesar la notificación `opcode 0xd`.
7. Excepción (`std::bad_alloc`) dentro de la sección crítica de `CUser::HandleGetUsersList` (`FUN_18008f714` / `FUN_18004e960` / `FUN_180047d20`) ⇒ el mutex `CUser+0x68` **queda tomado** ⇒ todo acquisitions posterior cuelga en (6).

## 9. Ciclo de vida del diálogo (orden observado + superficie nativa completa)

Orden observado en el gateway al abrir Users/Configuración (E-104 runtime):
`role/page` → `function/available/list` → `menu/available/list?roleId=1` → `subsystem/available/list` → `user/group/list?keyword=` → `config/ldap` → `role/list` → `user/page` → (al seleccionar usuario) `user/:id`, `authority/resource/{id}/role/list`, `resource-allocate/organization/device/fetch/list`, `tree/full/grade-device-tree`.

Superficie CRestLogical completa del pool de strings (file 0xc9c000–0xc9d900) para Users/Roles:

| Handler DPSDK | URL |
|---|---|
| GetAvailableSubSystems | `v1.1/subsystem/available/list` |
| GetSubSystemConfigWarning | `v1.1/subsystem/register/warning` |
| GetUserRolesList | `v1.1/role/list` |
| GetAllRolesList | `v1.1/role/all/list` |
| GetResourceRoles | `v1.1/authority/resource/{id}/role/list` |
| SetResourceRoles | `PUT v1.1/authority/resource/{id}/role/update` |
| GetDomainUserList / Add / DeleteInvalid | `v1.1/domain/user/...` |
| GetDomainOrganizations | `v1.1/domain/organization/list` |
| GetDomainInfosByPage | `v1.1/domain/page` |
| GetAccountMenuList | `v1.1/account/menu/list` |
| CheckDeviceFunction | `v1.1/account/function/device/check` |
| CheckChannelFunction | `v1.1/account/function/channel/check` |
| GetDeviceOverview | `v1.1/account/device/overview` |
| SearchFullGradeDeviceTree / SearchGradeDeviceTree | `v1.1/tree/{full/}grade-device-tree/search/list` |
| GetFullGradeDeviceTree / GetGradeDeviceTree | `v1.1/tree/{full/}grade-device-tree` |
| GetDeviceTreeInfo | `v1.1/tree/device-tree` |
| **GetUserGroup** | **`/admin/API/Rights/Groups`** (legacy) |
| **GetUserBaseInfo** | **`/admin/API/Rights/Users`** (legacy) |
| GetUserManagerRoles | `v1.1/role/page` |
| GetUserManagerUsers | `v1.1/user/page` |
| **GetUserDetailInfo** | **`/admin/API/Rights/User`** (legacy) |
| SaveUser | `v1.1/user/{id}` |
| GetRole | `v1.1/role/{id}` |
| GetUser | `v1.1/user/{id}` |
| AddRole / UpdateRole | `v1.1/role` |
| AddUser | `v1.1/user` |
| LockUser / UnLockUser | `v1.1/user/{id}/lock|unlock` |

E-105: las tres rutas legacy `/admin/API/Rights/*` se sirven con los mismos shapes (users page / groups / user detail).

## 10. Estado del gateway (post E-104)

Todos los endpoints de la secuencia sirven las claves nativas exactas (case-sensitive), flags string, arrays donde el nativo espera arrays, `results` de strings en `authority/.../role/list`, y variantes GET `/full/` del árbol. Tests de regresión: `brms.test.js` E-096…E-104.

---

## 10. Pipeline nativo completo de "Usuarios" (E-105) y análisis del AppHangB1

Todo lo de esta sección está tomado de offsets de binario (`UserLogical.dll`, `PluginFactory.dll`, `DPSDK.dll`), no de conjetura.

### 10.1 Secuencia al abrir el diálogo Usuarios (nativa, no SPA)

El diálogo es **nativo** (`PlatformConfigUI::CUserManagerUserCtrl` en `PluginFactory.dll`); la web (`brms-gateway/web-module/js`) no lo implementa. Secuencia observada en el log del gateway (21:58:38.273 → 21:58:39.934):

1. `GET /brms/api/v1.1/role/page?roleName=&pageSize=20&page=1`
2. `GET /brms/api/v1.1/function/available/list`
3. `GET /brms/api/v1.1/menu/available/list?roleId=1`
4. `GET /brms/api/v1.1/subsystem/available/list`
5. `GET /brms/api/v1.1/user/group/list?keyword=`
6. `GET /brms/api/v1.1/role/list`
7. `GET /brms/api/v1.1/config/ldap`
8. `GET /brms/api/v1.1/user/page?username=&online=&groupId=&pageSize=20&roleIds=&page=1&userType=` → **200 (7552 B)**
9. **silencio**: ninguna petición posterior.

El `WER` (`AppHang_DSS Client.exe_…/Report.wer`) registra `EventType=AppHangB1`, `ConsentKey=AppHangXProcB1`, `EventTime=134384759266254188` = **2026-11-06 21:58:46.625Z**, es decir **6.7 s después del 200 de `user/page`**. No hay `0xC0000005`: el hilo de UI queda **bloqueado**, no，我们会.

### 10.2 Orquestación en `UserLogical.dll`

| paso | función | evidencia |
|---|---|---|
| manejador | `CUser::HandleGetUsersList` = `FUN_180067f00` | log `User.cpp:0x469/0x470` (`DPSDK_GetUserManagerUsers success/failed`) |
| llamada REST | `DPSDK_GetUserManagerUsers(handle, &req, FUN_18005fa00, &out)` | `req` = 0x1b84 B; `out` = `&local_2068` |
| callback | `FUN_18005fa00` | switch por tipo: `0x17c4` (USERS) → `FUN_180070530` |
| conversor | `FUN_180070530` | escribe `*(u32*)(out+8) = native.totalCount` y materializa `pageData.length` filas lógicas de 0x88 B |
| entrega | `FUN_18005e8b0` → `PostTask` (async) | **no hay espera**: ni MQ, ni WebSocket, ni `WM_*` tras `GetUserManagerUsers` |

**Estructura nativa de la fila** (600 B, `FUN_1802a01c0` en DPSDK): `status`+0x000, `id`[64]+0x004, `username`[250]+0x044, `online`+0x140, `userType`+0x144, `enableMPT`(byte)+0x148, `name`[250]+0x149, `roleCount`+0x248, `roles`+0x250 (stride 0x13a: `roleName`[0x40] + `roleId`[0xfa]).

**Fila lógica** (0x88 B, `FUN_180070530`):

| offset | tipo | origen nativo |
|---|---|---|
| +0x00 | `std::string id` | `id` (+0x004) |
| +0x20 | `std::string username` | `username` (+0x044) |
| +0x40 | `std::string name` | `name` (+0x149) |
| +0x60 | `u32 userType` / `u32 online` | `userType` (+0x144) / `online` (+0x140) |
| +0x68 | `int status` | `status` (+0x000) |
| +0x6c | `byte enableMPT` | `enableMPT` (+0x148) |
| +0x70/+0x78/+0x80 | `vector<Role>` | `roles[]` (Role = `roleName`@0x00 + `roleId`@0x20, 0x40 B) |

**Payload de notificación** (`FUN_180058f10` + `FUN_18005e8b0`): `+0x00 opcode = 0xd`, `+0x28 errorCode`, `+0x2c seq`, **`+0x30 totalCount`** (= `local_2060` = `atoi(data.totalCount)`), `+0x34 handle DPSDK`.

### 10.3 Ruta de render en `PluginFactory.dll`

`CUserManagerUserCtrl::OnNotifyUserManagerState` = `FUN_180ac8f90` → `case 0xd` → `thunk_FUN_180ac33a0` (`FUN_180ac33a0`):

1. `COperSequence::HasSeqIn(ctrl+0x160, seq)` — si el `seq` no está en la secuencia, **se descarta la notificación**.
2. `GetUserManager()` → `IUserManager` vtable `+0x10` (id de usuario actual) y `+0x18` (objeto `UserList`).
3. `UserList` vtable **`+0x58`** = **getter de una sola lectura** = `FUN_1800647d0` (UserLogical): **toma el mutex `CUser+0x68`**, busca la `seq` en el mapa `CUser+0xd8`, copia el vector (`FUN_180047d20`, cuenta = `(end-begin)/0x88`) y **borra el nodo** (`FUN_180043220` + `FUN_18005ba00`).
4. `DSNumberPageCtrl::SetTotalCount(pageCtrl, notify+0x30, false)` — **`notify+0x30` es el `totalCount` del servidor**, no el número de filas.
5. `SetCurrentPage`, filtro, `QStandardItemModel::insertRow` + `FUN_180acb8e0` por fila, y `FUN_180ac8080` (habilita/deshabilita botones).

**El bucle de pintado está acotado por el tamaño del vector** (`(lStack_90 - local_98) / 0x88`, ensamblado en `0x180ac3570`), **nunca por `totalCount`**. Por tanto un `totalCount` enorme **no** produce bucle infinito; sólo afecta al paginador.

### 10.4 Qué campo dibuja cada columna (clave exacta y sensible a mayúsculas)

`FUN_180acb8e0` (relleno de fila) — la columna 1/2/3/4 y sus roles:

| columna | rol | valor | offset lógico | clave JSON |
|---|---|---|---|---|
| 0 | 2 | `username` (**no `name`**) | +0x20 | `username` |
| 1 | 2 | `username` | +0x20 | `username` |
| 1 | 0x101 | `name` | +0x40 | `name` |
| 1 | 0x103 | `status` (int) | +0x68 | `status` |
| 1 | (defecto) | bool "displayable" | — | — |
| 2 | (defecto) | `roles[].roleId` unidos por `","` | +0x70..+0x80 | `roles[].roleId` |
| 3 | 2 / 0x104 | `"Online"`/`"Offline"` + `online` | +0x64 | `online` |
| 4 | 2 | `"Normal User"`/`"Domain User"` | +0x60 | `userType` |
| 5 | botones | Edit/View/Delete/Unlock/Lock | +0x68 (`status`) | `status` |

`username` se compara con el literal **`"system"`** (`0x1819d9d68`, 6 bytes, `memcmp` con tope 6) → esa fila no es editable.

### 10.5 La única espera infinita del camino (origen del AppHangB1)

En `UserLogical.dll` el mutex de `CUser` (`this+0x68`) es un **mutex recursivo propio**, no un `CRITICAL_SECTION`:

- `FUN_180014020` (lock): `W |= 0x80000000`; **si `(int)W < 0` (bit31 ya puesto) entra en la ruta de contención** → `FUN_180013de0` (crea un `CreateEventA(NULL,0,0,NULL)` = **auto-reset**) y **`WaitForSingleObjectEx(hEvent, 0xffffffff, 0)`** (INFINITE) con reintento por CAS.
- **No hay ninguna comprobación de hilo propietario**: la prueba de "ya taken" es sólo el bit31. Por tanto **una reentrada desde el mismo hilo** (o un *lost wake-up* si el CAS falla tras consumir el evento auto-reset) **deja el hilo de UI aparcado para siempre** ⇒ `AppHangB1` sin `0xC0000005`.
- El hilo de UI **sí** toma ese mutex: `FUN_180ac33a0` → `FUN_1800647d0` → `FUN_180014020(CUser+0x68)`.
- El hilo lógico (`FUN_180067f00`) **libera** el mutex **antes** de publicar la notificación (`PostTask`), por lo que no hay contención directa escritor/lector… salvo que el mutex quede tomado por una excepción dentro de la sección crítica (`FUN_18008f714`/`FUN_18004e960`/`FUN_180047d20` pueden lanzar `std::bad_alloc` → **el mutex se queda tomado para siempre** y el siguiente acquisitions se cuelga en `WaitForSingleObjectEx(INFINITE)`).
- El dispatcher de notificaciones (`FUN_180009830`, el `CFunctionTask` que `PostTask`ea) toma **otro** mutex (`observer+0x28`, un objeto COM ref-counted **distinto** del `CUser`), por lo que **no** hay auto-deadlock entre dispatcher y getter.

### 10.6 Respuestas a las 5 preguntas de la investigación

1. **Secuencia exacta al abrir Usuarios y qué se dispara tras `user/page`**: ver §10.1 (8 peticiones; `user/page` es la última). Tras el 200 el cliente **no pide nada más**: el evento que sigue es **interno**: `DPSDK_GetUserManagerUsers` → callback `FUN_18005fa00` → `FUN_180070530` (conversor) → mapa `CUser+0xd8` → `PostTask` de la notificación `opcode 0xd` → `FUN_180ac8f90` → `FUN_180ac33a0` (getter + `SetTotalCount` + pintado).
2. **Estructura de `v1.1/user/page`**: raíz `data` con **`pageData[]`** (array) + **`totalCount`** (string). **No** `results[]` ni array raíz. Si `data` falta o no es objeto (con `code`+`desc` presentes) el parser devuelve **−1** (error DPSDK, sin datos); si `data` es un array raíz, el parser lo envuelve como `{"nodes":[…]}`. Si una clave falta, el campo queda **NULL/0 en silencio** (sin excepción).
3. **Campos obligatorios por estructura y modos de fallo**: hojas **string** (kind 2) strictly tipadas — un número/bool donde se espera string deja el campo NULL/0 **en silencio**; `roles` debe ser **array de objetos** `{roleName, roleId}`; `totalCount` se consume con `atoi`. Los bucles del cliente **no** dependen de `totalCount`/`pageCount`/`hasNext` (no existen en el descriptor): el bucle de filas usa `(end-begin)/0x88` ⇒ **no hay bucle infinito por contadores**.
4. **Callback nativo que espera**: **ninguno**. La entrega es asíncrona (`PostTask`). El único `WaitForSingleObjectEx(INFINITE)` del camino está en el **mutex recursivo propio** de `UserLogical` (`FUN_180014020`, `CUser+0x68`), que esTaken por el hilo de UI en el getter `FUN_1800647d0`; no hay MQ/WebSocket/`WM_*`.
5. **Campo dibujado**: **`username`** (columnas 0 y 1; `name` va en la columna 1 con rol 0x101; la columna 2 concatena los **`roleId`** de `roles[]` con `","`). Claves exactas: `username`, `name`, `roles[].roleId`, `roles[].roleName`, `online`, `userType`, `status`, `enableMPT`, `id`.

### 10.7 Causa raíz más probable y corrección aplicada

**Causa raíz (graduada por evidencia)**:
- *Hecho binario*: el hilo de UI sólo puede quedar bloqueado por `WaitForSingleObjectEx(INFINITE)` del mutex propio de `UserLogical` (`CUser+0x68`), tomado en el getter `FUN_1800647d0` justo al procesar la notificación `0xd`; ese mutex **no comprueba el hilo propietario** y usa un evento **auto-reset**, de modo que cualquier reentrada o *lost wake-up* lo deja aparcado indefinidamente.
- *Hecho de payload*: el cuerpo servido en E-100 (7556 B) **no cumplía el descriptor nativo**: hojas que eran **arrays JSON** (`roleIds:["1"]`, `roleNames:["Super Administrator"]`) donde el nativo exige **string**, ausencia de `name`, `enableMPT` y `roles[]`, y 5 arrays duplicados (`list/results/items/userList`) + `total/page/pageSize/pageCount`. El binder nativo hace **type-check estricto**: los nodos con tipo equivocado dejan el campo **NULL/0 en silencio**, de modo que la fila lógica que el UI pintaba quedaba **estructuralmente incompleta** (roles vacío ⇒ columna de roles vacía, `name` vacío) y el camino de notificación se entraba con un estado inconsistente.
- *Correlación runtime*: el cuelgue empieza justo tras el 200 de `user/page` (el único `user/page` que se sirvió) y no hay peticiones posteriores ⇒ el hilo de UI se queda dentro del handler de la notificación.

**Corrección aplicada (E-105, `poc/dss-v2-harness/brms-gateway/src/e025-devices.js`)**:
- `serializeUserPageRow()`: fila **estricta** = `id`, `username`, `name` (no vacío), `online`, `enableMPT`, `status`, `userType` (todos **string**) + `roles:[{roleId,roleName}]` (único array).
- `buildUserPagePayload()`: `data` = **`{pageData, totalCount}`** y nada más; `totalCount` = total de usuarios que casan, en **string decimal**.
- Se eliminan las hojas-array (`roleIds:["1"]`, `roleNames:[…]`, `roleIdArray`, `roleNameArray`) y los alias `list/results/items/userList/total/page/pageNo/pageSize/pageCount` ⇒ el cuerpo pasa de **7556 B a 386 B** y coincide exactamente con el descriptor nativo.
- El detalle `/user/:id` conserva los alias CSV (`roleIds:"1"`) para la SPA, ya con su propio descriptor nativo; **tampoco** tiene hojas-array.
- Tests: `brms.test.js` E-096/E-101/E-102 actualizados a las aserciones estrictas (57/57 en verde).

### 10.8 Estado del gateway (post E-105)

`v1.1/user/page` sirve el payload nativo estricto; el resto de endpoints de la secuencia (roles, grupos, LDAP, árbol, permisos) mantiene sus claves nativas exactas. Tests de regresión: `brms.test.js` E-096…E-105.

