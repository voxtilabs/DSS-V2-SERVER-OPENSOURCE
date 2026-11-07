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
- Alias que el gateway sirve además (superset inocuo para el nativo): `list/results/items/userList`, `roleIds` CSV + `roleIdArray`.

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

## 9. Estado del gateway (post E-104)

Todos los endpoints de la secuencia sirven las claves nativas exactas (case-sensitive), flags string, arrays donde el nativo espera arrays, `results` de strings en `authority/.../role/list`, y variantes GET `/full/` del árbol. Tests de regresión: `brms.test.js` E-096…E-104.
