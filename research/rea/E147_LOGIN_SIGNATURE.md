# E-147 — Handshake MD5 exacto del DSS Client (derivado de capturas vivas)

## Resultado

La fórmula documentada hasta E-146 estaba **incompleta**: el cliente hashea el
digest DOS veces. Fórmula exacta, verificada contra **tres** pares
(randomKey, signature) capturados en vivo del DSS Client real contra nuestro
gateway (`REALM=DSS-V2-LAB`, `user=admin`, `pass=admin123`):

```
temp    = md5(user + md5(password))
inner   = md5(`${user}:${realm}:${temp}`)
signature = md5( md5( inner + ':' + randomKey ) )
```

Las tres capturas coinciden carácter por carácter.

## Evidencia (capturada del cliente en `[REQ-BODY]` del gateway)

| randomKey | signature (capturada) | fórmula E-147 |
|---|---|---|
| e31e4b960115c08ab43bdbd7c2a3f221 | 9fe14f284717860a405c67ee148fa59d | MATCH |
| b043abb1304c77ca6ba4fd60b5772eba | 4e07f6c3d9a8bc04294c3b92aba71f09 | MATCH |
| 94485b3314fbe8acd1b5585b59541127 | 3419190c2ca8a0b996234ebcc654c8dd | MATCH |

Cuerpo real del cliente en la segunda llamada (shape exacto):

```json
{"userName":"admin","ipAddress":"","clientType":"WINPC_V2","randomKey":"<32 hex>","signature":"<32 hex>"}
```

- No envía `encryptType` en la segunda llamada.
- `randomKey` del reto es 32 hex (16 bytes).
- El reto (401) trae `realm`, `randomKey`, `encryptType:"MD5"`, `publickey`
  (clave RSA del flujo alternativo de recuperación de contraseña).

## Cambios aplicados

- `index.js`: `clientDigest()` + `makeSig()` ahora implementan la cadena real
  (modo estricto del harness valida exactamente lo que manda el cliente).
- `docs/DAHUA_COMPATIBILITY.md` §7: fórmula corregida.
- `harvest-real-dss.cjs`: harvester read-only del DSS Pro real con la fórmula
  exacta y el body byte-idéntico al cliente.

## Estado del harvest al DSS Pro real (200.54.10.50:1443)

- TLS OK, `/brms/api/v1.0/accounts/authorize` responde 401 con
  `realm`/`randomKey` (retos no consumen intentos).
- Con la fórmula exacta + credenciales provistas el servidor respondió
  `code 2001 "Incorrect username or password."` y **`unlockRemainTimes` quedó
  en 4** (el intento no decrementó el contador).
- Conclusión: la firma es correcta; el rechazo apunta a credenciales o a que
  la cuenta exige el flujo RSA (`publickey`) — pendiente de confirmar con el
  operador antes de reintentar. NO se hicieron más intentos.

## Reintento seguro (cuando se confirme la credencial)

```powershell
$env:DSS_REAL_HOST="200.54.10.50"; $env:DSS_REAL_PORT="1443";
$env:DSS_REAL_USER="system"; $env:DSS_REAL_PASS="<confirmada>";
node poc/dss-v2-harness/brms-gateway/harvest-real-dss.cjs
```

El script solo hace authorize + GETs/POSTs de lectura y guarda los DTOs
sanitizados en `poc/research/real-server/` (tokens y passwords redactados).
