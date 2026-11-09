# Runbook de despliegue controlado (verificado 2026-11-08, E-127/E-128)

El server `10.10.20.120` **NO tiene git** — el revert se hace en el repo
local y se sincroniza por scp.

## 0. Pre-check
```
ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && docker compose ps"
git -C "C:\Users\bruno\Downloads\LOCURA DSS" status   # limpio salvo lo que se va a commitear
```

## 1. Backups en el server
```
ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && tar czf /tmp/data-backup-\$(date +%s).tgz brms-gateway/data && cp docker-compose.yml /tmp/compose-\$(date +%s).yml && ls -l /tmp/data-backup-*.tgz | tail -1"
```

## 2. Gates locales (antes de tocar el server)
```
cd poc/dss-v2-harness/brms-gateway
node --check src/index.js                       # sintaxis
# matar zombis locales que ocupen 11443/9100 antes del boot-test
# PROHIBIDO `Get-Process node | Stop-Process -Force`: termina procesos gestionados
# (p.ej. el servidor MCP `rea` de OpenCode -> "MCP server process exited with code
# 255"). Matar solo por identidad (command line) o por puerto:
Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
  Where-Object { $_.CommandLine -match 'brms-gateway' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Get-NetTCPConnection -LocalPort 11443,9100 -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
node --test --test-timeout=20000 src\test\*.test.js   # 75 pass / 0 fail (E-128)
cd .. ; node --test e2e-lan-test.mjs           # 12/12 (x2-3; flake conocido: STOMP notifyChannelStatuses)
# boot-test local + auditoria de duplicados (Fastify aborta con rutas
# duplicadas): arrancar src/index.js, curl /health = 200, log sin FATAL
```

## 3. Publicar
```
git push git@github.com:voxtilabs/DSS-V2-SERVER-OPENSOURCE.git main
scp -r poc/dss-v2-harness/brms-gateway/src bruno@10.10.20.120:~/dss-v2-harness/brms-gateway/
```

## 4. Build/up (NO recrear mediamtx/activemq — preserva paths y colas)
```
ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && docker compose build brms-gateway && docker compose up -d brms-gateway"
```

## 5. Post-deploy
```
ssh bruno@10.10.20.120 "sleep 12; curl -fsS http://127.0.0.1:11443/health; docker ps --filter name=brms-gateway --format '{{.Status}}'"
# => {"status":"ok",...} + Up
ssh bruno@10.10.20.120 "docker exec -i dss-v2-harness-brms-gateway-1 node - < /tmp/live-verify.cjs"
# => SUMMARY 15/15
ssh bruno@10.10.20.120 "docker logs dss-v2-harness-brms-gateway-1 --tail 50 | grep -E 'FATAL|unhandledRejection'"  # vacio
ssh bruno@10.10.20.120 "docker exec dss-v2-harness-brms-gateway-1 tail -200 /app/data/logs/requests-\$(date +%F).log | grep FALLBACK | tail -5"
```

## 6. Rollback
```
git revert <commit> ; git push git@github.com:voxtilabs/DSS-V2-SERVER-OPENSOURCE.git main
# repetir pasos 3-5
# si el estado quedo corrupto:
ssh bruno@10.10.20.120 "cd ~/dss-v2-harness && docker compose stop brms-gateway && tar xzf /tmp/data-backup-<ts>.tgz -C . && docker compose up -d brms-gateway"
```

## Checklist post-deploy (verificado E-128)
- 15 checks de live-verify: login 2 pasos, add ONVIF, device/page, tree, grade
  tree, StartVideo rtsp://, DESCRIBE, view-tree, cleanup sin borrar D0238JDG3016.
- P0 residual REA ya no cae en catch-all: alarm/disarm, alarmBusiness/alarmList,
  config/server/time, DMS/Ptz/*, devicesManager/*, omc/upgrade/* (189-250B).
- ARS 9500: frame DVRIP fragmentado en 3 chunks → ACK Ret:100; payloadLen
  0xFFFFFFFF → sin OOM, socket bajo cap 1MiB/4MiB.
- Puertos: 1443/9443/11443/9100/9500/1883/5080/18800/19800 arriba; mediamtx
  8554 solo en 127.0.0.1:9554.
