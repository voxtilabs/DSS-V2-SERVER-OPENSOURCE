# SECURITY.md — Modelo de amenazas y controles

## 1. Principios

1. DSS V2 gestiona vidas privadas y seguridad física: cualquier falla aquí es crítica.
2. Superficie de ataque mínima: **nada** se expone a Internet salvo el API Gateway con TLS.
3. Cero secretos en claro: credenciales de NVR y usuarios cifradas en reposo (AEAD).
4. Privilegio mínimo: RBAC por organización/canal; multi-tenant estricto.
5. Auditoría total de acciones administrativas y de conexión a dispositivos.

## 2. Contexto de amenaza (evidencia real)

- EV-011: atacantes acceden a cámaras Dahua vía P2P cloud usando solo SN en entornos mal
  configurados; hay campañas con backdoor persistente (p2pwn). Conclusión: el SN tampoco debe ser
  la única llave; DSS V2 exige usuario/contraseña por dispositivo y registra cada conexión.
- La nube P2P es un servicio externo que control su tiempo; fuera de él no hay ninguna garantía:
  todos los endpoints de DSS V2 deben operar en redes aisladas.

## 3. Controles por capa

| Capa | Control |
|---|---|
| Red | Segmentación: gateway (única cara pública), conector/video en red interna, Redis/DB privada; firewall host; no SSH a Internet |
| API Gateway | TLS 1.2+/1.3, certificados administrados, rate liming por IP/usuario, cabeceras de seguridad (HSTS, CSP), anti-CSRF para cookies |
| Autenticación | Argon2id para usuarios; sesiones firmadas TTL corto + rotate; lockout tras N intentos; 2FA opcional |
| Credenciales dispositivo | cifrado AES-256-GCM con clave en backend seguro (env var/vault/KMS-ready); sin plaintext en DB ni logs |
| Sesiones WS | token por socket; expiración; ping/pong con cierre limpio |
| Auditoría | tabla append-only: quien, cuando, qué, desde dónde; export a SIEM (futuro) |
| Dispositivos | acceso de solo-lectura preferente; nunca se "bridgea" al appliance en producción |
| Dependencias | SBOM por build, `dependabot`, revisión de licencias antes de new deps |
| Build | CI reproducible; sin credenciales en repo; `secrets scanning` |

## 4. Reglas del proyecto (derivadas)

- No almacenar contraseñas de NVR en texto plano.
- No exponer interfaces administrativas a Internet.
- Los binarios/instaladores Dahua se guardan fuera de git, con SHA-256 y fuente en manifests
  (`research/evidence/*-manifest.md`).
- No extraemos ni reutilizamos secretos/credenciales/keys incrustados en software propietario.

## 5. Puertos externos permitidos (prod)

| Exposición | Servicio |
|---|---|
| 443 TCP (único público) | API Gateway + Web |

Todo lo demás solo en red interna: Postgres 5432, Redis 6379 (si aplica), conector interno :8089,
métricas internas para Prometheus :9091.

## 6. Checklist de gobernanza

- [x] Diseño contemplado desde Fase 0 (no parche final)
- [ ] TLS+rate-limiting implementados antes cualquier endpoint público (Fase 2)
- [ ] Cifrado de credenciales listo antes de agregar el primer NVR por SN
- [ ] Pentest interno antes de Fase 3 (Web Client)
