# research/ — Evidencia y laboratorio (convenciones)

La carpeta `research/evidence/` está **fuera de git** (ver `.gitignore`): nunca se publican capturas,
logs de dispositivos, instaladores ni datos con SN. Organización local:

```
research/evidence/
├── E-001-capturas-lab/        *.pcapng + notas
├── E-002-netsdk-linux/        logs de ejecución, outputs de ffprobe
├── E-003-p2p-cloud/           DNS/pcaps de laboratorio
├── E-004-dss-integration-api/ respuestas curl (sin tokens reales)
├── E-005-poc-p2p/             logs del conector, validaciones de video
├── E-006-rea-dss-binaries/    samples/, dumps referenciados con SHA-256
├── sdk-manifest.md            fuente/versión/sha-256 de SDKs utilizados
├── samples-manifest.md        fuente/versión/sha-256 de instaladores .exe analizados
└── bench-YYYYMMDD.md          benches reales con hardware especificado
```

Reglas:
1. No incluir contraseñas ni SN reales en texto plano: usar identificadores del experimento.
2. Los binarios de muestra (por ejemplo `General_DSS-Client_Win64_IS_V8.006...exe`) se guardan
   fuera del repositorio con su huella SHA-256 documentada en el manifest — jamás en git.
3. Toda evidencia citada en `docs/` debe existir aquí o indicar la fuente externa localizada.
