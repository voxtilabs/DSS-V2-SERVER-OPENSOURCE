# Fallback de ingenieria inversa sin MCP (REA caido)

Cuando el MCP `rea` no esta en el catalogo de herramientas (se cae
intermitentemente; ver diagnostico en curso), usar **Ghidra headless
directo**:

```powershell
cd tools\ghidra-fallback
.\rea-ghidra.ps1 -Target C:\Users\bruno\Downloads\dssv2-setup\dssclient-extracted\MainFormPlugin.dll -Strings "versions don't match" -NoAnalysis
.\rea-ghidra.ps1 -Target <bin> -Decompile 0x180166cd3
.\rea-ghidra.ps1 -Target <bin> -Exports -NoAnalysis
```

- `ReaStrings.java` imprime cada string que matchea el regex **con sus xrefs**
  (funcion que lo referencia) - equivalente a `search_strings`+`xrefs` del MCP.
- `ReaDecomp.java` decompila la funcion que contiene la VA dada.
- `ReaExports.java` lista los exports (external entry points).
- Para string-pool crudo sin Ghidra (mas rapido): node + fs sobre el binario
  (ver scripts en `$env:TEMP\opencode\*.cjs`, ej. find-toast.cjs / xref-toast.cjs).

Requisito: `GHIDRA_HOME` o Ghidra en `C:\Users\bruno\Tools\dssv2\ghidra\ghidra_12.1.4_PUBLIC`.
Los post-scripts son **Java** (este Ghidra 12.1.4 headless no trae PyGhidra
habilitado; los .java compilan on-the-fly y siempre funcionan).
