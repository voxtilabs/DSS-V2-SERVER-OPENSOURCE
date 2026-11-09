#!/usr/bin/env pwsh
# rea-ghidra.ps1 - Fallback PERMANENTE de ingenieria inversa con Ghidra headless
# directo (no depende del MCP de REA). Si el MCP se cae, usar esto.
#
# Uso:
#   ./rea-ghidra.ps1 -Target <binario> -Strings '<regex>' [-MaxHits 200] [-NoAnalysis]
#   ./rea-ghidra.ps1 -Target <binario> -Decompile 0x180166cd3
#   ./rea-ghidra.ps1 -Target <binario> -Exports
#
# Requiere: Ghidra 12.x en $GHIDRA_HOME (o C:\Users\bruno\Tools\dssv2\ghidra\ghidra_12.1.4_PUBLIC).
# Los scripts Java viven junto a este wrapper (ReaStrings/ReaDecomp/ReaExports).
# Salida: consola + log en $env:TEMP\opencode\ghidra-out\<nombre>-<ts>.log
param(
  [Parameter(Mandatory=$true)][string]$Target,
  [string]$Strings,
  [string]$Decompile,
  [switch]$Exports,
  [int]$MaxHits = 200,
  [switch]$NoAnalysis,
  [int]$TimeoutSec = 900
)
$ErrorActionPreference = 'Stop'
$GHIDRA = if ($env:GHIDRA_HOME) { $env:GHIDRA_HOME } else { 'C:\Users\bruno\Tools\dssv2\ghidra\ghidra_12.1.4_PUBLIC' }
$HEADLESS = "$GHIDRA\support\analyzeHeadless.bat"
if (-not (Test-Path $HEADLESS)) { throw "Ghidra headless no encontrado en $HEADLESS (pon GHIDRA_HOME)" }
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$OUT = "$env:TEMP\opencode\ghidra-out"; New-Item -ItemType Directory -Force -Path $OUT | Out-Null
$name = [IO.Path]::GetFileNameWithoutExtension($Target)
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$projDir = "$env:TEMP\opencode\ghidra-proj\$name-$ts"; New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$log = "$OUT\$name-$ts.log"

$post = $null; $extra = @()
if ($Strings) { $post = 'ReaStrings.java'; $extra = @("`"$Strings`"", "$MaxHits") }
if ($Decompile) { $post = 'ReaDecomp.java'; $extra = @("$Decompile", "$TimeoutSec") }
if ($Exports) { $post = 'ReaExports.java'; $extra = @("5000") }
if (-not $post) { throw 'Indica -Strings, -Decompile o -Exports' }

$cmdArgs = @("$projDir", "p-$ts", '-import', $Target, '-scriptPath', $DIR, '-postScript', $post) + $extra
if ($NoAnalysis) { $cmdArgs += '-noanalysis' }
Write-Host "Ghidra headless: $Target :: $post $($extra -join ' ') (noanalysis=$NoAnalysis) -> $log"
$proc = Start-Process -FilePath $HEADLESS -ArgumentList $cmdArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"
Write-Host "exit=$($proc.ExitCode) log=$log"
Get-Content $log | Select-String -Pattern 'REA-|EXP |STR |XREF|DECOMP|SCRIPT ERROR' | Select-Object -First 600 | ForEach-Object { $_.Line }
