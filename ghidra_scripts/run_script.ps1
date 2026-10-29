# Runs a Ghidra script headless against the analysed FM15 project without re-analysing or saving.
# Usage: .\run_script.ps1 <ScriptName.java> [script args...]
# Set $env:FM15_PROJECT to use a copy of the project (e.g. ghidra_project_fees) so runs can happen in parallel.
param([Parameter(Mandatory)][string]$Script, [Parameter(ValueFromRemainingArguments)][string[]]$ScriptArgs)

$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot"
if (-not $env:GHIDRA_HEADLESS_MAXMEM) { $env:GHIDRA_HEADLESS_MAXMEM = "12G" }
$root = Split-Path $PSScriptRoot -Parent
$project = if ($env:FM15_PROJECT) { $env:FM15_PROJECT } else { "ghidra_project" }
& "C:\Users\Shadow\Tools\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat" "$root\$project" FM15 `
	-process fm.exe -noanalysis -readOnly -scriptPath $PSScriptRoot -postScript $Script @ScriptArgs
