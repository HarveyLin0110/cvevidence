[CmdletBinding()]
param(
    [ValidateSet('start', 'restart', 'stop', 'status')]
    [string]$Action = 'start',
    [ValidateRange(1024, 65535)]
    [int]$Port = 8505,
    [string]$Distribution = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL is required. See docs/setup/windows-wsl.md.'
}

# Use the existing Linux service manager so process identity and health checks
# are shared with the documented Linux workflow.
& wsl.exe --distribution $Distribution --cd $projectRoot --exec .venv/bin/python scripts/workspace_wsl.py $Action --port $Port
if ($LASTEXITCODE -ne 0) {
    throw "Workspace service failed (exit $LASTEXITCODE). See var/service/workspace-$Port.log."
}
