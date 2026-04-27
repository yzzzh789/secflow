param(
    [int]$Port = 9091,
    [string]$PythonBin = "python"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dataDir = Join-Path $repoRoot "data"
$exePath = Join-Path $repoRoot "secflow.exe"

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$env:SECFLOW_ROLE = "host-agent"
$env:SECFLOW_HTTP_PORT = "$Port"
$env:SECFLOW_PROJECT_ROOT = $repoRoot
$env:SECFLOW_PYTHON_BIN = $PythonBin
$env:PACKET_ANALYZER_DB_PATH = (Join-Path $dataDir "packet_analyzer.sqlite")
$env:NIC_TRAFFIC_DB_PATH = (Join-Path $dataDir "nic_traffic.sqlite")
$env:WEBSITE_SECURITY_STATE_PATH = (Join-Path $dataDir "website_security_state.json")
$env:SECFLOW_HOST_AGENT_URL = ""

Write-Host "Starting SecFlow host agent on port $Port"
Write-Host "Project root: $repoRoot"
Write-Host "Python binary: $PythonBin"

if (Test-Path $exePath) {
    & $exePath
    exit $LASTEXITCODE
}

go run .
