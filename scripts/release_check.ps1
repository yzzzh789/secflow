param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"

$patterns = @(
    @{ Name = "runtime sqlite"; Filter = "*.sqlite"; Path = "data" },
    @{ Name = "runtime sqlite wal"; Filter = "*.sqlite-wal"; Path = "data" },
    @{ Name = "runtime sqlite shm"; Filter = "*.sqlite-shm"; Path = "data" },
    @{ Name = "website security state"; Filter = "website_security_state.json"; Path = "data" },
    @{ Name = "python bytecode"; Filter = "*.pyc"; Path = "." },
    @{ Name = "windows executable"; Filter = "*.exe"; Path = "." }
)

$violations = @()
foreach ($pattern in $patterns) {
    $base = Join-Path $Root $pattern.Path
    if (-not (Test-Path -LiteralPath $base)) {
        continue
    }
    $matches = Get-ChildItem -LiteralPath $base -Recurse -File -Filter $pattern.Filter -ErrorAction SilentlyContinue
    foreach ($match in $matches) {
        $relative = Resolve-Path -LiteralPath $match.FullName -Relative
        $violations += [pscustomobject]@{
            Type = $pattern.Name
            Path = $relative
        }
    }
}

$pycacheDirs = Get-ChildItem -LiteralPath $Root -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue
foreach ($dir in $pycacheDirs) {
    $violations += [pscustomobject]@{
        Type = "python cache directory"
        Path = Resolve-Path -LiteralPath $dir.FullName -Relative
    }
}

if ($violations.Count -eq 0) {
    Write-Host "release check passed"
    exit 0
}

Write-Host "release check failed: runtime artifacts are present"
$violations | Sort-Object Type, Path | Format-Table -AutoSize
exit 1
