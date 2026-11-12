[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location -LiteralPath $repo
try {
    New-Item -ItemType Directory -Path dist/linux-amd64 -Force | Out-Null
    New-Item -ItemType Directory -Path dist/linux-arm64 -Force | Out-Null

    Write-Host "Building Linux amd64 binary..."
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -trimpath -ldflags '-s -w' -o dist/linux-amd64/proxy ./cmd/proxy
    if ($LASTEXITCODE) { throw "Linux amd64 build failed" }

    Push-Location dist/linux-amd64
    try {
        tar -czf proxy-linux-amd64.tar.gz proxy
    } finally { Pop-Location }

    Write-Host "Building Linux arm64 binary..."
    $env:GOARCH = "arm64"
    go build -trimpath -ldflags '-s -w' -o dist/linux-arm64/proxy ./cmd/proxy
    if ($LASTEXITCODE) { throw "Linux arm64 build failed" }

    Push-Location dist/linux-arm64
    try {
        tar -czf proxy-linux-arm64.tar.gz proxy
    } finally { Pop-Location }

    Write-Host "Linux packaging completed successfully."
    Get-FileHash dist/linux-amd64/proxy, dist/linux-amd64/proxy-linux-amd64.tar.gz, dist/linux-arm64/proxy, dist/linux-arm64/proxy-linux-arm64.tar.gz -Algorithm SHA256
} finally {
    Pop-Location
}
