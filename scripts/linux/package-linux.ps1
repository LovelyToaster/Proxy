[CmdletBinding()]
param(
    [string]$Version = "0.1.0-dev",
    [string]$Commit = "",
    [string]$BuildDate = "",
    [string]$ReleaseDir = "dist/release",
    [switch]$FetchGeo
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location -LiteralPath $repo
try {
    if (-not $Commit) {
        try { $Commit = (git rev-parse --short HEAD 2>$null).Trim() } catch { $Commit = "unknown" }
        if (-not $Commit) { $Commit = "unknown" }
    }
    if (-not $BuildDate) {
        $BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    $geoDir = Join-Path $repo "dist/geo-cache"
    New-Item -ItemType Directory -Path $geoDir, (Join-Path $repo "dist/linux-amd64/data"), (Join-Path $repo "dist/linux-arm64/data"), (Join-Path $repo $ReleaseDir) -Force | Out-Null

    $geoBase = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
    foreach ($geoFile in @('geoip.dat', 'geosite.dat')) {
        $dst = Join-Path $geoDir $geoFile
        $winExisting = Join-Path $repo "dist/windows-amd64/data/$geoFile"
        if (-not $FetchGeo -and -not (Test-Path $dst) -and (Test-Path $winExisting)) {
            Copy-Item $winExisting $dst -Force
        }
        if ($FetchGeo -or -not (Test-Path $dst)) {
            Write-Host "Downloading $geoFile from Loyalsoldier/v2ray-rules-dat..."
            Invoke-WebRequest -Uri "$geoBase/$geoFile" -OutFile $dst -UseBasicParsing
            $sumText = (Invoke-WebRequest -Uri "$geoBase/$geoFile.sha256sum" -UseBasicParsing).Content.Trim()
            $expected = ($sumText -split '\s+')[0].ToLowerInvariant()
            $actual = (Get-FileHash $dst -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "Geo SHA-256 mismatch for ${geoFile}: got $actual, expected $expected"
            }
        }
    }

    $ldflags = "-s -w -X proxy.local/m0/internal/buildinfo.Version=$Version -X proxy.local/m0/internal/buildinfo.Commit=$Commit -X proxy.local/m0/internal/buildinfo.BuildDate=$BuildDate"
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"

    foreach ($arch in @('amd64', 'arm64')) {
        Write-Host "Building Linux $arch binary..."
        $env:GOARCH = $arch
        $outDir = Join-Path $repo "dist/linux-$arch"
        go build -trimpath -ldflags $ldflags -o (Join-Path $outDir "proxy") ./cmd/proxy
        if ($LASTEXITCODE) { throw "Linux $arch build failed" }
        Copy-Item (Join-Path $geoDir "geoip.dat"), (Join-Path $geoDir "geosite.dat") -Destination (Join-Path $outDir "data") -Force

        Push-Location $outDir
        try {
            $tarName = "proxy-linux-$arch.tar.gz"
            tar -czf $tarName proxy data/geoip.dat data/geosite.dat
            if ($LASTEXITCODE) { throw "tar failed for Linux $arch" }
            Copy-Item $tarName (Join-Path (Join-Path $repo $ReleaseDir) $tarName) -Force
        } finally { Pop-Location }
    }

    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    Write-Host "Linux packaging completed successfully."
    Get-FileHash (Join-Path (Join-Path $repo $ReleaseDir) "proxy-linux-amd64.tar.gz"), (Join-Path (Join-Path $repo $ReleaseDir) "proxy-linux-arm64.tar.gz") -Algorithm SHA256
} finally {
    Pop-Location
}
