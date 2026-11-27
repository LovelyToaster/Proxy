[CmdletBinding()]
param(
    [string]$Version = "0.1.0-dev",
    [string]$Commit = "",
    [string]$BuildDate = "",
    [string]$ReleaseDir = "dist/release",
    [switch]$FetchGeo,
    [switch]$FetchWinDivert,
    [switch]$SkipInstaller
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

    $stageDir = Join-Path $repo "dist/windows-amd64"
    $dataDir = Join-Path $stageDir "data"
    New-Item -ItemType Directory -Path $stageDir, $dataDir, (Join-Path $repo "dist/installer"), (Join-Path $repo $ReleaseDir) -Force | Out-Null

    # Ensure official WinDivert binaries are present and hash-verified.
    $wdManifest = Get-Content (Join-Path $repo "platform/windows/windivert.json") -Raw | ConvertFrom-Json
    $dllPath = Join-Path $stageDir "WinDivert.dll"
    $sysPath = Join-Path $stageDir "WinDivert64.sys"
    $licPath = Join-Path $stageDir "WinDivert-LICENSE"
    if ($FetchWinDivert -or -not (Test-Path $dllPath) -or -not (Test-Path $sysPath) -or -not (Test-Path $licPath)) {
        $tmpZip = Join-Path ([IO.Path]::GetTempPath()) ("windivert-" + [Guid]::NewGuid().ToString("N") + ".zip")
        $tmpExt = Join-Path ([IO.Path]::GetTempPath()) ("windivert-" + [Guid]::NewGuid().ToString("N"))
        try {
            Write-Host "Downloading official WinDivert $($wdManifest.version)..."
            Invoke-WebRequest -Uri $wdManifest.url -OutFile $tmpZip -UseBasicParsing
            Expand-Archive -Path $tmpZip -DestinationPath $tmpExt -Force
            foreach ($prop in $wdManifest.files.PSObject.Properties) {
                $src = Join-Path $tmpExt $prop.Value.archive_path
                if (-not (Test-Path $src)) { throw "Missing expected WinDivert archive file: $($prop.Value.archive_path)" }
                Copy-Item -Path $src -Destination (Join-Path $stageDir $prop.Name) -Force
            }
        } finally {
            Remove-Item -Path $tmpZip, $tmpExt -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($name in @('WinDivert.dll', 'WinDivert64.sys')) {
        $expected = $wdManifest.files.$name.sha256.ToLowerInvariant()
        $actual = (Get-FileHash (Join-Path $stageDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "WinDivert SHA-256 mismatch for ${name}: got $actual, expected $expected"
        }
    }

    # Ensure GeoIP/GeoSite DAT files from Loyalsoldier/v2ray-rules-dat are present.
    $geoBase = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
    foreach ($geoFile in @('geoip.dat', 'geosite.dat')) {
        $dst = Join-Path $dataDir $geoFile
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

    $allowed = @('proxy.exe','WinDivert.dll','WinDivert64.sys','WinDivert-LICENSE','geoip.dat','geosite.dat')
    $sources = @(Get-Content (Join-Path $PSScriptRoot windows-installer.nsi) | Where-Object { $_ -match '^\s*File\s' })
    foreach ($line in $sources) {
        if ($line -notmatch '"([^"\r\n]+)"\s*$' -or [IO.Path]::GetFileName($Matches[1]) -notin $allowed) { throw "Unexpected installer payload: $line" }
    }
    if ($sources.Count -ne $allowed.Count) { throw 'Installer payload must contain exactly the six approved files' }

    $ldflags = "-s -w -X proxy.local/m0/internal/buildinfo.Version=$Version -X proxy.local/m0/internal/buildinfo.Commit=$Commit -X proxy.local/m0/internal/buildinfo.BuildDate=$BuildDate"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -trimpath -ldflags $ldflags -o dist/windows-amd64/proxy.exe ./cmd/proxy
    if ($LASTEXITCODE) { throw 'proxy build failed' }
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue

    # Build unified proxy-windows-amd64.zip for proxy update and portable usage.
    $zipStage = Join-Path ([IO.Path]::GetTempPath()) ("proxy-win-zip-" + [Guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Path (Join-Path $zipStage "data") -Force | Out-Null
        Copy-Item (Join-Path $stageDir "proxy.exe"), $dllPath, $sysPath, $licPath -Destination $zipStage
        Copy-Item (Join-Path $dataDir "geoip.dat"), (Join-Path $dataDir "geosite.dat") -Destination (Join-Path $zipStage "data")
        $zipOut = Join-Path (Join-Path $repo $ReleaseDir) "proxy-windows-amd64.zip"
        Remove-Item $zipOut -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $zipStage "*") -DestinationPath $zipOut -CompressionLevel Optimal
    } finally {
        Remove-Item $zipStage -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not $SkipInstaller) {
        $compiler = (Get-Command makensis.exe -ErrorAction Stop).Source
        $cleanVer = $Version.TrimStart('v')
        $installerOut = Join-Path (Join-Path $repo $ReleaseDir) "Proxy-Setup-$Version-x64.exe"
        & $compiler /V2 "/DVERSION=$cleanVer" "/DOUTFILE=$installerOut" (Join-Path $PSScriptRoot windows-installer.nsi)
        if ($LASTEXITCODE) { throw 'NSIS compilation failed' }
        Copy-Item $installerOut (Join-Path $repo "dist/installer/Proxy-Setup-x64.exe") -Force
        Get-FileHash $installerOut, (Join-Path (Join-Path $repo $ReleaseDir) "proxy-windows-amd64.zip") -Algorithm SHA256
    } else {
        Get-FileHash (Join-Path (Join-Path $repo $ReleaseDir) "proxy-windows-amd64.zip") -Algorithm SHA256
    }
} finally { Pop-Location }
