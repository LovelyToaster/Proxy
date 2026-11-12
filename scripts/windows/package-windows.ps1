[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location -LiteralPath $repo
try {
    $allowed = @('proxy.exe','WinDivert.dll','WinDivert64.sys','WinDivert-LICENSE','geoip.dat','geosite.dat')
    $sources = @(Get-Content (Join-Path $PSScriptRoot windows-installer.nsi) | Where-Object { $_ -match '^\s*File\s' })
    foreach ($line in $sources) {
        if ($line -notmatch '"([^"\r\n]+)"\s*$' -or [IO.Path]::GetFileName($Matches[1]) -notin $allowed) { throw "Unexpected installer payload: $line" }
    }
    if ($sources.Count -ne $allowed.Count) { throw 'Installer payload must contain exactly the six approved files' }
    New-Item -ItemType Directory -Path dist/installer -Force | Out-Null
    go build -trimpath -ldflags '-s -w' -o dist/windows-amd64/proxy.exe ./cmd/proxy
    if ($LASTEXITCODE) { throw 'proxy build failed' }
    Push-Location dist/windows-amd64
    try {
        .\proxy.exe --config .\proxy-global.yaml config check
        if ($LASTEXITCODE) { throw 'Configuration validation failed' }
    } finally { Pop-Location }
    $compiler = (Get-Command makensis.exe -ErrorAction Stop).Source
    & $compiler /V2 (Join-Path $PSScriptRoot windows-installer.nsi)
    if ($LASTEXITCODE) { throw 'NSIS compilation failed' }
    Get-FileHash dist/installer/Proxy-Setup-x64.exe -Algorithm SHA256
} finally { Pop-Location }

