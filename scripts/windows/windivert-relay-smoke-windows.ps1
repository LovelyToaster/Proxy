param([switch]$IPv4Only, [switch]$SkipDNS)
$ErrorActionPreference = 'Stop'
$log = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'dist/windows-amd64/windivert-relay-smoke.log'
Start-Transcript -LiteralPath $log -Force | Out-Null
try {
    & (Join-Path $PSScriptRoot 'wfp-smoke-windows.ps1') -Backend windivert -IPv4Only:$IPv4Only -SkipDNS:$SkipDNS
} catch {
    Write-Host ($_ | Out-String)
    throw
} finally {
    Stop-Transcript | Out-Null
}
