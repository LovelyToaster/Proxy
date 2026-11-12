[CmdletBinding()]
param(
    [string]$DomesticURL = 'https://www.baidu.com/',
    [string]$ForeignURL = 'https://example.com/'
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$bin = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'dist/windows-amd64'
Push-Location -LiteralPath $bin
function Get-Control {
    param([string[]]$Arguments)
    $value = & .\proxy.exe --runtime .\runtime-global @Arguments --json
    if ($LASTEXITCODE) { throw "Control failed for $Arguments" }
    return $value | ConvertFrom-Json
}
function Get-Count {
    param($Map, [string]$Name)
    if (!$Map -or !$Map.PSObject.Properties[$Name]) { return 0 }
    return [long]$Map.$Name
}
try {
    $before = Get-Control -Arguments @('status')
    if ($before.capture -ne 'windivert' -or $before.capture_stats.scope -ne 'global') { throw 'Start proxy-global.yaml with WinDivert first' }
    $dnsBefore = Get-Control -Arguments @('dns', 'status')
    $null = Get-Control -Arguments @('dns', 'flush')
    Clear-DnsClientCache
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($url in @($DomesticURL, $ForeignURL)) {
        Write-Host "Testing $url"
        & "$env:SystemRoot\System32\curl.exe" --noproxy '*' --connect-timeout 15 --max-time 40 --fail --silent --show-error --output NUL --write-out 'HTTP %{http_code}\n' $url
        if ($LASTEXITCODE) { $failures.Add("Request failed for $url") }
    }
    $after = Get-Control -Arguments @('status')
    $dnsAfter = Get-Control -Arguments @('dns', 'status')
    $direct = (Get-Count $after.connected 'direct') - (Get-Count $before.connected 'direct')
    $proxy = (Get-Count $after.connected 'proxy') - (Get-Count $before.connected 'proxy')
    $mainland = (Get-Count $dnsAfter.upstream_requests 'mainland') - (Get-Count $dnsBefore.upstream_requests 'mainland')
    $other = (Get-Count $dnsAfter.upstream_requests 'other') - (Get-Count $dnsBefore.upstream_requests 'other')
    Write-Host "TCP direct +$direct, SOCKS5 +$proxy"
    Write-Host "DNS mainland +$mainland, other DoH +$other"
    $after | ConvertTo-Json -Depth 5
    $dnsAfter | ConvertTo-Json -Depth 5
    if ($direct -lt 1 -or $proxy -lt 1) { $failures.Add('Expected both direct and proxy connections; check the GeoIP classification of the test destinations') }
    if ($mainland -lt 1 -or $other -lt 1) { $failures.Add('Expected both DNS upstreams; check the GEOSITE classification of the test names') }
    if ($failures.Count) { throw ($failures -join [Environment]::NewLine) }
    Write-Host 'Global capture with system DNS, CN/direct, other/SOCKS5 and DNS split: PASS'
} finally {
    Pop-Location
}

