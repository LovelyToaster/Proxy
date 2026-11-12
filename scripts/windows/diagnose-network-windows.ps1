param(
    [ValidateSet('on','off')][string]$Label = 'on',
    [string]$Proxy = 'proxy.exe',
    [string]$Site = 'www.baidu.com',
    [string]$OutputDirectory = (Get-Location).Path
)

# Read-only collection. Run once with capture enabled and once after stopping it.
# Explicit DNS server queries are ALSO hijacked while capture is enabled.
$ErrorActionPreference = 'Continue'
$report = Join-Path $OutputDirectory ("proxy-network-{0}-{1}.txt" -f $Label,(Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $report | Out-Null
function Section([string]$Name, [scriptblock]$Action) {
    Write-Host "`n=== $Name ==="
    try { & $Action | Out-String -Width 240 | Write-Host } catch { Write-Host $_ }
}
try {
    Section 'Context' { Get-Date; "Label=$Label Site=$Site"; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber }
    Section 'Adapters' { Get-NetAdapter | Select-Object Name,InterfaceIndex,Status,InterfaceDescription }
    Section 'IP interfaces' { Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,InterfaceMetric,NlMtu }
    Section 'Addresses' { Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,IPAddress,AddressState,PrefixOrigin }
    Section 'DNS servers' { Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses }
    Section 'DNS policy' { Get-DnsClientNrptPolicy -Effective }
    Section 'Default routes' { Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric }
    Section 'Proxy listener owners' {
        Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in @(7891,15090) } | Select-Object LocalAddress,LocalPort,OwningProcess
        Get-NetUDPEndpoint | Where-Object { $_.LocalPort -in @(53,1053,15353) } | Select-Object LocalAddress,LocalPort,OwningProcess
        Get-Process | Where-Object { $_.ProcessName -match 'proxy|mihomo|clash' } | Select-Object Id,ProcessName,Path
    }
    Section 'Capture firewall' {
        $rules = Get-NetFirewallRule -DisplayName 'ProxyTransparent-Capture' -ErrorAction SilentlyContinue
        $rules | Select-Object DisplayName,Enabled,Profile,Direction,Action
        $rules | Get-NetFirewallApplicationFilter | Select-Object Program
        $rules | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort
    }
    if (Get-Command $Proxy -ErrorAction SilentlyContinue) {
        if ($Label -eq 'on') {
            Section 'Status before probes' { & $Proxy status --json; & $Proxy dns status --json }
            Section 'Local DNS engine A' { & $Proxy dns test $Site --server '127.0.0.1:15353' --type A }
            Section 'Local DNS engine AAAA' { & $Proxy dns test $Site --server '127.0.0.1:15353' --type AAAA }
        }
        Section 'Mihomo DNS on 1053' { & $Proxy dns test $Site --server '127.0.0.1:1053' --type A }
    }
    Section 'Windows DNS A' { Resolve-DnsName $Site -Type A -DnsOnly -NoHostsFile -QuickTimeout }
    Section 'Windows DNS AAAA' { Resolve-DnsName $Site -Type AAAA -DnsOnly -NoHostsFile -QuickTimeout }
    foreach ($family in @('-4','-6')) {
        Section "HTTPS $family (no explicit proxy)" {
            & curl.exe $family --noproxy '*' --connect-timeout 4 --max-time 8 -sS -o NUL -w 'ip=%{remote_ip} dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total} http=%{http_code}\n' "https://$Site/"
            "curl_exit=$LASTEXITCODE"
        }
    }
    # Reuse destinations from the supplied failure log; no DNS lookup is involved.
    foreach ($ip in @('202.89.233.100','2409:8c20:5a62:300::df6d:9129')) {
        Section "TCP $ip port 443 (no DNS)" {
            $parsed = [System.Net.IPAddress]::Parse($ip)
            $client = New-Object System.Net.Sockets.TcpClient -ArgumentList $parsed.AddressFamily
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $task = $client.ConnectAsync($parsed,443)
                if (!$task.Wait(4000)) { throw 'connect timeout (4s)' }
                "connected=$($client.Connected) elapsed_ms=$($timer.ElapsedMilliseconds)"
            } finally { $client.Dispose() }
        }
    }
    if ($Label -eq 'on' -and (Get-Command $Proxy -ErrorAction SilentlyContinue)) {
        Section 'Status after probes' { & $Proxy status --json; & $Proxy dns status --json }
        Section 'Recent daemon logs' { & $Proxy logs }
    }
} finally {
    Stop-Transcript | Out-Null
    Write-Host "Saved: $report"
}
