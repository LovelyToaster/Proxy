[CmdletBinding()]
param(
    [switch]$IPv4Only,
    [switch]$SkipDNS
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$log = Join-Path $repo 'dist/windows-amd64/windivert-relay-smoke.log'
Start-Transcript -LiteralPath $log -Force | Out-Null

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the approved live test from an elevated PowerShell.'
    }
    if ((Get-DnsClientServerAddress).ServerAddresses | Where-Object { $_ -in @('127.0.0.1', '::1') }) {
        throw 'The DNS 53 fixtures would overlap a configured Windows resolver. Run the smoke test in an isolated Windows environment.'
    }

    $lab = (New-Item -ItemType Directory -Path (
        Join-Path ([IO.Path]::GetTempPath()) ('proxy-windivert-' + [guid]::NewGuid())
    )).FullName
    $children = [Collections.Generic.List[Diagnostics.Process]]::new()
    $oldGOOS = $env:GOOS
    $oldGOARCH = $env:GOARCH
    $oldDNSFixture = $env:PROXY_M3_DNS_FIXTURE
    $v6Enabled = if ($IPv4Only) { 'false' } else { 'true' }
    $scopeCIDRs = if ($IPv4Only) { '["127.0.0.1/32"]' } else { '["127.0.0.1/32", "::1/128"]' }
    $expectedTCP = if ($IPv4Only) { 1 } else { 2 }
    $expectedUDP = 2 * $expectedTCP

    function Get-LabPort {
        $ipv4 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $ipv6 = $null
        try {
            $ipv4.Start()
            $port = $ipv4.LocalEndpoint.Port
            $ipv6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, $port)
            $ipv6.Start()
            return $port
        } finally {
            if ($ipv6) { $ipv6.Stop() }
            $ipv4.Stop()
        }
    }

    function Start-Fixture {
        param([string]$Binary, [string[]]$Arguments, [string]$Ready)
        $procLog = Join-Path $lab "process-$($children.Count).log"
        $stdout = "$procLog.stdout"
        $process = Start-Process -FilePath $Binary -ArgumentList $Arguments -RedirectStandardError $procLog -RedirectStandardOutput $stdout -PassThru -WindowStyle Hidden
        $children.Add($process)
        for ($i = 0; $i -lt 120; $i++) {
            if ($process.HasExited) { throw ((Get-Content -LiteralPath $procLog, $stdout) -join [Environment]::NewLine) }
            if (Select-String -LiteralPath $procLog, $stdout -SimpleMatch $Ready -Quiet) {
                return $process
            }
            Start-Sleep -Milliseconds 50
        }
        throw "Fixture did not start: $(Get-Content -Raw -LiteralPath $procLog)"
    }

    function Probe {
        param([string]$Binary, [string]$Network, [string]$Endpoint)
        if ($IPv4Only -and $Network.EndsWith('6')) { return }
        & $Binary probe $Network $Endpoint
        if ($LASTEXITCODE -ne 0) { throw "$Network probe failed for $Endpoint" }
    }

    function Control {
        param([string]$Operation)
        $result = & $proxy --runtime $runtime $Operation --json
        if ($LASTEXITCODE -ne 0) { throw "proxy $Operation failed" }
        return $result | ConvertFrom-Json
    }

    function Probe-DNS {
        param([string]$Binary, [string]$Endpoint, [string]$Expected)
        if ($IPv4Only -and $Endpoint.StartsWith('[')) { return }
        foreach ($transport in @('udp', 'tcp')) {
            $probeArgs = @('dns', 'test', 'probe.test', '--server', $Endpoint, '--type', 'TXT')
            if ($transport -eq 'tcp') { $probeArgs += '--tcp' }
            $result = & $Binary @probeArgs 2>&1
            if ($LASTEXITCODE -ne 0 -or !($result | Select-String -SimpleMatch ('"' + $Expected + '"'))) {
                $response = ($result | ForEach-Object { "$_" }) -join [Environment]::NewLine
                throw "$transport DNS probe for $Endpoint expected $Expected, exit=$LASTEXITCODE, received $response"
            }
        }
    }

    Push-Location -LiteralPath $repo
    try {
        $env:GOOS = 'windows'
        $env:GOARCH = (go env GOHOSTARCH)
        if ($LASTEXITCODE -ne 0) { throw 'Unable to determine Go host architecture' }
        go build -o "$lab/" ./cmd/...
        if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
        foreach ($file in @('WinDivert.dll', 'WinDivert64.sys')) {
            Copy-Item -LiteralPath (Join-Path $repo "dist/windows-amd64/$file") -Destination $lab
        }
        $echo = Join-Path $lab 'm0.exe'
        $client = Join-Path $lab 'windivert-probe.exe'
        Copy-Item -LiteralPath $echo -Destination $client
        $proxy = Join-Path $lab 'proxy.exe'
        $config = Join-Path $lab 'proxy.yaml'
        $runtime = Join-Path $lab 'runtime'
        $targetPort = Get-LabPort
        $v4 = "127.0.0.1:$targetPort"
        $v6 = "[::1]:$targetPort"
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'tcp4', $v4) -Ready ' ready '
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'tcp6', $v6) -Ready ' ready '
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'udp4', $v4) -Ready ' ready '
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'udp6', $v6) -Ready ' ready '
        $otherPort = Get-LabPort
        $other4 = "127.0.0.1:$otherPort"
        $other6 = "[::1]:$otherPort"
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'udp4', $other4) -Ready ' ready '
        $null = Start-Fixture -Binary $echo -Arguments @('echo', 'udp6', $other6) -Ready ' ready '
        $listenPort = Get-LabPort
        $yamlApp = $client.Replace("'", "''")
        [IO.File]::WriteAllText($config, @"
version: 1
capture:
  mode: windivert
  windows_application: '$yamlApp'
  ipv4: true
  ipv6: $v6Enabled
  udp: true
  port: $listenPort
  cidrs: $scopeCIDRs
  ports: [$targetPort]
outbounds:
  direct:
    type: direct
routing:
  rules:
    - outbound: direct
"@)
        & $proxy --config $config config check
        if ($LASTEXITCODE -ne 0) { throw 'WinDivert scope configuration failed validation' }
        Probe $client tcp4 $v4
        Probe $client tcp6 $v6
        Probe $client udp4 $v4
        Probe $client udp6 $v6

        $serviceArgs = @('run', '--config', ('"{0}"' -f $config), '--runtime', ('"{0}"' -f $runtime))
        $service = Start-Fixture -Binary $proxy -Arguments $serviceArgs -Ready 'proxyd ready'
        Probe $client tcp4 $v4
        Probe $client tcp6 $v6
        if ((Control status).connected.direct -ne $expectedTCP) { throw 'Unexpected scoped TCP connection count' }
        Probe $echo tcp4 $v4
        Probe $echo tcp6 $v6
        if ((Control status).connected.direct -ne $expectedTCP) { throw 'An unscoped application was redirected' }
        Write-Host "windivert TCP redirect and application isolation (IPv4Only=$IPv4Only): PASS"
        Probe $client udp4 $v4
        Probe $client udp6 $v6
        & $client probe-pair udp4 $v4 $other4
        if ($LASTEXITCODE -ne 0) { throw 'IPv4 UDP multi-target/source-port probe failed' }
        if (!$IPv4Only) {
            & $client probe-pair udp6 $v6 $other6
            if ($LASTEXITCODE -ne 0) { throw 'IPv6 UDP multi-target/source-port probe failed' }
        }
        if ((Control status).udp.opened.direct -ne $expectedUDP) { throw 'Unexpected scoped UDP association count' }
        $udpStatus = (Control status).udp
        if (!$udpStatus.PSObject.Properties['capture_dropped'] -or $udpStatus.capture_dropped -ne 0) {
            throw 'Capture UDP drop counter missing or nonzero'
        }
        Probe $echo udp4 $v4
        Probe $echo udp6 $v6
        if ((Control status).udp.opened.direct -ne $expectedUDP) { throw 'An unscoped application was redirected' }
        Write-Host "windivert connected UDP, sendto, source port and application isolation (IPv4Only=$IPv4Only): PASS"
        if ((Control stop).state -ne 'stopping' -or !$service.WaitForExit(8000) -or $service.ExitCode -ne 0) {
            throw 'Proxy failed to stop cleanly'
        }
        Probe $client tcp4 $v4
        Probe $client tcp6 $v6
        Probe $client udp4 $v4
        Probe $client udp6 $v6

        $service = Start-Fixture -Binary $proxy -Arguments $serviceArgs -Ready 'proxyd ready'
        Probe $client tcp4 $v4
        if ((Control status).connected.direct -ne 1) { throw 'WinDivert re-arm failed' }
        $service.Kill()
        if (!$service.WaitForExit(5000)) { throw 'Proxy process did not exit' }
        Probe $client tcp4 $v4
        Probe $client tcp6 $v6
        Probe $client udp4 $v4
        Probe $client udp6 $v6
        Write-Host "windivert clean stop and process-crash recovery: PASS"
        if ($SkipDNS) {
            Write-Host 'DNS 53 live tests skipped'
            return
        }

        $fixture = Join-Path $lab 'dns-fixture.exe'
        go test -c -o $fixture ./internal/dnsengine
        if ($LASTEXITCODE -ne 0) { throw 'Unable to build the local DNS fixture' }
        $dnsClient = Join-Path $lab 'windivert-dns-probe.exe'
        Copy-Item -LiteralPath $proxy -Destination $dnsClient
        $dns4 = '127.0.0.1:53'
        $dns6 = '[::1]:53'
        $upstream = "127.0.0.1:$(Get-LabPort)"
        foreach ($endpoint in @($dns4, $dns6, $upstream)) {
            $env:PROXY_M3_DNS_FIXTURE = $endpoint
            $null = Start-Fixture -Binary $fixture -Arguments @('-test.v', '-test.run=^TestM3LabUpstream$') -Ready 'DNS fixture ready'
        }
        Probe-DNS $dnsClient $dns4 $dns4
        Probe-DNS $dnsClient $dns6 $dns6
        $yamlDNSApp = $dnsClient.Replace("'", "''")
        [IO.File]::WriteAllText($config, @"
version: 1
capture:
  mode: windivert
  windows_application: '$yamlDNSApp'
  ipv4: true
  ipv6: $v6Enabled
  port: $listenPort
  cidrs: $scopeCIDRs
outbounds:
  direct:
    type: direct
routing:
  rules:
    - outbound: direct
dns:
  enabled: true
  hijack: true
  upstreams:
    lab:
      type: udp
      address: "$upstream"
  rules:
    - upstream: lab
"@)
        $service = Start-Fixture -Binary $proxy -Arguments $serviceArgs -Ready 'proxyd ready'
        Probe-DNS $dnsClient $dns4 $upstream
        Probe-DNS $dnsClient $dns6 $upstream
        Probe-DNS $proxy $dns4 $dns4
        Probe-DNS $proxy $dns6 $dns6
        if ((Control stop).state -ne 'stopping' -or !$service.WaitForExit(8000) -or $service.ExitCode -ne 0) {
            throw 'DNS capture failed to stop cleanly'
        }
        Probe-DNS $dnsClient $dns4 $dns4
        Probe-DNS $dnsClient $dns6 $dns6
        Write-Host "windivert DNS UDP/TCP 53, application isolation and restoration (IPv4Only=$IPv4Only): PASS"
    } catch {
        Get-ChildItem -LiteralPath $lab -Filter 'process-*.log*' -File |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Tail 12 | Write-Host }
        throw
    } finally {
        foreach ($process in $children) {
            if (!$process.HasExited) {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            }
            $process.Dispose()
        }
        $env:GOOS = $oldGOOS
        $env:GOARCH = $oldGOARCH
        $env:PROXY_M3_DNS_FIXTURE = $oldDNSFixture
        Pop-Location
        Get-ChildItem -LiteralPath $lab -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Remove-Item -LiteralPath $lab
    }
} catch {
    Write-Host ($_ | Out-String)
    throw
} finally {
    Stop-Transcript | Out-Null
}
