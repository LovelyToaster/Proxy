[CmdletBinding()]
param([string]$BinaryDirectory = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'dist/windows-amd64'))

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this loopback test from an administrator PowerShell.'
}
$bin = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$proxy = Join-Path $bin 'proxy.exe'
$echo = Join-Path $bin 'm0.exe'
$log = Join-Path $bin 'windivert-smoke.log'
$lab = (New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('proxy-divert-' + [guid]::NewGuid()))).FullName
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$failures = [Collections.Generic.List[string]]::new()
Start-Transcript -LiteralPath $log -Force | Out-Null
function Start-Fixture {
    param([string]$Binary, [string[]]$Arguments, [string]$Ready)
    $stderr = Join-Path $lab "process-$($children.Count).stderr"
    $stdout = Join-Path $lab "process-$($children.Count).stdout"
    $process = Start-Process -FilePath $Binary -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardError $stderr -RedirectStandardOutput $stdout
    $children.Add($process)
    for ($i = 0; $i -lt 100; $i++) {
        if ($process.HasExited) { throw (Get-Content -Raw -LiteralPath $stderr) }
        if (Select-String -LiteralPath $stderr -SimpleMatch $Ready -Quiet) {
            return @{ Process = $process; Stdout = $stdout; Stderr = $stderr }
        }
        Start-Sleep -Milliseconds 50
    }
    throw 'Fixture readiness timed out'
}
try {
    & $proxy capture sniff --duration 1s --filter false
    if ($LASTEXITCODE) { throw 'Empty-filter timeout failed' }
    $status = & $proxy capture status --json | ConvertFrom-Json
    if ($LASTEXITCODE -or !$status.driver_loaded -or $status.version -ne '2.2') {
        throw 'WinDivert version query failed'
    }
    Write-Host 'WinDivert version and empty-filter timeout: PASS'
    $sniff = Start-Fixture $proxy @('capture', 'sniff', '--duration', '10s', '--filter', '"loopback and (tcp or udp)"') 'WinDivert sniff ready'
    foreach ($network in @('tcp4', 'tcp6', 'udp4', 'udp6')) {
        $address = if ($network.EndsWith('4')) { '127.0.0.1' } else { '::1' }
        # Obtain a dedicated port from each echo fixture.
        $listener = if ($network.StartsWith('tcp')) {
            [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($address), 0)
        } else { $null }
        if ($listener) {
            try { $listener.Start(); $port = $listener.LocalEndpoint.Port } finally { $listener.Stop() }
        } else {
            $udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($address), 0))
            try { $port = $udp.Client.LocalEndPoint.Port } finally { $udp.Dispose() }
        }
        $endpoint = if ($network.EndsWith('4')) { "${address}:$port" } else { "[${address}]:$port" }
        $fixture = Start-Fixture $echo @('echo', $network, $endpoint) ' ready '
        & $echo probe $network $endpoint
        if ($LASTEXITCODE) {
            $failures.Add("$network loopback failed")
        } else {
            Write-Host "$network loopback during sniff: PASS"
        }
        $fixture.Process.Kill()
        [void]$fixture.Process.WaitForExit(3000)
    }
    if (!$sniff.Process.WaitForExit(15000) -or $sniff.Process.ExitCode -ne 0) {
        throw 'Sniff failed to finish'
    }
    $counts = Get-Content -Raw -LiteralPath $sniff.Stdout | ConvertFrom-Json
    if ($counts.ipv4 -le 0 -or $counts.ipv6 -le 0) { $failures.Add('Expected both IPv4 and IPv6 captured packets') }
    $counts | ConvertTo-Json -Compress | Write-Host
    if ($failures.Count) { throw ($failures -join [Environment]::NewLine) }
    Write-Host 'WinDivert dual-stack read-only sniff: PASS'
} catch {
    Write-Host ($_ | Out-String)
    throw
} finally {
    foreach ($process in $children) {
        if (!$process.HasExited) { $process.Kill(); [void]$process.WaitForExit(3000) }
        $process.Dispose()
    }
    Stop-Transcript | Out-Null
}
