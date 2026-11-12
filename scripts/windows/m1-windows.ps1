$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lab = (New-Item -ItemType Directory -Path (
    Join-Path ([IO.Path]::GetTempPath()) ('proxy-m1-' + [guid]::NewGuid())
)).FullName
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$failures = [Collections.Generic.List[string]]::new()
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH

function Start-LabProcess {
    param([string]$Binary, [string[]]$Arguments, [string]$ReadyPattern)
    $log = Join-Path $lab ("process-{0}.log" -f $children.Count)
    $process = Start-Process -FilePath $Binary -ArgumentList $Arguments -RedirectStandardError $log -PassThru -WindowStyle Hidden
    $children.Add($process)
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) { throw (Get-Content -Raw -LiteralPath $log) }
        $ready = Select-String -LiteralPath $log -Pattern $ReadyPattern | Select-Object -First 1
        if ($ready) {
            return @{
                Process = $process
                Match = $ready.Matches[0]
                Log = $log
            }
        }
        Start-Sleep -Milliseconds 50
    }
    throw "Process did not report readiness: $Binary"
}

function Get-LoopbackEndpoint {
    param([Net.IPAddress]$Address)
    $listener = [Net.Sockets.TcpListener]::new($Address, 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.ToString()
    } finally {
        $listener.Stop()
    }
}

function Invoke-Control {
    param([string[]]$Arguments)
    $result = & $proxy --config $config --runtime $runtime @Arguments
    if ($LASTEXITCODE -ne 0) { throw "proxy $($Arguments -join ' ') failed (exit $LASTEXITCODE)" }
    return $result
}

Push-Location -LiteralPath $repo
try {
    $env:GOOS = 'windows'
    $env:GOARCH = (go env GOHOSTARCH)
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine the native Go architecture' }
    go build -o "$lab/" ./cmd/...
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
    $m0 = Join-Path $lab 'm0.exe'
    $proxy = Join-Path $lab 'proxy.exe'
    $config = Join-Path $lab 'proxy.yaml'
    $runtime = Join-Path $lab 'runtime'

    Write-Host '=== M0 Windows loopback ==='
    try {
        & (Join-Path $PSScriptRoot 'm0-windows.ps1') -Binary $m0
    } catch {
        $failures.Add("M0: $($_.Exception.Message)")
    }

    Write-Host '=== M1 Windows TCP service ==='
    $cases = foreach ($item in @(
        @{ Network = 'tcp4'; Address = [Net.IPAddress]::Loopback },
        @{ Network = 'tcp6'; Address = [Net.IPAddress]::IPv6Loopback }
    )) {
        try {
            $bind = if ($item.Network -eq 'tcp6') { '[::1]:0' } else { '127.0.0.1:0' }
            $echo = Start-LabProcess -Binary $m0 -Arguments @('echo', $item.Network, $bind) -ReadyPattern ' ready (.+)$'
            @{
                Network = $item.Network
                Address = Get-LoopbackEndpoint -Address $item.Address
                Target = $echo.Match.Groups[1].Value
            }
        } catch {
            $failures.Add("M1 $($item.Network) setup: $($_.Exception.Message)")
        }
    }
    if (!$cases) { throw 'No M1 loopback fixture could be started' }

    $listeners = foreach ($case in $cases) {
        '  - address: "{0}"' -f $case.Address
        '    target: "{0}"' -f $case.Target
    }
    $yaml = @"
version: 1
capture:
  mode: off
listeners:
$($listeners -join [Environment]::NewLine)
outbounds:
  first:
    type: direct
  second:
    type: direct
routing:
  rules:
    - outbound: first
"@
    [IO.File]::WriteAllText($config, $yaml)
    Invoke-Control @('config', 'check')
    $service = Start-LabProcess -Binary $proxy -Arguments @(
        'run',
        '--config', ('"{0}"' -f $config),
        '--runtime', ('"{0}"' -f $runtime)
    ) -ReadyPattern 'proxyd ready'
    $initial = Invoke-Control @('status', '--json') | ConvertFrom-Json
    if ($initial.state -ne 'running' -or $initial.generation -ne 1 -or $initial.capture -ne 'off') {
        throw 'Unexpected initial status from Named Pipe'
    }
    Write-Host 'M1 Named Pipe and config: PASS'

    $passed = @()
    foreach ($case in $cases) {
        & $m0 probe $case.Network $case.Address
        if ($LASTEXITCODE -eq 0) {
            Write-Host "M1 $($case.Network) relay: PASS"
            $passed += $case
        } else {
            $failures.Add("M1 $($case.Network) relay failed")
        }
    }
    $before = Invoke-Control @('status', '--json') | ConvertFrom-Json
    if ([int]$before.connected.first -ne $passed.Count) { throw 'Unexpected initial outbound counter' }

    [IO.File]::WriteAllText($config, $yaml.Replace('outbound: first', 'outbound: second'))
    $reload = Invoke-Control @('reload', '--json') | ConvertFrom-Json
    if ($reload.generation -ne 2) { throw 'Reload did not publish generation 2' }
    foreach ($case in $passed) {
        & $m0 probe $case.Network $case.Address
        if ($LASTEXITCODE -ne 0) { throw "M1 $($case.Network) probe failed after reload" }
    }
    $after = Invoke-Control @('status', '--json') | ConvertFrom-Json
    if ($after.generation -ne 2 -or [int]$after.connected.second -ne $passed.Count) {
        throw 'Reloaded outbound was not selected'
    }
    if ($passed.Count -gt 0) { Write-Host 'M1 reload and outbound selection: PASS' }

    $stop = Invoke-Control @('stop', '--json') | ConvertFrom-Json
    if ($stop.state -ne 'stopping' -or !$service.Process.WaitForExit(8000) -or $service.Process.ExitCode -ne 0) {
        throw 'Service did not stop cleanly'
    }
    Write-Host 'M1 stop: PASS'
    if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
    Write-Host 'Windows M0 and M1 loopback: PASS'
} catch {
    if ($service -and (Test-Path -LiteralPath $service.Log)) {
        Get-Content -LiteralPath $service.Log | Select-Object -Last 10 | Write-Host
    }
    throw
} finally {
    foreach ($process in $children) {
        if (!$process.HasExited) {
            Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue
            [void]$process.WaitForExit(5000)
        }
        $process.Dispose()
    }
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    Pop-Location
    Get-ChildItem -LiteralPath $lab -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
    Remove-Item -LiteralPath $lab
}
