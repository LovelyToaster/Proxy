param([Parameter(Mandatory)][string]$Binary)
$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$tempDir = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('proxy-m0-' + [guid]::NewGuid()))
$children = [Collections.Generic.List[Diagnostics.Process]]::new()

function Start-LabProcess {
    param([string[]]$Arguments)
    $log = Join-Path $tempDir.FullName ("process-{0}.log" -f $children.Count)
    $process = Start-Process -FilePath $Binary -ArgumentList $Arguments -RedirectStandardError $log -PassThru -WindowStyle Hidden
    $children.Add($process)
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $process.Refresh()
        if ($process.HasExited) { throw (Get-Content -Raw -LiteralPath $log) }
        $ready = Select-String -LiteralPath $log -Pattern ' ready (.+)$'
        if ($ready) { return $ready.Matches[0].Groups[1].Value }
        Start-Sleep -Milliseconds 25
    }
    throw "Fixture did not start: $Arguments"
}

try {
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($network in @('tcp4', 'tcp6', 'udp4', 'udp6')) {
        try {
            $address = if ($network.EndsWith('6')) { '[::1]:0' } else { '127.0.0.1:0' }
            $target = Start-LabProcess @('echo', $network, $address)
            $relay = Start-LabProcess @('relay', $network, $address, $target)
            & $Binary probe $network $relay
            if ($LASTEXITCODE -ne 0) { throw "Relay probe failed for $network" }
            if ($network.StartsWith('udp')) {
                $otherTarget = Start-LabProcess @('echo', $network, $address)
                $otherRelay = Start-LabProcess @('relay', $network, $address, $otherTarget)
                & $Binary probe-pair $network $relay $otherRelay
                if ($LASTEXITCODE -ne 0) { throw "Multi-target probe failed for $network" }
            }
            Write-Output "$network user-mode loopback OK"
        } catch {
            $failures.Add("$network - $($_.Exception.Message)")
        }
    }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
} finally {
    foreach ($process in $children) {
        if (!$process.HasExited) {
            Stop-Process -InputObject $process -Force
            $process.WaitForExit()
        }
    }
    Get-ChildItem -LiteralPath $tempDir.FullName -File | Remove-Item
    Remove-Item -LiteralPath $tempDir.FullName
}
