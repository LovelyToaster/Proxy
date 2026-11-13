[CmdletBinding()]
param(
    [string]$BinaryDirectory = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'dist/windows-amd64'),
    [switch]$SkipBuild,
    [int]$SizeMiB = 128,
    [int]$Repeats = 2
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员权限运行 PowerShell 后再执行本测速脚本（WinDivert 需要管理员权限）。'
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$bin = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$proxy = Join-Path $bin 'proxy.exe'

if (!$SkipBuild) {
    Write-Host '正在编译最新 proxy.exe ...'
    Push-Location $repoRoot
    try {
        & go build -o $proxy ./cmd/proxy
        if ($LASTEXITCODE -ne 0) { throw 'go build ./cmd/proxy 失败' }
    } finally {
        Pop-Location
    }
}

if (!(Test-Path -LiteralPath $proxy)) {
    throw "未找到 proxy.exe: $proxy"
}
if (!(Test-Path -LiteralPath (Join-Path $bin 'WinDivert.dll'))) {
    throw "未找到 WinDivert.dll，请确认 $bin 目录完整。"
}

$lab = (New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('proxy-bench-' + [guid]::NewGuid()))).FullName
$runtime = Join-Path $lab 'runtime'
New-Item -ItemType Directory -Path $runtime | Out-Null

$fixtureSrc = @'
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const blockSize = 256 * 1024

type result struct {
	Label     string  `json:"label"`
	Direction string  `json:"direction"`
	Streams   int     `json:"streams"`
	Repeat    int     `json:"repeat"`
	Bytes     int64   `json:"bytes"`
	Seconds   float64 `json:"seconds"`
	Mbps      float64 `json:"mbps"`
}

func serve(conn net.Conn, size int64, block []byte) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	var mode [1]byte
	if _, err := io.ReadFull(conn, mode[:]); err != nil {
		return
	}
	switch mode[0] {
	case 'D':
		for sent := int64(0); sent < size; {
			chunk := block
			if rem := size - sent; rem < int64(len(chunk)) {
				chunk = chunk[:rem]
			}
			n, err := conn.Write(chunk)
			sent += int64(n)
			if err != nil {
				return
			}
		}
	case 'U':
		buf := make([]byte, blockSize)
		for recvd := int64(0); recvd < size; {
			want := len(buf)
			if rem := size - recvd; rem < int64(want) {
				want = int(rem)
			}
			n, err := conn.Read(buf[:want])
			recvd += int64(n)
			if err != nil {
				return
			}
		}
		_, _ = conn.Write([]byte{'K'})
	}
}

func runServer(addr string, size int64) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "ready throughput")
	block := make([]byte, blockSize)
	for i := range block {
		block[i] = 'x'
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serve(c, size, block)
	}
}

func transfer(addr, mode string, size int64, block []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write([]byte(mode)); err != nil {
		return err
	}
	if mode == "U" {
		for sent := int64(0); sent < size; {
			chunk := block
			if rem := size - sent; rem < int64(len(chunk)) {
				chunk = chunk[:rem]
			}
			n, err := conn.Write(chunk)
			sent += int64(n)
			if err != nil {
				return err
			}
		}
		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 'K' {
			return fmt.Errorf("missing ack: %v", err)
		}
	} else {
		buf := make([]byte, blockSize)
		for recvd := int64(0); recvd < size; {
			n, err := conn.Read(buf)
			recvd += int64(n)
			if err != nil && recvd < size {
				return err
			}
		}
	}
	return nil
}

func runClient(addr, label string, size int64, repeats int) error {
	block := make([]byte, blockSize)
	for i := range block {
		block[i] = 'x'
	}
	for _, mode := range []string{"D", "U"} {
		for _, streams := range []int{1, 4} {
			for r := 1; r <= repeats; r++ {
				start := time.Now()
				var wg sync.WaitGroup
				errs := make(chan error, streams)
				for range streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := transfer(addr, mode, size, block); err != nil {
							errs <- err
						}
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					return err
				}
				elapsed := time.Since(start).Seconds()
				totalBytes := size * int64(streams)
				mbps := float64(totalBytes) * 8 / elapsed / 1e6
				line, _ := json.Marshal(result{
					Label:     label,
					Direction: mode,
					Streams:   streams,
					Repeat:    r,
					Bytes:     totalBytes,
					Seconds:   float64(int(elapsed*10000)) / 10000,
					Mbps:      float64(int(mbps*100)) / 100,
				})
				fmt.Println(string(line))
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 4 {
		os.Exit(2)
	}
	sizeMiB, _ := strconv.ParseInt(os.Args[3], 10, 64)
	size := sizeMiB * 1024 * 1024
	switch os.Args[1] {
	case "server":
		if err := runServer(os.Args[2], size); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "client":
		if len(os.Args) < 6 {
			os.Exit(2)
		}
		repeats, _ := strconv.Atoi(os.Args[5])
		if err := runClient(os.Args[2], os.Args[4], size, repeats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
'@

$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$records = [Collections.Generic.List[object]]::new()

function Start-BgProcess {
    param([string]$FilePath, [string[]]$ArgumentList, [string]$ReadyMarker, [string]$Tag)
    $stdout = Join-Path $lab "$Tag.stdout"
    $stderr = Join-Path $lab "$Tag.stderr"
    $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $children.Add($p)
    for ($i = 0; $i -lt 120; $i++) {
        if ($p.HasExited) {
            $errText = if (Test-Path $stderr) { Get-Content -Raw -LiteralPath $stderr } else { '' }
            $outText = if (Test-Path $stdout) { Get-Content -Raw -LiteralPath $stdout } else { '' }
            throw "$Tag 提前退出 (code=$($p.ExitCode)):`n$errText`n$outText"
        }
        $hit = $false
        if ((Test-Path $stderr) -and (Select-String -LiteralPath $stderr -SimpleMatch $ReadyMarker -Quiet)) { $hit = $true }
        if ((Test-Path $stdout) -and (Select-String -LiteralPath $stdout -SimpleMatch $ReadyMarker -Quiet)) { $hit = $true }
        if ($hit) { return @{ Process = $p; Stdout = $stdout; Stderr = $stderr } }
        Start-Sleep -Milliseconds 100
    }
    throw "$Tag 启动超时"
}

try {
    $srcPath = Join-Path $lab 'fixture.go'
    Set-Content -LiteralPath $srcPath -Value $fixtureSrc -Encoding UTF8
    $serverExe = Join-Path $lab 'bench-server.exe'
    $clientExe = Join-Path $lab 'bench-client.exe'
    Write-Host '正在编译测速夹具...'
    & go build -o $serverExe $srcPath
    if ($LASTEXITCODE -ne 0) { throw '编译 bench-server.exe 失败' }
    Copy-Item -LiteralPath $serverExe -Destination $clientExe

    $null = Start-BgProcess -FilePath $serverExe -ArgumentList @('server', '127.0.0.1:18443', "$SizeMiB") -ReadyMarker 'ready throughput' -Tag 'server-v4'
    $null = Start-BgProcess -FilePath $serverExe -ArgumentList @('server', '[::1]:18443', "$SizeMiB") -ReadyMarker 'ready throughput' -Tag 'server-v6'

    Write-Host "`n[1/2] 测试直连基线 (IPv4 & IPv6, ${SizeMiB}MiB/流 x $Repeats 轮)..."
    foreach ($pair in @(@('127.0.0.1:18443', 'direct-v4'), @('[::1]:18443', 'direct-v6'))) {
        $lines = & $clientExe client $pair[0] "$SizeMiB" $pair[1] "$Repeats"
        if ($LASTEXITCODE -ne 0) { throw "直连测速失败: $($pair[1])" }
        foreach ($line in $lines) {
            Write-Host $line
            $records.Add(($line | ConvertFrom-Json))
        }
    }

    $cfgPath = Join-Path $lab 'bench.yaml'
    $escapedClient = $clientExe.Replace('\', '\\')
    @"
capture:
  mode: windivert
  scope: application
  windows_application: "$escapedClient"
  ipv4: true
  ipv6: true
  udp: true
outbounds:
  captured:
    type: direct
routing:
  rules:
    - outbound: captured
"@ | Set-Content -LiteralPath $cfgPath -Encoding UTF8

    Write-Host "`n[2/2] 启动 WinDivert 应用级接管代理并测速..."
    $proxyProc = Start-BgProcess -FilePath $proxy -ArgumentList @('run', '--config', $cfgPath, '--runtime', $runtime) -ReadyMarker 'proxyd ready' -Tag 'proxy'
    $cores = [Environment]::ProcessorCount
    try {
        foreach ($pair in @(@('127.0.0.1:18443', 'windivert-app-v4'), @('[::1]:18443', 'windivert-app-v6'))) {
            $proxyProc.Process.Refresh()
            $cpuBefore = $proxyProc.Process.TotalProcessorTime
            $wallBefore = [DateTime]::UtcNow
            $lines = & $clientExe client $pair[0] "$SizeMiB" $pair[1] "$Repeats"
            if ($LASTEXITCODE -ne 0) { throw "WinDivert 测速失败: $($pair[1])" }
            $wallAfter = [DateTime]::UtcNow
            $proxyProc.Process.Refresh()
            $cpuAfter = $proxyProc.Process.TotalProcessorTime
            $wallSec = ($wallAfter - $wallBefore).TotalSeconds
            $cpuSec = ($cpuAfter - $cpuBefore).TotalSeconds
            $usedCores = if ($wallSec -gt 0) { [math]::Round($cpuSec / $wallSec, 2) } else { 0 }
            $totalPct = if ($wallSec -gt 0) { [math]::Round($cpuSec / ($wallSec * $cores) * 100, 2) } else { 0 }
            $rssMiB = [math]::Round($proxyProc.Process.WorkingSet64 / 1MB, 2)
            foreach ($line in $lines) {
                Write-Host $line
                $records.Add(($line | ConvertFrom-Json))
            }
            Write-Host ("CPU_STATS scenario={0} wall_s={1:N2} proxy_cpu_s={2:N2} proxy_cores={3:N2}/{4} total_cpu_pct={5:N2}% rss_mib={6:N2}" -f $pair[1], $wallSec, $cpuSec, $usedCores, $cores, $totalPct, $rssMiB)
        }
        $statusJson = & $proxy --config $cfgPath --runtime $runtime status --json
        Write-Host "`n代理状态:"
        Write-Host $statusJson
    } finally {
        & $proxy --config $cfgPath --runtime $runtime stop | Out-Null
        if (!$proxyProc.Process.WaitForExit(5000)) {
            $proxyProc.Process.Kill()
        }
    }

    Write-Host "`n=== 聚合汇总 (平均速率) ==="
    $grouped = $records | Group-Object label, direction, streams | ForEach-Object {
        $avgMbps = ($_.Group | Measure-Object -Property mbps -Average).Average
        [pscustomobject]@{
            Scenario  = $_.Group[0].label
            Dir       = $_.Group[0].direction
            Streams   = $_.Group[0].streams
            Mbps      = [math]::Round($avgMbps, 2)
            Gbps      = [math]::Round($avgMbps / 1000, 2)
        }
    }
    $grouped | Format-Table -AutoSize
} finally {
    foreach ($p in $children) {
        if (!$p.HasExited) { $p.Kill(); [void]$p.WaitForExit(3000) }
        $p.Dispose()
    }
    if (Test-Path -LiteralPath $lab) {
        Remove-Item -LiteralPath $lab -Recurse -Force -ErrorAction SilentlyContinue
    }
}
