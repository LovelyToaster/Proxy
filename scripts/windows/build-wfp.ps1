[CmdletBinding()]
param(
    [ValidateSet('x64', 'ARM64')][string]$Platform = 'x64',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$project = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'platform/windows/wfp-driver/ProxyWfp.vcxproj'
$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if (!$msbuild) { throw 'Run this script from a WDK or EWDK developer shell with MSBuild on PATH.' }
& $msbuild.Source $project /m /t:Build "/p:Platform=$Platform" "/p:Configuration=$Configuration"
if ($LASTEXITCODE -ne 0) { throw "WDK build failed (exit $LASTEXITCODE)" }
$driver = Join-Path (Split-Path -Parent $project) "out/$Platform/$Configuration/ProxyWfp.sys"
if (!(Test-Path -LiteralPath $driver -PathType Leaf)) { throw 'WDK build did not produce ProxyWfp.sys' }
Get-Item -LiteralPath $driver
