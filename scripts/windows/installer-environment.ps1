[CmdletBinding()]
param(
    [ValidateSet('Add', 'Remove')][string]$Action = 'Add',
    [string]$Directory,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
function Same-Path([string]$Left, [string]$Right) {
    return [string]::Equals([Environment]::ExpandEnvironmentVariables($Left.Trim().Trim('"')).TrimEnd('\'), $Right.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
}
function Update-PathValue([string]$Value, [string]$Target, [bool]$Remove) {
    $parts = @()
    if ($Value -ne '') { $parts = @($Value.Split(';')) }
    if ($Remove) { return (@($parts | Where-Object { !(Same-Path $_ $Target) }) -join ';') }
    if (@($parts | Where-Object { Same-Path $_ $Target }).Count) { return $Value }
    return ((@($parts) + $Target) -join ';')
}
if ($SelfTest) {
    $target = 'C:\Program Files\Proxy'
    if ((Update-PathValue 'C:\Windows' $target $false) -ne "C:\Windows;$target") { throw 'Add failed' }
    if ((Update-PathValue "C:\Windows;$target\" $target $false) -ne "C:\Windows;$target\") { throw 'Deduplication failed' }
    if ((Update-PathValue "C:\ProxyTools;$target;C:\Windows" $target $true) -ne 'C:\ProxyTools;C:\Windows') { throw 'Removal failed' }
    'PATH transformation tests: PASS'
    exit 0
}
if (!$Directory -or ![IO.Path]::IsPathRooted($Directory)) { throw 'Absolute installation directory required' }
$machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$key = $machine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
$ownership = $machine.CreateSubKey('Software\ProxyTransparent')
try {
    $value = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $present = @($value.Split(';') | Where-Object { Same-Path $_ $Directory }).Count -gt 0
    if ($Action -eq 'Add') {
        if (!$present) {
            $key.SetValue('Path', (Update-PathValue $value $Directory $false), [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $ownership.SetValue('PathAdded', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        }
    } elseif ($ownership.GetValue('PathAdded', 0) -eq 1) {
        $key.SetValue('Path', (Update-PathValue $value $Directory $true), [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $ownership.DeleteValue('PathAdded', $false)
    }
} finally { $key.Close(); $ownership.Close(); $machine.Close() }
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ProxyEnvironmentNotify {
 [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);
}
'@
$result = [UIntPtr]::Zero
$null = [ProxyEnvironmentNotify]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 2000, [ref]$result)
