[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSCommandPath) {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden `
            -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$PSCommandPath`"") | Out-Null
    }
    return
}

$SID_SYSTEM = '*S-1-5-18'
$SID_TI     = '*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

foreach ($r in 'HKCU:\Software\Policies','HKLM:\Software\Policies') {
    if (Test-Path $r) {
        Get-ChildItem $r -Recurse | Where-Object { $_.PSChildName -eq 'URLBlocklist' } |
            Remove-Item -Recurse -Force
    }
}

foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') {
    Remove-ItemProperty $p -Name 'SettingsPageVisibility' -Force
}

$hf = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
if (Test-Path $hf) {
    $keep = foreach ($l in Get-Content $hf) {
        $t = $l.TrimStart()
        if ($t -eq '' -or $t.StartsWith('#')) { $l }
        elseif ($t -match '^\s*[0-9a-fA-F\.:]+\s+\S+') { }
        else { $l }
    }
    Set-ItemProperty $hf -Name IsReadOnly -Value $false
    Set-Content $hf -Value $keep -Encoding ASCII -Force
}

foreach ($b in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    if (Test-Path $b) {
        Get-ChildItem $b | ForEach-Object { Remove-ItemProperty $_.PSPath -Name 'Debugger' -Force }
    }
}

if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    Get-NetFirewallRule -Enabled True -Action Block | Remove-NetFirewallRule
}

foreach ($d in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains') {
    if (Test-Path $d) {
        Get-ChildItem $d -Recurse | Where-Object {
            (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -eq 4 }
        } | Remove-Item -Recurse -Force
    }
}
foreach ($z in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3') {
    if (Test-Path $z) { Set-ItemProperty $z -Name '1806' -Value 0 -Type DWord -Force }
}

foreach ($h in 'HKCU:','HKLM:') {
    $k = "$h\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    if (Test-Path $k) { Remove-Item $k -Recurse -Force }
}

$pp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
if (Test-Path $pp) { Set-ItemProperty $pp -Name 'EnablePrefetcher' -Value 3 -Type DWord -Force }
Set-Service -Name SysMain -StartupType Automatic
Start-Service -Name SysMain
$pf = Join-Path $env:WINDIR 'Prefetch'
if (Test-Path $pf) {
    $deny = (Get-Acl $pf).Access | Where-Object { $_.AccessControlType -eq 'Deny' }
    if ($deny) {
        & icacls $pf /reset 2>&1 | Out-Null
        & icacls $pf /grant "${SID_SYSTEM}:(OI)(CI)F" 2>&1 | Out-Null
        Restart-Service SysMain
    }
}

foreach ($n in 'fsutil.exe','wevtutil.exe','powershell.exe','cmd.exe','reg.exe','regedit.exe',
                'tasklist.exe','sc.exe','netsh.exe','certutil.exe','wmic.exe') {
    $f = Join-Path $env:WINDIR "System32\$n"
    if (-not (Test-Path $f)) { continue }
    $deny = (Get-Acl $f).Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and $_.IdentityReference -match 'Users|Administrators|Everyone|Authenticated'
    }
    if ($deny) {
        & takeown /f $f /a 2>&1 | Out-Null
        & icacls $f /reset 2>&1 | Out-Null
        & icacls $f /setowner $SID_TI 2>&1 | Out-Null
    }
}

Remove-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32' -Name 'NotFileMru' -Force

$ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
if (Test-Path $ci) { Set-ItemProperty $ci -Name 'VerifiedAndReputablePolicyState' -Value 0 -Type DWord -Force }

if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
    Get-PnpDevice -Class DiskDrive | Where-Object { $_.Status -ne 'OK' } |
        ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }
}

foreach ($store in 'Cert:\LocalMachine\Disallowed','Cert:\CurrentUser\Disallowed') {
    Get-ChildItem $store | Remove-Item -Force
}

Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'AicEnabled' -Force

foreach ($k in @('HKCU:\Console') + (Get-ChildItem 'HKCU:\Console' | ForEach-Object { $_.PSPath })) {
    $sc = (Get-ItemProperty $k -Name 'ScreenColors').ScreenColors
    if ($sc -ne $null -and ($sc -band 0x0F) -eq (($sc -shr 4) -band 0x0F)) {
        Set-ItemProperty $k -Name 'ScreenColors' -Value 7 -Type DWord -Force
    }
}

foreach ($e in @(
    @{ P='HKCU:\Software\Policies\Microsoft\Windows\System'; N='DisableCMD' },
    @{ P='HKLM:\Software\Policies\Microsoft\Windows\System'; N='DisableCMD' },
    @{ P='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; N='DisableRegistryTools' },
    @{ P='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; N='DisableTaskMgr' })) {
    Remove-ItemProperty $e.P -Name $e.N -Force
}
foreach ($base in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') {
    Remove-ItemProperty $base -Name 'DisallowRun' -Force
    Remove-Item (Join-Path $base 'DisallowRun') -Recurse -Force
}

foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Command Processor',
                'HKCU:\SOFTWARE\Microsoft\Command Processor',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Command Processor') {
    Remove-ItemProperty $k -Name 'AutoRun' -Force
}
