Write-Host @"made with love by lily<3
"@ -ForegroundColor Cyan
Write-Host "< Service Status >"

$services = @("SysMain", "PcaSvc", "DPS", "EventLog", "Schedule", "Bam", "Dusmsvc", "Appinfo", "CDPSvc", "DcomLaunch", "PlugPlay", "wsearch")

foreach ($svcName in $services) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        $statusColor = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host ("{0,-15} {1,-40} {2}" -f $svcName, $svc.DisplayName, $svc.Status) -ForegroundColor $statusColor
    } else {
        Write-Host ("{0,-15} {1,-40} {2}" -f $svcName, "Not Found", "Stopped") -ForegroundColor Red
    }
}


Write-Host "`n< Service Start Time >"

foreach ($svcName in $services) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        try {
            $process = Get-WmiObject Win32_Service -Filter "Name='$svcName'" | Select-Object ProcessId
            if ($process.ProcessId -gt 0) {
                $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Host ("{0,-15} {1}" -f $svcName, $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Cyan
                }
            }
        } catch {
            Write-Host ("{0,-15} {1}" -f $svcName, "N/A") -ForegroundColor Yellow
        }
    }
}


Write-Host "`n< System Boot Time >"

try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    Write-Host ("Last Boot: {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Cyan
    Write-Host ("Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Cyan
} catch {
    Write-Host "Unable to retrieve boot time information" -ForegroundColor Red
}


Write-Host "`n< Registry >"

$settings = @(
    @{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "$($s.Name): " -NoNewLine
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host "$($s.Warning)" -ForegroundColor Red
    } else {
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}


Write-Host "`n< Event Log >"

$usnClear = Get-WinEvent -FilterHashtable @{LogName="Application"; Id=3079} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($usnClear) {
    Write-Host "USN Journal Cleared: Yes ($($usnClear.TimeCreated))" -ForegroundColor Yellow
} else {
    Write-Host "USN Journal Cleared: No" -ForegroundColor Green
}

$eventLogClear = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=1102} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($eventLogClear) {
    Write-Host "Event Logs Cleared: Yes ($($eventLogClear.TimeCreated))" -ForegroundColor Yellow
} else {
    Write-Host "Event Logs Cleared: No" -ForegroundColor Green
}


Write-Host "`n< Prefetch >"
$prefetchPath = "$env:SystemRoot\Prefetch"

if (Test-Path $prefetchPath) {
    $prefetchFiles = Get-ChildItem $prefetchPath -File -ErrorAction SilentlyContinue
    $hasHidden = $prefetchFiles | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::Hidden }
    $hasReadOnly = $prefetchFiles | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReadOnly }

    $hiddenResult = if ($hasHidden) { "Yes" } else { "No" }
    $readonlyResult = if ($hasReadOnly) { "Yes" } else { "No" }

    Write-Host "Hidden Files Present: $hiddenResult" -ForegroundColor Yellow
    Write-Host "Read-Only Files Present: $readonlyResult" -ForegroundColor Yellow
} else {
    Write-Host "Prefetch folder not found" -ForegroundColor Red
}


Write-Host "`n< Recycle Bin >"

try {
    
    $recycleBinEvents = Get-WinEvent -FilterHashtable @{LogName="System"; Id=10006} -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($recycleBinEvents) {
        Write-Host "Recycle Bin Last Cleared: $($recycleBinEvents.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
    } else {
        
        $recycleBinPath = "$env:SystemDrive`\$Recycle.Bin"
        if (Test-Path $recycleBinPath) {
            $recycleBinFolders = Get-ChildItem $recycleBinPath -Directory -ErrorAction SilentlyContinue
            if ($recycleBinFolders) {
                $latestMod = $recycleBinFolders | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Host "Recycle Bin Last Modified: $($latestMod.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
            } else {
                Write-Host "Recycle Bin appears empty or inaccessible" -ForegroundColor Green
            }
        } else {
            Write-Host "Recycle Bin path not found" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Unable to access Recycle Bin information" -ForegroundColor Red
}

Write-Host "`nCheck complete." -ForegroundColor Cyan
