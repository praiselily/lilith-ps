$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script requires administrator privileges. Please run as admin." -ForegroundColor Red
    exit
}

Write-Host "made with love by lily<3" -ForegroundColor Yellow

try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    Write-Host ("Last Boot: {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Green
    Write-Host ("Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Green
} catch {
    Write-Host "Unable to retrieve boot time information" -ForegroundColor Red
}

$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "`nConnected Drives:" -ForegroundColor Cyan
    foreach ($drive in $drives) {
        Write-Host "  $($drive.DeviceID): $($drive.FileSystem)" -ForegroundColor Green
    }
}

Write-Host "`nService Status" -ForegroundColor Cyan

$services = @(
    @{Name = "SysMain"; DisplayName = "SysMain"},
    @{Name = "PcaSvc"; DisplayName = "PcaSvc"},
    @{Name = "DPS"; DisplayName = "DPS"},
    @{Name = "EventLog"; DisplayName = "Windows Event Log"},
    @{Name = "Schedule"; DisplayName = "Task Scheduler"},
    @{Name = "Bam"; DisplayName = "Bam"},
    @{Name = "Dusmsvc"; DisplayName = "Data Usage Service"},
    @{Name = "Appinfo"; DisplayName = "Application Information"},
    @{Name = "CDPSvc"; DisplayName = "Connected Devices Platform Service"},
    @{Name = "DcomLaunch"; DisplayName = "DCOM Server Process Launcher"},
    @{Name = "PlugPlay"; DisplayName = "Plug and Play"},
    @{Name = "wsearch"; DisplayName = "Windows Search"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $statusColor = if ($service.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host ("{0,-15} {1,-35} {2}" -f $svc.Name, $service.DisplayName, $service.Status) -ForegroundColor $statusColor -NoNewline
        
        if ($service.Status -eq "Running") {
            try {
                $process = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" | Select-Object ProcessId
                if ($process.ProcessId -gt 0) {
                    $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host (" | Started: {0}" -f $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Yellow -NoNewline
                    }
                }
            } catch {
                Write-Host " | Start Time: N/A" -ForegroundColor DarkYellow -NoNewline
            }
        }
        Write-Host ""
    } else {
        Write-Host ("{0,-15} {1,-35} {2}" -f $svc.Name, "Not Found", "Stopped") -ForegroundColor Red
    }
}

$settings = @(
    @{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "$($s.Name): " -NoNewline
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host "$($s.Warning)" -ForegroundColor Red
    } else {
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}

function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        $eventTime = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "$message at: " -NoNewline -ForegroundColor White
        Write-Host $eventTime -ForegroundColor Yellow
    } else {
        Write-Host "$message - No records found" -ForegroundColor Green
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        $eventTime = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $eventID = $event.Id
        Write-Host "$message (Event ID: $eventID) at: " -NoNewline -ForegroundColor White
        Write-Host $eventTime -ForegroundColor Yellow
    } else {
        Write-Host "$message - No records found" -ForegroundColor Green
    }
}

function Check-DeviceDeleted {
    try {
        $event = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" -FilterXPath "*[System[EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            $eventTime = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "Device configuration changed at: " -NoNewline -ForegroundColor White
            Write-Host $eventTime -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $event = Get-WinEvent -FilterHashtable @{LogName="System"; ID=225} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            $eventTime = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "Device removed at: " -NoNewline -ForegroundColor White
            Write-Host $eventTime -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $events = Get-WinEvent -LogName "System" | Where-Object {$_.Id -eq 225 -or $_.Id -eq 400} | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($events) {
            $eventTime = $events.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "Last device change at: " -NoNewline -ForegroundColor White
            Write-Host $eventTime -ForegroundColor Yellow
            return
        }
    } catch {}

    Write-Host "Device changes - No records found" -ForegroundColor Green
}

Check-EventLog "Application" 3079 "USN Journal cleared"
Check-RecentEventLog "System" @(104, 1102) "Event Logs cleared"
Check-EventLog "System" 1074 "Last PC Shutdown"
Check-EventLog "Security" 4616 "System time changed"
Check-EventLog "System" 6005 "Event Log Service started"
Check-DeviceDeleted

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    $prefetchFiles = Get-ChildItem $prefetchPath -File -ErrorAction SilentlyContinue
    $hiddenFiles = $prefetchFiles | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::Hidden }
    $readOnlyFiles = $prefetchFiles | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReadOnly }

    Write-Host "`nPrefetch" -ForegroundColor Cyan
    if ($hiddenFiles) {
        Write-Host "Hidden Files: $($hiddenFiles.Count) found" -ForegroundColor Yellow
        foreach ($file in $hiddenFiles) {
            Write-Host "  - $($file.Name)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Hidden Files: None" -ForegroundColor Green
    }

    if ($readOnlyFiles) {
        Write-Host "Read-Only Files: $($readOnlyFiles.Count) found" -ForegroundColor Yellow
        foreach ($file in $readOnlyFiles) {
            Write-Host "  - $($file.Name)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Read-Only Files: None" -ForegroundColor Green
    }
} else {
    Write-Host "`nPrefetch folder not found" -ForegroundColor Red
}

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
                Write-Host "Recycle Bin Last Modified: $($latestMod.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
            } else {
                Write-Host "Recycle Bin appears empty" -ForegroundColor Green
            }
        } else {
            Write-Host "Recycle Bin: No activity found" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "Recycle Bin: Unable to access information" -ForegroundColor Yellow
}

Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "System check complete." -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Cyan
