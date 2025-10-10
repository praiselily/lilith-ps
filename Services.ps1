$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           ADMINISTRATOR PRIVILEGES REQUIRED       ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!      ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}


Write-Host "`n                    made with love by lily<3" -ForegroundColor Magenta
Write-Host "`n" + "═" * 65 -ForegroundColor DarkCyan

try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    Write-Host "  SYSTEM BOOT TIME" -ForegroundColor Yellow
    Write-Host ("  └─ Last Boot: {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host ("  └─ Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor White
} catch {
    Write-Host "❌ Unable to retrieve boot time information" -ForegroundColor Red
}

$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "`n CONNECTED DRIVES" -ForegroundColor Yellow
    foreach ($drive in $drives) {
        Write-Host ("  └─ {0}: {1}" -f $drive.DeviceID, $drive.FileSystem) -ForegroundColor Green
    }
}

Write-Host "`n🔧 SERVICE STATUS" -ForegroundColor Yellow
Write-Host "─" * 65 -ForegroundColor DarkGray

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
        if ($service.Status -eq "Running") {
            Write-Host ("   {0,-15} {1,-35}" -f $svc.Name, $service.DisplayName) -ForegroundColor Green -NoNewline
            try {
                $process = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" | Select-Object ProcessId
                if ($process.ProcessId -gt 0) {
                    $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host (" │ 🕐 {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Cyan
                    } else {
                        Write-Host (" │ ⏱️  N/A" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor DarkGray
                    }
                }
            } catch {
                Write-Host " │ ⏱️  N/A" -ForegroundColor DarkGray
            }
        } else {
            Write-Host ("  ❌ {0,-15} {1,-35} {2}" -f $svc.Name, $service.DisplayName, $service.Status) -ForegroundColor Red
        }
    } else {
        Write-Host ("  ⚠️  {0,-15} {1,-35} {2}" -f $svc.Name, "Not Found", "Stopped") -ForegroundColor Yellow
    }
}

Write-Host "`n  REGISTRY " -ForegroundColor Yellow
Write-Host "─" * 65 -ForegroundColor DarkGray

$settings = @(
    @{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host " " -NoNewline -ForegroundColor Red
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Warning)" -ForegroundColor Red
    } else {
        Write-Host " " -NoNewline -ForegroundColor Green
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}

function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "    " -NoNewline -ForegroundColor Yellow
        Write-Host "$message at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "   " -NoNewline -ForegroundColor Green
        Write-Host "$message" -ForegroundColor White
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "    " -NoNewline -ForegroundColor Yellow
        Write-Host "$message (ID: $($event.Id)) at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "   " -NoNewline -ForegroundColor Green
        Write-Host "$message" -ForegroundColor White
    }
}

function Check-DeviceDeleted {
    try {
        $event = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" -FilterXPath "*[System[EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            Write-Host "  🔌 " -NoNewline -ForegroundColor Yellow
            Write-Host "Device configuration changed at: " -NoNewline -ForegroundColor White
            Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $event = Get-WinEvent -FilterHashtable @{LogName="System"; ID=225} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            Write-Host "   " -NoNewline -ForegroundColor Yellow
            Write-Host "Device removed at: " -NoNewline -ForegroundColor White
            Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $events = Get-WinEvent -LogName "System" | Where-Object {$_.Id -eq 225 -or $_.Id -eq 400} | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($events) {
            Write-Host "   " -NoNewline -ForegroundColor Yellow
            Write-Host "Last device change at: " -NoNewline -ForegroundColor White
            Write-Host $events.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    Write-Host "   " -NoNewline -ForegroundColor Green
    Write-Host "Device changes" -ForegroundColor White
}

Write-Host "`n EVENT LOGS " -ForegroundColor Yellow
Write-Host "─" * 65 -ForegroundColor DarkGray

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

    Write-Host "`n PREFETCH " -ForegroundColor Yellow
    Write-Host "─" * 65 -ForegroundColor DarkGray

    if ($hiddenFiles) {
        Write-Host "    Hidden Files: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($hiddenFiles.Count) found" -ForegroundColor Red
        foreach ($file in $hiddenFiles) {
            Write-Host ("    └─ {0}" -f $file.Name) -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "   Hidden Files: " -NoNewline -ForegroundColor Green
        Write-Host "None" -ForegroundColor White
    }

    if ($readOnlyFiles) {
        Write-Host "    Read-Only Files: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($readOnlyFiles.Count) found" -ForegroundColor Red
        foreach ($file in $readOnlyFiles) {
            Write-Host ("    └─ {0}" -f $file.Name) -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "   Read-Only Files: " -NoNewline -ForegroundColor Green
        Write-Host "None" -ForegroundColor White
    }
} else {
    Write-Host "`n Prefetch folder not found" -ForegroundColor Red
}

try {
    $recycleBinEvents = Get-WinEvent -FilterHashtable @{LogName="System"; Id=10006} -MaxEvents 1 -ErrorAction SilentlyContinue
    
    Write-Host "`n  RECYCLE BIN" -ForegroundColor Yellow
    Write-Host "─" * 65 -ForegroundColor DarkGray

    if ($recycleBinEvents) {
        Write-Host "    Last Cleared: " -NoNewline -ForegroundColor Yellow
        Write-Host $recycleBinEvents.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Red
    } else {
        $recycleBinPath = "$env:SystemDrive`\$Recycle.Bin"
        if (Test-Path $recycleBinPath) {
            $recycleBinFolders = Get-ChildItem $recycleBinPath -Directory -ErrorAction SilentlyContinue
            if ($recycleBinFolders) {
                $latestMod = $recycleBinFolders | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Host "   Last Modified: " -NoNewline -ForegroundColor Cyan
                Write-Host $latestMod.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor White
            } else {
                Write-Host "   Recycle Bin: " -NoNewline -ForegroundColor Green
                Write-Host "Empty" -ForegroundColor White
            }
        } else {
            Write-Host "    Recycle Bin: " -NoNewline -ForegroundColor Blue
            Write-Host "No activity found" -ForegroundColor White
        }
    }
} catch {
    Write-Host "   Recycle Bin: " -NoNewline -ForegroundColor Red
    Write-Host "Unable to access information" -ForegroundColor White
}

Write-Host "`n" + "█" * 65 -ForegroundColor Cyan
Write-Host "   🎉 SYSTEM CHECK COMPLETE • ALL OPERATIONS FINISHED   " -ForegroundColor Green
Write-Host "█" * 65 -ForegroundColor Cyan
Write-Host "`n"
