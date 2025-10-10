# ===============================================
# Services
# ===============================================
Write-Host "=== Service Status ==="

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


# reg keys

Write-Host "`n=== Registry Settings ==="

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


# event logs

Write-Host "`n=== Event Log Checks ==="


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


# prefetch folder

Write-Host "`n=== Prefetch Folder Scan ==="
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


Write-Host "`nCheck complete." -ForegroundColor Cyan
