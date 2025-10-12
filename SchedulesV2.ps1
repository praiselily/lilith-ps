Start-Sleep -Seconds 1
Write-Host "Optimized by Lily (the BEST sser****)
Credits to nolww for the original scrpit" -ForegroundColor Cyan
Write-Host "Analyzing scheduled tasks for suspicious and unsigned entries..." -ForegroundColor Red
Start-Sleep -Seconds 1

function Test-Signature {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return $sig.Status -eq "Valid"
    }
    catch { 
        return $false 
    }
}

function Get-FullPath {
    param([string]$ExePath)
    if ([string]::IsNullOrWhiteSpace($ExePath)) { return $null }
    
    $ExePath = $ExePath.Trim('"')
    
    if (Test-Path -LiteralPath $ExePath -ErrorAction SilentlyContinue) {
        return $ExePath
    }
    
    if ($ExePath -notmatch '\\') {
        $whereResult = Get-Command $ExePath -ErrorAction SilentlyContinue
        if ($whereResult) {
            return $whereResult.Path
        }
    }
    
    try {
        $expandedPath = [Environment]::ExpandEnvironmentVariables($ExePath)
        if ($expandedPath -ne $ExePath -and (Test-Path -LiteralPath $expandedPath -ErrorAction SilentlyContinue)) {
            return $expandedPath
        }
    }
    catch { }
    
    return $null
}

$suspectPrograms = "cmd.exe", "powershell.exe", "powershell_ise.exe", "rundll32.exe", "regsvr32.exe", "taskmgr.exe", "LaunchTM.exe", "WinRAR.exe"

$allTasks = Get-ScheduledTask
$filteredTasks = @()

foreach ($task in $allTasks) {
    try {
        if ($task.Actions -and $task.Actions.Count -gt 0) {
            foreach ($action in $task.Actions) {
                if ($action.Execute -and $action.Execute.Trim()) {
                    $exeName = [System.IO.Path]::GetFileName($action.Execute.Trim('"'))
                    $exePath = Get-FullPath -ExePath $action.Execute
                    
                    $isSuspicious = $suspectPrograms -contains $exeName
                    $isSigned = "No"
                    
                    if ($exePath -and (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
                        $isSigned = if (Test-Signature -Path $exePath) { "Yes" } else { "No" }
                    } else {
                        $isSigned = "Invalid Path"
                    }
                    
                    if ($isSuspicious -eq "Yes" -or $isSigned -ne "Yes") {
                        $filteredTasks += [PSCustomObject]@{
                            TaskName = $task.TaskName
                            TaskPath = $task.TaskPath  
                            Action = $action.Execute
                            Arguments = $action.Arguments
                            FullPath = $exePath
                            Suspicion = if ($isSuspicious) { "Yes" } else { "No" }
                            Signed = $isSigned
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error processing task: $($task.TaskName)" -ForegroundColor Yellow
    }
}

if ($filteredTasks.Count -gt 0) {
    Write-Host "Found $($filteredTasks.Count) suspicious/unsigned tasks:" -ForegroundColor Yellow
    $filteredTasks | Out-GridView -Title "Suspicious/Unsigned Scheduled Tasks - Review Carefully!" -PassThru
} else {
    Write-Host "No suspicious or unsigned tasks found" -ForegroundColor Green
}

Write-Host "PRESS ENTER TO QUIT" -ForegroundColor White
Read-Host
