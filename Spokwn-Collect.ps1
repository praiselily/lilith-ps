<#
    Spokwn Tool Collector
    Downloads most of spoks tools into C:\Screenshare, not all are included but i added the ones i use the most. espouken.exe, 
    bamparser.exe and prefetchparser,exe might require you to disable your AV.

    Run via CMD:
    powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass ^
        && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Spokwn-Collect.ps1)
#>

$BaseDir = "C:\Screenshare"
$LogFile = "$BaseDir\download-log.txt"
New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
$ProgressPreference = 'SilentlyContinue'

Write-Host "=== Spokwn Tool Collector ==="
Write-Host "All tools will be saved in: $BaseDir`n"

$Tools = @(
    @{ Name="Kernel Live Dump Analyzer Parser"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"; File="KernelLiveDumpTool.exe" },
    @{ Name="BAM Parser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"; File="BAMParser.exe" },
    @{ Name="Paths Parser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"; File="PathsParser.exe" },
    @{ Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"; File="JournalTrace.exe" },
    @{ Name="Tool"; Url="https://github.com/spokwn/Tool/releases/download/v1.1.3/espouken.exe"; File="espouken.exe" },
    @{ Name="PcaSvc Executed"; Url="https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe"; File="PcaSvcExecuted.exe" },
    @{ Name="BAM Deleted Keys"; Url="https://github.com/spokwn/BamDeletedKeys/releases/download/v1.0/BamDeletedKeys.exe"; File="BamDeletedKeys.exe" },
    @{ Name="Prefetch Parser"; Url="https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"; File="PrefetchParser.exe" },
    @{ Name="Activities Cache Parser"; Url="https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe"; File="ActivitiesCacheParser.exe" }
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$jobs = @()
foreach ($tool in $Tools) {
    $jobScript = {
        param($ToolName, $ToolUrl, $OutputPath, $LogPath)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            $start = Get-Date
            Invoke-WebRequest -Uri $ToolUrl -OutFile $OutputPath -ErrorAction Stop
            $elapsed = [math]::Round((New-TimeSpan $start (Get-Date)).TotalSeconds, 1)
            Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - Downloaded: $ToolName ($elapsed s)"
            Write-Host "[+] $ToolName downloaded successfully ($elapsed s)"
        }
        catch {
            Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - FAILED: $ToolName ($ToolUrl)"
            Write-Warning "Failed to download $ToolName"
        }
    }
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $tool.Name, $tool.Url, (Join-Path $BaseDir $tool.File), $LogFile
}

$jobs | Wait-Job | Receive-Job
$jobs | Remove-Job -Force

if (Test-Path $LogFile) {
    if (Select-String -Path $LogFile -Pattern "FAILED" -Quiet) {
        Write-Host "`n  Some downloads failed. Check log for details." -ForegroundColor Yellow
    } else {
        Write-Host "`n  All downloads completed successfully." -ForegroundColor Green
    }
} else {
    Write-Host "`n  No downloads completed." -ForegroundColor Red
}

Write-Host "Location: $BaseDir"
Write-Host "Log: $LogFile"
