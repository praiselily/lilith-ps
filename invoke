<#
    Spokwn Tool Collector
    Downloads all Spokwn DFIR utilities into C:\Screenshare

    Run via CMD or PowerShell:
    powershell -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/<YOUR-USER>/<YOUR-REPO>/main/spokwn-collector.ps1 | iex"
#>

# --- Setup ---
$BaseDir = "C:\Screenshare"
$LogFile = "$BaseDir\download-log.txt"
New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
$ProgressPreference = 'SilentlyContinue'   # disables slow progress bar rendering

Write-Host "=== Spokwn Tool Collector ==="
Write-Host "All tools will be saved in: $BaseDir`n"

# --- Tool list ---
$Tools = @(
    @{ Name="Kernel Live Dump Analyzer Parser"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"; File="KernelLiveDumpTool.exe" },
    @{ Name="BAM Parser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"; File="BAMParser.exe" },
    @{ Name="Paths Parser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"; File="PathsParser.exe" },
    @{ Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"; File="JournalTrace.exe" },
    @{ Name="Tool"; Url="https://github.com/spokwn/Tool/releases/latest/download/Tool.exe"; File="Tool.exe" },
    @{ Name="PcaSvc Executed"; Url="https://github.com/spokwn/pcasvc-executed/releases/latest/download/PcaSvc-Executed.exe"; File="PcaSvc-Executed.exe" }
)

# --- Download function ---
function Download-Tool {
    param($Name, $Url, $OutPath)
    try {
        Write-Host "`n[+] Downloading $Name..."
        $start = Get-Date
        Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -ErrorAction Stop
        $elapsed = [math]::Round((New-TimeSpan $start (Get-Date)).TotalSeconds, 1)
        Add-Content -Path $LogFile -Value "$(Get-Date -Format 'u') - Downloaded: $Name ($elapsed s)"
        Write-Host "    -> Saved to $OutPath"
    }
    catch {
        Write-Warning "Failed to download $Name : $($_.Exception.Message)"
        Add-Content -Path $LogFile -Value "$(Get-Date -Format 'u') - FAILED: $Name ($Url)"
    }
}

# --- Parallel downloads ---
Write-Host "`nStarting downloads in parallel..."
$jobs = @()
foreach ($tool in $Tools) {
    $out = Join-Path $BaseDir $tool.File
    $jobs += Start-Job -ScriptBlock ${function:Download-Tool} -ArgumentList $tool.Name, $tool.Url, $out
}

Wait-Job -Job $jobs | Out-Null
Receive-Job -Job $jobs | Out-Null
Remove-Job -Job $jobs

Write-Host "`n✅ All Spokwn tools downloaded successfully."
Write-Host "Location: $BaseDir"
Write-Host "Log: $LogFile"
