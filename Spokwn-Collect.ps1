<#
    Spokwn Tool Collector
    Downloads most of spoks tools into C:\Screenshare, not all are included but i added the ones i use the most. espouken.exe and bamparser.exe might require you to disable your AV.

    Run via CMD:
    powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass ^
        && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Spokwn-Collect.ps1)
#>

# logging
$BaseDir = "C:\Screenshare"
$LogFile = "$BaseDir\download-log.txt"
New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
$ProgressPreference = 'SilentlyContinue'

Write-Host "=== Spokwn Tool Collector ==="
Write-Host "All tools will be saved in: $BaseDir`n"

# tools
$Tools = @(
    @{ Name="Kernel Live Dump Analyzer Parser"; Url="https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe"; File="KernelLiveDumpTool.exe" },
    @{ Name="BAM Parser"; Url="https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"; File="BAMParser.exe" },
    @{ Name="Paths Parser"; Url="https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"; File="PathsParser.exe" },
    @{ Name="JournalTrace"; Url="https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"; File="JournalTrace.exe" },
    @{ Name="Tool"; Url="https://github.com/spokwn/Tool/releases/download/v1.1.3/espouken.exe"; File="espouken.exe" },
    @{ Name="PcaSvc Executed"; Url="https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe"; File="PcaSvcExecuted.exe" }
)

# download
function Download-Tool {
    param($Name, $Url, $OutPath, $LogPath)

    # Force TLS 1.2 for GitHub HTTPS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Write-Host "`n[+] Downloading $Name..."
        $start = Get-Date
        Invoke-WebRequest -Uri $Url -OutFile $OutPath -ErrorAction Stop
        $elapsed = [math]::Round((New-TimeSpan $start (Get-Date)).TotalSeconds, 1)
        Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - Downloaded: $Name ($elapsed s)"
        Write-Host "    -> Saved to $OutPath"
    }
    catch {
        Write-Warning "Failed to download $Name : $($_.Exception.Message)"
        Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - FAILED: $Name ($Url)"
    }
}

# download2
# Jobs in PS5.1 lose TLS settings, so re-set inside each job
Write-Host "`nStarting downloads in parallel..."
$jobs = @()

foreach ($tool in $Tools) {
    $out = Join-Path $BaseDir $tool.File
    $jobs += Start-Job -InitializationScript {
        # ensure TLS 1.2 inside the job
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } -ScriptBlock {
        param($Name, $Url, $OutPath, $LogPath)

        try {
            Write-Host "`n[+] Downloading $Name..."
            $start = Get-Date
            Invoke-WebRequest -Uri $Url -OutFile $OutPath -ErrorAction Stop
            $elapsed = [math]::Round((New-TimeSpan $start (Get-Date)).TotalSeconds, 1)
            Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - Downloaded: $Name ($elapsed s)"
            Write-Host "    -> Saved to $OutPath"
        }
        catch {
            Write-Warning "Failed to download $Name : $($_.Exception.Message)"
            Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') - FAILED: $Name ($Url)"
        }

    } -ArgumentList $tool.Name, $tool.Url, $out, $LogFile
}


$jobs | Wait-Job | ForEach-Object {
    Receive-Job $_ -ErrorAction SilentlyContinue
    Remove-Job $_
}


if (Select-String -Path $LogFile -Pattern "FAILED" -Quiet) {
    Write-Host "`n⚠️  Some downloads failed. Check log for details:" -ForegroundColor Yellow
} else {
    Write-Host "`n✅  All Spokwn tools downloaded successfully." -ForegroundColor Green
}

Write-Host "Location: $BaseDir"
Write-Host "Log: $LogFile"
