Write-Host @"
___       ___  ___       ___  _________  ___  ___     
|\  \     |\  \|\  \     |\  \|\___   ___\\  \|\  \    
\ \  \    \ \  \ \  \    \ \  \|___ \  \_\ \  \\\  \   
 \ \  \    \ \  \ \  \    \ \  \   \ \  \ \ \   __  \  
  \ \  \____\ \  \ \  \____\ \  \   \ \  \ \ \  \ \  \ 
   \ \_______\ \__\ \_______\ \__\   \ \__\ \ \__\ \__\
    \|_______|\|__|\|_______|\|__|    \|__|  \|__|\|__|
"@ -ForegroundColor Cyan 
Write-Host "Made with love by Lily<3" -ForegroundColor Magenta                                                     
Write-Host @"                                                       
    Heads up, some of the tools (BAM Parser and Hayabusa)
    will flag as a virus, they are not. If you wish to 
    install them, toggle your antivirus before execution.
"@ -ForegroundColor Cyan

$DownloadPath = "C:\Screenshare"
if (!(Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
}

function Download-File {
    param([string]$Url, [string]$FileName, [string]$ToolName)
    
    try {
        $outputPath = Join-Path $DownloadPath $FileName
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $outputPath -UserAgent "PowerShell" -UseBasicParsing | Out-Null
        
        if ($FileName -like "*.zip") {
            $extractPath = Join-Path $DownloadPath ($FileName -replace '\.zip$', '')
            Expand-Archive -Path $outputPath -DestinationPath $extractPath -Force | Out-Null
            Remove-Item $outputPath -Force | Out-Null
        }
        return $true
    }
    catch {
        return $false
    }
    finally {
        $ProgressPreference = 'Continue'
    }
}

function Download-Tools {
    param([array]$Tools, [string]$CategoryName)
    
    $successCount = 0
    $jobs = @()
    
    foreach ($tool in $Tools) {
        $scriptBlock = {
            param($Url, $FileName, $ToolName, $DownloadPath)
            try {
                $ProgressPreference = 'SilentlyContinue'
                $outputPath = Join-Path $DownloadPath $FileName
                Invoke-WebRequest -Uri $Url -OutFile $outputPath -UserAgent "PowerShell" -UseBasicParsing | Out-Null
                
                if ($FileName -like "*.zip") {
                    $extractPath = Join-Path $DownloadPath ($FileName -replace '\.zip$', '')
                    Expand-Archive -Path $outputPath -DestinationPath $extractPath -Force | Out-Null
                    Remove-Item $outputPath -Force | Out-Null
                }
                return $true
            }
            catch {
                return $false
            }
            finally {
                $ProgressPreference = 'Continue'
            }
        }
        
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $tool.Url, $tool.File, $tool.Name, $DownloadPath
        $jobs += @{ Job = $job; Name = $tool.Name }
    }
    
    Write-Host "Downloading $CategoryName tools..." -NoNewline
    
    while ($jobs.Job.State -contains "Running") {
        Start-Sleep -Milliseconds 100
    }
    
    foreach ($jobInfo in $jobs) {
        $result = Receive-Job -Job $jobInfo.Job
        Remove-Job -Job $jobInfo.Job -Force | Out-Null
        if ($result) { $successCount++ }
    }
    
    Write-Host " Done" -ForegroundColor Green
    Write-Host "  $successCount/$($Tools.Count) tools downloaded successfully" -ForegroundColor Cyan
}

$spowksucksasscheeks = @(
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

$zimmermanTools = @(
    @{ Name="AmcacheParser"; Url="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"; File="AmcacheParser.zip" },
    @{ Name="AppCompatCacheParser"; Url="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip"; File="AppCompatCacheParser.zip" },
    @{ Name="JumpListExplorer"; Url="https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip"; File="JumpListExplorer.zip" },
    @{ Name="bstrings"; Url="https://download.ericzimmermanstools.com/net9/bstrings.zip"; File="bstrings.zip" },
    @{ Name="PECmd"; Url="https://download.ericzimmermanstools.com/net9/PECmd.zip"; File="PECmd.zip" },
    @{ Name="SrumECmd"; Url="https://download.ericzimmermanstools.com/net9/SrumECmd.zip"; File="SrumECmd.zip" },
    @{ Name="TimelineExplorer"; Url="https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip"; File="TimelineExplorer.zip" }
)

$nirsoftTools = @(
    @{ Name="WinPrefetchView"; Url="https://www.nirsoft.net/utils/winprefetchview-x64.zip"; File="winprefetchview-x64.zip" },
    @{ Name="USBDeview"; Url="https://www.nirsoft.net/utils/usbdeview-x64.zip"; File="usbdeview-x64.zip" },
    @{ Name="NetworkUsageView"; Url="https://www.nirsoft.net/utils/networkusageview-x64.zip"; File="networkusageview-x64.zip" },
    @{ Name="AlternateStreamView"; Url="https://www.nirsoft.net/utils/alternatestreamview-x64.zip"; File="alternatestreamview-x64.zip" },
    @{ Name="UninstallView"; Url="https://www.nirsoft.net/utils/uninstallview-x64.zip"; File="uninstallview-x64.zip" },
    @{ Name="PreviousFilesRecovery"; Url="https://www.nirsoft.net/utils/previousfilesrecovery-x64.zip"; File="previousfilesrecovery-x64.zip" }
)

$otherTools = @(
    @{ Name="System Informer"; Url="https://github.com/winsiderss/si-builds/releases/download/3.2.25297.1516/systeminformer-build-canary-setup.exe"; File="systeminformer-build-canary-setup.exe" },
    @{ Name="Everything Search"; Url="https://www.voidtools.com/Everything-1.4.1.1029.x86-Setup.exe"; File="Everything-1.4.1.1029.x86-Setup.exe" },
    @{ Name="FTK Imager"; Url="https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe"; File="AccessData_FTK_Imager_4.7.1.exe" }
)


$response = Read-Host "`nDo you want to download Spokwn's tools? (Y/N)"
if ($response -match '^[Yy]') {
    Download-Tools -Tools $spowksucksasscheeks -CategoryName "Spokwn's"
} else {
    Write-Host "Skipping" -ForegroundColor Yellow
}

$response = Read-Host "`nDo you want to download Zimmerman's tools? (Y/N)"
if ($response -match '^[Yy]') {
    Download-Tools -Tools $zimmermanTools -CategoryName "Zimmerman's"
    
    $runtimeResponse = Read-Host "`nWould you like to install the .NET Runtime (required for zimmerman) (Y/N)"
    if ($runtimeResponse -match '^[Yy]') {
        Write-Host "Downloading .NET Runtime..." -NoNewline
        $netResult = Download-File -Url "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.306/dotnet-sdk-9.0.306-win-x64.exe" -FileName "dotnet-sdk-9.0.306-win-x64.exe" -ToolName ".NET Runtime"
        Write-Host " Done" -ForegroundColor Green
    } else {
        Write-Host "Skipping" -ForegroundColor Yellow
    }
} else {
    Write-Host "Skipping" -ForegroundColor Yellow
}

$response = Read-Host "`nDo you want to download Nirsoft tools? (Y/N)"
if ($response -match '^[Yy]') {
    Download-Tools -Tools $nirsoftTools -CategoryName "Nirsoft"
} else {
    Write-Host "Skipping" -ForegroundColor Yellow
}

Write-Host "`nNote: hayabusa might flag as a virus (its very safe n open source)" -ForegroundColor Yellow
$response = Read-Host "Do you want to download Hayabusa? (Y/N)"
if ($response -match '^[Yy]') {
    Write-Host "Downloading Hayabusa..." -NoNewline
    $hayabusaResult = Download-File -Url "https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip" -FileName "hayabusa-3.6.0-win-x64.zip" -ToolName "Hayabusa"
    Write-Host " Done" -ForegroundColor Green
} else {
    Write-Host "Skipping" -ForegroundColor Yellow
}

$response = Read-Host "`nDo you want to download other common tools (i couldnt think of a category)? (Y/N)"
if ($response -match '^[Yy]') {
    Download-Tools -Tools $otherTools -CategoryName "Other Common"
} else {
    Write-Host "Skipping" -ForegroundColor Yellow
}

Write-Host "`nhit up @praiselily if u got ideas for tools to add" -ForegroundColor Cyan
Write-Host "Doownloads are located in: $DownloadPath" -ForegroundColor Cyan
