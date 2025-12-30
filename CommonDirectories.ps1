Write-Host "`
           w   8          
██████╗  █████╗ ████████╗██╗  ██╗███████╗
██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝
██████╔╝███████║   ██║   ███████║███████╗
██╔═══╝ ██╔══██║   ██║   ██╔══██║╚════██║
██║     ██║  ██║   ██║   ██║  ██║███████║
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝  made with love by lily<3
`n" -ForegroundColor Cyan

$directories = @(
    "$env:windir\System32",
    "$env:windir\SysWOW64", 
    "$env:USERPROFILE\AppData\Local\Temp"
)

$outputDir = "C:\Screenshare"
$outputFile = "$outputDir\paths.txt"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$microsoftRegex = [regex]::new('Microsoft|Windows|Redmond', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$trustedRegex = [regex]::new('NVIDIA|Intel|AMD|Realtek|VIA|Qualcomm', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$knownCheatRegex = [regex]::new('manthe', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)

$knownGoodFiles = @{
    'ntoskrnl.exe' = $true
    'kernel32.dll' = $true
    'user32.dll' = $true
    'advapi32.dll' = $true
    'shell32.dll' = $true
    'explorer.exe' = $true
    'svchost.exe' = $true
    'services.exe' = $true
    'lsass.exe' = $true
    'csrss.exe' = $true
    'winlogon.exe' = $true
    'dwm.exe' = $true
}

$signatureCache = @{}

function Test-ShouldIncludeFile {
    param([System.IO.FileInfo]$FileInfo)
    
    try {
        $fileName = $FileInfo.Name
        
        if ($fileName -like "*.mui") {
            return $false
        }
        
        $extension = $FileInfo.Extension.ToLower()
        
        if ($extension -ne "") {
            $nonExecutableExtensions = @('.evtx', '.etl', '.dat', '.db', '.log', '.log1', '.log2', 
                                          '.regtrans-ms', '.blf', '.cab', '.rtf', '.inf', '.txt',
                                          '.tmp', '.bin', '.bak', '.btx', '.btr', '.wal', '.xml')
            if ($nonExecutableExtensions -contains $extension) {
                return $false
            }
        }

        try {
            $stream = [System.IO.File]::OpenRead($FileInfo.FullName)
            $buffer = New-Object byte[] 2
            $bytesRead = $stream.Read($buffer, 0, 2)
            $stream.Close()
            
            if ($bytesRead -ge 2) {
                if ($buffer[0] -ne 0x4D -or $buffer[1] -ne 0x5A) {
                    return $false
                }
            } else {
                return $false
            }
        }
        catch {
        }

        if ($fileName -match '^(microsoft|windows|ms)') {
            return $false
        }
        
        if ($knownGoodFiles.ContainsKey($fileName.ToLower())) {
            return $false
        }

        try {
            $filePath = $FileInfo.FullName

            if ($signatureCache.ContainsKey($filePath)) {
                return $signatureCache[$filePath]
            }
            
            $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
            
            if ($signature.Status -eq "Valid" -and $signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                
                if ($knownCheatRegex.IsMatch($subject)) {
                    $signatureCache[$filePath] = $true
                    return $true
                }

                if ($microsoftRegex.IsMatch($subject) -or $trustedRegex.IsMatch($subject)) {
                    $signatureCache[$filePath] = $false
                    return $false
                }
            }
        }
        catch {
        }

        try {
            $versionInfo = $FileInfo.VersionInfo
            if ($versionInfo.CompanyName) {
                if ($microsoftRegex.IsMatch($versionInfo.CompanyName) -or $trustedRegex.IsMatch($versionInfo.CompanyName)) {
                    return $false
                }
            }
        }
        catch {
        }
        
        return $true
    }
    catch {
        return $false
    }
}

if (Test-Path $outputFile) {
    Remove-Item $outputFile -Force
}

Write-Host "Scanning for non-Microsoft files" -ForegroundColor Green
Write-Host ""
Write-Host ""
Write-Host "Output: $outputFile`n" -ForegroundColor Cyan

$startTime = Get-Date
$fileCount = 0
$totalFilesChecked = 0

$stringBuilder = [System.Text.StringBuilder]::new()

foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        Write-Host "Directory not found: $directory" -ForegroundColor Red
        continue
    }
    
    Write-Host "Scanning: $directory" -ForegroundColor Yellow
    $dirStartTime = Get-Date
    $dirFileCount = 0
    
    try {
        $files = Get-ChildItem -Path $directory -File -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.Length -ge 300KB }
        
        foreach ($fileInfo in $files) {
            try {
                $totalFilesChecked++

                if ($totalFilesChecked % 500 -eq 0) {
                    Write-Host "  Checked: $totalFilesChecked | Found: $fileCount" -ForegroundColor Gray
                }
                
                if (Test-ShouldIncludeFile -FileInfo $fileInfo) {
                    [void]$stringBuilder.AppendLine($fileInfo.FullName)
                    $fileCount++
                    $dirFileCount++
                }
            }
            catch {
                continue
            }
        }
        
        $dirTime = (Get-Date) - $dirStartTime
        Write-Host "  Found: $dirFileCount files in $([math]::Round($dirTime.TotalSeconds, 1))s" -ForegroundColor Green
    }
    catch {
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

[System.IO.File]::WriteAllText($outputFile, $stringBuilder.ToString(), [System.Text.UTF8Encoding]::new($false))

$totalTime = (Get-Date) - $startTime

Write-Host "`nScan Complete c:" -ForegroundColor Green
Write-Host "Time: $([math]::Round($totalTime.TotalMinutes, 1)) minutes" -ForegroundColor White
Write-Host "Files checked: $totalFilesChecked" -ForegroundColor White
Write-Host "Non-Microsoft files found: $fileCount" -ForegroundColor Cyan
Write-Host "Output: $outputFile`n" -ForegroundColor Cyan

if (Test-Path $outputFile) {
    $lineCount = (Get-Content $outputFile | Measure-Object).Count
    Write-Host "Paths written: $lineCount" -ForegroundColor White
    
    if ($fileCount -gt 0) {
        $samplePaths = Get-Content $outputFile | Select-Object -First 5
        
        Write-Host "`nSample paths:" -ForegroundColor Yellow
        foreach ($path in $samplePaths) {
            if (Test-Path $path) {
                $fileItem = Get-Item $path -ErrorAction SilentlyContinue
                if ($fileItem) {
                    $sizeMB = [math]::Round($fileItem.Length / 1MB, 2)

                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                        if ($sig -and $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match 'manthe')) {
                            Write-Host "  [FLAGGED CHEAT] $path ($sizeMB MB)" -ForegroundColor Red
                        } else {
                            Write-Host "  $path ($sizeMB MB)" -ForegroundColor Green
                        }
                    }
                    catch {
                        Write-Host "  $path ($sizeMB MB)" -ForegroundColor Green
                    }
                }
            }
        }

        $totalSize = 0
        $collectedFiles = Get-Content $outputFile
        foreach ($filePath in $collectedFiles) {
            if (Test-Path $filePath) {
                $fileItem = Get-Item $filePath -ErrorAction SilentlyContinue
                if ($fileItem) {
                    $totalSize += $fileItem.Length
                }
            }
        }
        
        $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
        Write-Host "`nTotal size: $totalSizeMB MB" -ForegroundColor Cyan
    }
} else {
    Write-Host "No files found" -ForegroundColor Yellow
}

Write-Host "`nRun paths parser with YARA rules on '$outputFile'" -ForegroundColor Green
Write-Host "Hit up @praiselily if you find any issues" -ForegroundColor Cyan
