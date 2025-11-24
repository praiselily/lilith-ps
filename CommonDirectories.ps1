Write-Host "`
⠀⠀⠀⠀⣶⣄⠀⠀⠀⠀⠀⠀⢀⣶⡆⠀⠀⠀
⠀⠀⠀⢸⣿⣿⡆⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀
⠀⠀⠀⠘⣿⣿⣿⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢿⣿⣿⣤⣤⣤⣤⣼⣿⡿⠃⠀⠀⠀
⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀
⠀⠀⢠⣿⡃⣦⢹⣿⣟⣙⣿⣿⠰⡀⣿⣇⠀⠀
⠠⠬⣿⣿⣷⣶⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⡭⠤      
⠀⣼⣿⣿⣿⣿⠿⠛⠛⠛⠛⠻⢿⣿⣿⣿⣿⡀
⢰⣿⣿⣿⠋⠀⠀⠀⢀⣀⠀⠀⠀⠉⢿⣿⣿⣧
⢸⣿⣿⠃⠜⠛⠂⠀⠋⠉⠃⠐⠛⠻⠄⢿⣿⣿
⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
⠘⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏
⠀⠈⠻⠿⣤⣀⡀⠀⠀⠀⠀⠀⣀⣠⠾⠟⠋⠀            made with love by lily<3
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

$microsoftKeywords = @(
    "Microsoft", 
    "Windows", 
    "Microsoft Corporation",
    "Windows Publisher",
    "Microsoft Windows"
)

$microsoftPattern = ($microsoftKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|'
$microsoftRegex = [regex]::new($microsoftPattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Test-MicrosoftFile {
    param([System.IO.FileInfo]$FileInfo)
    
    try {
        $fileName = $FileInfo.Name
        if ($fileName -like "*.mui" -or $fileName -like "*Microsoft*" -or $fileName -like "*Windows*") {
            $versionInfo = $FileInfo.VersionInfo
            if ($versionInfo.CompanyName -or $versionInfo.ProductName) {
                if ($microsoftRegex.IsMatch($versionInfo.CompanyName) -or 
                    $microsoftRegex.IsMatch($versionInfo.ProductName)) {
                    return $true
                }
            }
        }
        
        
        try {
            $signature = Get-AuthenticodeSignature -FilePath $FileInfo.FullName -ErrorAction Stop
            if ($signature.Status -eq "Valid" -and $signature.SignerCertificate) {
                if ($microsoftRegex.IsMatch($signature.SignerCertificate.Subject)) {
                    return $true
                }
            }
        }
        catch {
        }
        
        return $false
    }
    catch {
        return $false
    }
}

if (Test-Path $outputFile) {
    Remove-Item $outputFile -Force
}

Write-Host "Scanning directories for large non-Microsoft files" -ForegroundColor Green
Write-Host "This may take up to a minutee" -ForegroundColor Yellow
Write-Host "Output: $outputFile" -ForegroundColor Cyan

$startTime = Get-Date
$fileCount = 0
$totalFilesChecked = 0
$streamWriter = [System.IO.StreamWriter]::new($outputFile, $false, [System.Text.UTF8Encoding]::new($false))
foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        Write-Host "Directory not found: $directory" -ForegroundColor Red
        continue
    }
    
    Write-Host "Processing: $directory" -ForegroundColor Yellow
    $dirStartTime = Get-Date
    $dirFileCount = 0
    
    try {
        $allFiles = [System.IO.Directory]::EnumerateFiles($directory, "*", [System.IO.SearchOption]::AllDirectories)
        
        foreach ($filePath in $allFiles) {
            try {
                $fileInfo = [System.IO.FileInfo]::new($filePath)
                
                if ($fileInfo.Length -lt 1MB) {
                    continue
                }
                
                $totalFilesChecked++
                
                
                if ($totalFilesChecked % 500 -eq 0) {
                    Write-Host "  Processed $totalFilesChecked files" -ForegroundColor Gray
                }
                
                if (-not (Test-MicrosoftFile -FileInfo $fileInfo)) {
                    $streamWriter.WriteLine($fileInfo.FullName)
                    $fileCount++
                    $dirFileCount++
                }
            }
            catch {
                continue
            }
        }
        
        $dirTime = (Get-Date) - $dirStartTime
        Write-Host "  Found $dirFileCount files in $([math]::Round($dirTime.TotalSeconds, 1)) seconds" -ForegroundColor Green
    }
    catch {
        Write-Host "  Error processing directory: $($_.Exception.Message)" -ForegroundColor Red
    }
}
$streamWriter.Close()

$totalTime = (Get-Date) - $startTime

Write-Host "`nScan completed in $([math]::Round($totalTime.TotalMinutes, 1)) minutes!" -ForegroundColor Green
Write-Host "Total files checked: $totalFilesChecked" -ForegroundColor White
Write-Host "Large non-Microsoft files found: $fileCount" -ForegroundColor Green
Write-Host "Output: $outputFile" -ForegroundColor Cyan

if (Test-Path $outputFile) {
    $lineCount = (Get-Content $outputFile | Measure-Object).Count
    Write-Host "Lines in output file: $lineCount" -ForegroundColor White
    
    $validPaths = 0
    $samplePaths = Get-Content $outputFile | Select-Object -First 10
    Write-Host "`nTesting first 10 paths:" -ForegroundColor Yellow
    foreach ($path in $samplePaths) {
        if (Test-Path $path) {
            Write-Host "  VALID: $path" -ForegroundColor Green
            $validPaths++
        } else {
            Write-Host "  INVALID: $path" -ForegroundColor Red
        }
    }
    
    if ($validPaths -eq $samplePaths.Count) {
        Write-Host "All sample paths are valid!??" -ForegroundColor Green
    } else {
        Write-Host "Some paths appear to be invalid. This could be due to:" -ForegroundColor Yellow
        Write-Host "  - Files being deleted after scanning" -ForegroundColor Yellow
        Write-Host "  - Permission issues" -ForegroundColor Yellow
        Write-Host "  - Temporary files that no longer exist" -ForegroundColor Yellow
    }
} else {
    Write-Host "No output file was created." -ForegroundColor Red
}
if ((Test-Path $outputFile) -and $fileCount -gt 0) {
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
    $totalSizeMB = $totalSize / 1MB
    Write-Host "Total size: $([math]::Round($totalSizeMB, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "No files meeting criteria were found." -ForegroundColor Yellow
}

Write-host "Scan the paths with paths parser n verify cheats manually, hit up @praiselily if u find any issues" -ForgroundColor Cyan
