$paths = @(
    "C:\Program Files\Java",
    "C:\Program Files (x86)\Java",
    "$env:USERPROFILE\AppData\.lunarclient",
    "$env:USERPROFILE\AppData\.minecraft", 
    "$env:USERPROFILE\AppData\modrinth\",
    "$env:USERPROFILE\AppData\Roaming\Badlion Client\Data",
    "C:\Windows\System32"   
)
$strings = @(
    "mod_d.classUT",
    "mod_d.class", 
    "net/java/a",
    "net/java/b",
    "net/java/c"
)
$jarMagic = [byte[]](0x50,0x4B,0x03,0x04)
$minSizeKB = 1400

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

function Test-IsJarMagic {
    param([string]$file)
    try {
        $fs = [System.IO.File]::Open($file, 'Open', 'Read')
        $bytes = New-Object byte[] 4
        $fs.Read($bytes, 0, 4) | Out-Null
        $fs.Close()
        return ($bytes -join ",") -eq ($jarMagic -join ",")
    }
    catch { return $false }
}

function Search-FileForStrings {
    param([string]$file, [string[]]$strings)
    try {
        $content = Get-Content $file -Raw -Encoding Byte
        $text = [System.Text.Encoding]::ASCII.GetString($content)
        foreach($s in $strings){
            if ($text.Contains($s)) {
                return $s
            }
        }
    } catch {}
    return $null
}

Write-Host "Looking for Doomsday" -ForegroundColor Yellow
Write-Host "Usually takes less than a minute" -ForegroundColor Gray
Write-Host ""
$results = @()
$currentPath = 0
$processedFiles = @{}  

foreach ($path in $paths) {
    $currentPath++
    $percentComplete = [math]::Round(($currentPath / $paths.Count) * 50)
    
    Write-Progress -Activity "Phase 1: Analyzing system locations" -Status "Processing location $currentPath of $($paths.Count)" -PercentComplete $percentComplete

    if (-not (Test-Path $path)) { 
        continue 
    }

    if ($path -eq "C:\Windows\System32") {
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt ($minSizeKB * 1024) }
    } else {
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt ($minSizeKB * 1024) }
    }

    foreach ($f in $files) {
        
        if ($processedFiles.ContainsKey($f.FullName)) { continue }
        
        $isJar = $false
        $matchedString = $null
        
        if (Test-IsJarMagic $f.FullName) {
            $isJar = $true
            $matchedString = Search-FileForStrings -file $f.FullName -strings $strings
        } else {
            $matchedString = Search-FileForStrings -file $f.FullName -strings $strings
        }
        
        $isDisguisedJar = $isJar -and $f.Extension -ne ".jar"
        
        if ($matchedString) {
            $results += [PSCustomObject]@{
                FileName        = $f.FullName
                Extension       = $f.Extension
                IsActualJAR     = if ($isJar) { "YES" } else { "NO" }
                IsDisguisedJAR  = if ($isDisguisedJar) { "YES" } else { "NO" }
                SuspiciousMatch = $matchedString
                FileSize        = "$([math]::Round($f.Length/1KB, 2)) KB"
                ScanType        = "System Scan"
            }

            $processedFiles[$f.FullName] = $true
        }
    }
}

Write-Progress -Activity "Phase 1: Analyzing system locations" -Completed
Write-Host ""
Write-Host "Phase 2: Scanning user directories" -ForegroundColor Cyan

$extensions = "*.jar"
$path = "C:\Users"
$jsearchResults = @()

$jarFiles = Get-ChildItem -Path $path -Include $extensions -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt ($minSizeKB * 1024) }
$total = $jarFiles.Count

if ($total -gt 0) {
    $i = 0
    $ErrorActionPreference = 'SilentlyContinue'

    $jarFiles | ForEach-Object { 
        $file = $_
        $i++
        $percentComplete = 50 + [math]::Round(($i / $total) * 50)
        
        Write-Progress -Activity "Phase 2: Scanning JAR files" -Status "Processing $i of $total files" -PercentComplete $percentComplete

        if ($processedFiles.ContainsKey($file.FullName)) { return }
        
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach($string in $strings){
                if($content.Contains($string)){
                    $jsearchResults += [PSCustomObject]@{
                        FileName = $file.FullName
                        Extension = $file.Extension
                        IsActualJAR = "YES"
                        IsDisguisedJAR = "NO"
                        SuspiciousMatch = $string
                        FileSize = "$([math]::Round($file.Length/1KB, 2)) KB"
                        ScanType = "JAR Scan"
                    }

                    $processedFiles[$file.FullName] = $true
                    break
                }
            }
        }
    }

    $ErrorActionPreference = 'Continue'
}

Write-Progress -Activity "scanning for .jar files" -Completed


$allFindings = $results + $jsearchResults

if ($allFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "Dooooooooomsday instnaces found: $($allFindings.Count)" -ForegroundColor Red
    Write-Host ""
    
    $allFindings | Format-Table -AutoSize 
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "no instances found" -ForegroundColor Green
    Write-Host "System appears clean, (isn't always the case of course)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Analysis complete" -ForegroundColor Green
