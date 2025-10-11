Write-Host @"
___       ___  ___       ___  _________  ___  ___
|\  \     |\  \|\  \     |\  \|\___   ___\\  \|\  \
\ \  \    \ \  \ \  \    \ \  \|___ \  \_\ \  \\\  \
 \ \  \    \ \  \ \  \    \ \  \   \ \  \ \ \   __  \
  \ \  \____\ \  \ \  \____\ \  \   \ \  \ \ \  \ \  \
   \ \_______\ \__\ \_______\ \__\   \ \__\ \ \__\ \__\
    \|_______|\|__|\|_______|\|__|    \|__|  \|__|\|__|
Made with love by lily <3

                          Drive executions !
"@ -ForegroundColor Cyan

$OutputDirectory = "C:\Screenshare"
$OutputFile = Join-Path $OutputDirectory "output.txt"
$JsonOutputFile = Join-Path $OutputDirectory "results.json"
$Artifacts = @()

$Global:SignatureCache = @{}
$Global:EntropyCache = @{}
$Global:StringScanCache = @{}
$Global:FileHashCache = @{}
$Global:ZoneIdentifierCache = @{}
$LogBuffer = [System.Collections.Generic.List[string]]::new()

$SuspiciousKeywords = @("clicker", "vape", "cheat", "hack", "inject", "bot", "macro", "manthe", "ghost", "spoofer", "aim", "killaura", "keyauth", "velocity", "scaffold", "bhop", "triggerbot", "wallhack", "esp", "norecoil", "autoclicker", "crack", "keygen", "serial", "bypass", "exploit")
$SuspiciousSigners = @("manthe", "cheat", "hack", "inject", "spoofer", "ghost", "crack", "keygen", "serial", "bypass", "exploit")
$SpoofedExtensions = @(".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".wsf", ".cpl", ".com", ".pif")


$HighPriorityFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:TEMP",
    "$env:USERPROFILE\AppData\Local\Temp"
)

if (-not (Test-Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    catch {
        exit 1
    }
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    $LogBuffer.Add($logEntry)
    if ($LogBuffer.Count -gt 50) {
        Add-Content -Path $OutputFile -Value $LogBuffer
        $LogBuffer.Clear()
    }
}

function Flush-LogBuffer {
    if ($LogBuffer.Count -gt 0) {
        Add-Content -Path $OutputFile -Value $LogBuffer
        $LogBuffer.Clear()
    }
}

function Get-FileHashCached {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) { return "N/A" }
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) { return "N/A" }

        if ($Global:FileHashCache.ContainsKey($FilePath)) {
            return $Global:FileHashCache[$FilePath]
        }

        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hash) {
            $Global:FileHashCache[$FilePath] = $hash.Hash
            return $hash.Hash
        }
        return "N/A"
    }
    catch {
        return "N/A"
    }
}

function Get-FileEntropyCached {
    param([string]$FilePath)

    try {
        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        if ($extension -notin @('.exe', '.dll', '.scr', '.sys', '.ps1', '.bat', '.cmd', '.vbs', '.js')) {
            return 0
        }

        if (-not (Test-Path $FilePath)) { return 0 }
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) { return 0 }
        if ($fileInfo.Length -eq 0) { return 0 }

        if ($Global:EntropyCache.ContainsKey($FilePath)) {
            return $Global:EntropyCache[$FilePath]
        }

        $sampleSize = 64KB
        $bytes = @()

        if ($fileInfo.Length -le $sampleSize) {
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        } else {
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..($sampleSize-1)]
        }

        $byteCount = @{}
        foreach ($byte in $bytes) {
            if (-not $byteCount.ContainsKey($byte)) {
                $byteCount[$byte] = 0
            }
            $byteCount[$byte]++
        }

        $entropy = 0.0
        $totalBytes = $bytes.Length

        foreach ($count in $byteCount.Values) {
            $probability = $count / $totalBytes
            $entropy -= $probability * [Math]::Log($probability, 2)
        }

        $entropy = [Math]::Round($entropy, 2)
        $Global:EntropyCache[$FilePath] = $entropy
        return $entropy
    }
    catch {
        return 0
    }
}

function Test-FileStringsCached {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) { return @() }
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) { return @() }
        if ($fileInfo.Length -gt 40MB) { return @() }

        if ($Global:StringScanCache.ContainsKey($FilePath)) {
            return $Global:StringScanCache[$FilePath]
        }

        $suspiciousStrings = @("clicker", "hwid", "aim", "aura", "macro", "vape", "cheat", "inject", "spoofer", "bhop", "trigger", "wallhack", "esp", "norecoil", "autoclicker", "crack", "keygen", "serial", "bypass", "exploit")
        $foundStrings = @()

        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $sampleSize = [Math]::Min($bytes.Length, 32768)
        $content = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $sampleSize)

        foreach ($string in $suspiciousStrings) {
            if ($content -match $string) {
                $foundStrings += "CONTAINS_$($string.ToUpper())"
            }
        }

        $Global:StringScanCache[$FilePath] = $foundStrings
        return $foundStrings
    }
    catch {
        return @()
    }
}

function Get-DigitalSignatureCached {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) { return "File not found" }
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) { return "N/A" }

        if ($Global:SignatureCache.ContainsKey($FilePath)) {
            return $Global:SignatureCache[$FilePath]
        }

        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq "Valid") {
            $signer = $sig.SignerCertificate.Subject

            if ($signer -match "CN=([^,]+)") {
                $commonName = $matches[1]

                foreach ($suspiciousSigner in $SuspiciousSigners) {
                    if ($commonName -match $suspiciousSigner) {
                        $result = "SUSPICIOUS_SIGNER - $commonName"
                        $Global:SignatureCache[$FilePath] = $result
                        return $result
                    }
                }
                $result = "Signed - $commonName"
                $Global:SignatureCache[$FilePath] = $result
                return $result
            }
            $result = "Signed - $signer"
            $Global:SignatureCache[$FilePath] = $result
            return $result
        } else {
            $result = "Unsigned"
            $Global:SignatureCache[$FilePath] = $result
            return $result
        }
    }
    catch {
        $result = "Unsigned"
        $Global:SignatureCache[$FilePath] = $result
        return $result
    }
}

function Get-ZoneIdentifier {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) { return "N/A" }

        if ($Global:ZoneIdentifierCache.ContainsKey($FilePath)) {
            return $Global:ZoneIdentifierCache[$FilePath]
        }

        $zoneInfo = Get-Item -Path $FilePath -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
        if ($zoneInfo) {
            $result = "Internet_Download"
            $Global:ZoneIdentifierCache[$FilePath] = $result
            return $result
        }

        $result = "Local_File"
        $Global:ZoneIdentifierCache[$FilePath] = $result
        return $result
    }
    catch {
        return "N/A"
    }
}

function Get-SuspiciousPriority {
    param([string]$SuspiciousActivity, [string]$FileName)

    $priority = 0

    if ($SuspiciousActivity -match "SUSPICIOUS_KEYWORD_") { $priority += 1000 }
    if ($SuspiciousActivity -match "SPOOFED_EXTENSION_") { $priority += 600 }
    if ($SuspiciousActivity -match "SUSPICIOUS_SIGNER") { $priority += 1200 }
    if ($SuspiciousActivity -match "HIGH_ENTROPY") { $priority += 400 }
    if ($SuspiciousActivity -match "CONTAINS_") { $priority += 500 }
    if ($SuspiciousActivity -match "Internet_Download") { $priority += 300 }
    if ($SuspiciousActivity -match "DOUBLE_EXTENSION") { $priority += 800 }
    if ($SuspiciousActivity -ne "N/A") { $priority += 100 }

    return $priority
}

function Test-DoubleExtension {
    param([string]$FileName)

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $firstExtension = [System.IO.Path]::GetExtension($baseName)
    $lastExtension = [System.IO.Path]::GetExtension($FileName)

    if ($firstExtension -ne "" -and $lastExtension -in @('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js')) {
        return $true
    }
    return $false
}

function Evaluate-FileSuspicion {
    param(
        [string]$FilePath,
        [string]$Source,
        [string]$ArtifactFile = "N/A",
        [datetime]$Timestamp = (Get-Date),
        [string]$USNReason = "N/A",
        [string]$RawReason = "N/A"
    )

    try {
        $normalizedPath = $FilePath.ToLower().Replace('/', '\')
        if (-not (Test-Path $normalizedPath)) {
            return $null
        }

        $fileInfo = Get-Item $normalizedPath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) {
            return $null
        }

        $fileName = $fileInfo.Name
        $suspiciousReasons = @()

        
        foreach ($keyword in $SuspiciousKeywords) {
            if ($fileName -match [regex]::Escape($keyword)) {
                $suspiciousReasons += "SUSPICIOUS_KEYWORD_$($keyword.ToUpper())"
            }
        }

        if ($Source -eq "BAM") {
            $extension = [System.IO.Path]::GetExtension($normalizedPath).ToLower()
            if ($extension -in $SpoofedExtensions) {
                $suspiciousReasons += "SPOOFED_EXTENSION_$($extension.ToUpper().Replace('.',''))"
            }
        }

        if (Test-DoubleExtension -FileName $fileName) {
            $suspiciousReasons += "DOUBLE_EXTENSION"
        }

        $extension = [System.IO.Path]::GetExtension($normalizedPath).ToLower()
        if ($extension -in @('.exe', '.dll', '.scr', '.sys', '.ps1', '.bat', '.cmd', '.vbs', '.js')) {
            
            $entropy = Get-FileEntropyCached -FilePath $normalizedPath
            if ($entropy -gt 7.0) {  
                $suspiciousReasons += "HIGH_ENTROPY_$entropy"
            }

            $suspiciousStrings = Test-FileStringsCached -FilePath $normalizedPath
            if ($suspiciousStrings.Count -gt 0) {
                $suspiciousReasons += $suspiciousStrings
            }

            $zoneInfo = Get-ZoneIdentifier -FilePath $normalizedPath
            if ($zoneInfo -eq "Internet_Download") {
                $suspiciousReasons += "INTERNET_DOWNLOAD"
            }
        }

        
        $signature = Get-DigitalSignatureCached -FilePath $normalizedPath
        $fileHash = Get-FileHashCached -FilePath $normalizedPath

        
        if ($signature -match "Unsigned") {
            $entropy = Get-FileEntropyCached -FilePath $normalizedPath
            if ($entropy -gt 6.8) {  
                $suspiciousReasons += "UNSIGNED_HIGH_ENTROPY_$entropy"
            }
        }

        if ($suspiciousReasons.Count -gt 0 -or $signature -match "SUSPICIOUS_SIGNER") {
            $priority = Get-SuspiciousPriority -SuspiciousActivity ($suspiciousReasons -join " | ") -FileName $fileName
            $confidence = if ($suspiciousReasons.Count -gt 3 -or $priority -gt 1500) { "HIGH" } elseif ($suspiciousReasons.Count -gt 1 -or $priority -gt 800) { "MEDIUM" } else { "LOW" }

            return [PSCustomObject]@{
                Source = $Source
                FullPath = $normalizedPath
                Timestamp = $Timestamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                FileExists = $true
                Signature = $signature
                SHA256 = $fileHash
                ArtifactFile = $ArtifactFile
                SuspiciousActivity = if ($suspiciousReasons.Count -gt 0) { ($suspiciousReasons -join " | ") } else { "N/A" }
                USNReason = $USNReason
                RawReason = $RawReason
                Priority = $priority
                Confidence = $confidence
            }
        }
    }
    catch {
        return $null
    }
    return $null
}


function Get-PrefetchFiles {
    Write-Log "Scanning Prefetch files for suspicious keywords..."
    $results = @()

    try {
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
            
            Write-Log "Checking $($prefetchFiles.Count) prefetch files for suspicious keywords"
            
            foreach ($pf in $prefetchFiles) {
                $exeName = $pf.Name.Split('-')[0]  
                
                
                foreach ($keyword in $SuspiciousKeywords) {
                    if ($exeName -match [regex]::Escape($keyword)) {
                        Write-Log "SUSPICIOUS PREFETCH: $($pf.Name) contains keyword: $keyword"
                        
                        
                        $result = [PSCustomObject]@{
                            Source = "Prefetch"
                            FullPath = $pf.FullName
                            Timestamp = $pf.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                            FileExists = $true
                            Signature = "N/A"
                            SHA256 = Get-FileHashCached -FilePath $pf.FullName
                            ArtifactFile = "Prefetch"
                            SuspiciousActivity = "SUSPICIOUS_PREFETCH_$($keyword.ToUpper())"
                            USNReason = "N/A"
                            RawReason = "N/A"
                            Priority = 900
                            Confidence = "MEDIUM"
                        }
                        $results += $result
                        break  
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error accessing prefetch directory - $($_.Exception.Message)"
    }

    Write-Log "Prefetch keyword scan completed - $($results.Count) suspicious prefetch files found"
    return $results
}


function Get-BAMEntries {
    Write-Log "Scanning BAM entries with enhanced detection..."
    $results = @()

    $bamPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
    )

    foreach ($bamPath in $bamPaths) {
        if (Test-Path $bamPath) {
            try {
                $users = Get-ChildItem -Path $bamPath -ErrorAction SilentlyContinue
                Write-Log "Found $($users.Count) users in BAM registry at $bamPath"
                
                foreach ($user in $users) {
                    $userSid = $user.PSChildName
                    $userPath = Join-Path $bamPath $userSid
                    Write-Log "Scanning BAM for user SID - $userSid"
                    
                    $entries = Get-ChildItem -Path $userPath -ErrorAction SilentlyContinue

                    foreach ($entry in $entries) {
                        try {
                            $entryValue = Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue
                            if ($entryValue) {
                                
                                $propertyNames = $entryValue.PSObject.Properties | Where-Object {
                                    $_.Name -notlike "PS*" -and $_.Name -ne "Path"
                                }

                                foreach ($prop in $propertyNames) {
                                    $data = $prop.Value
                                    $filePaths = @()
                                    
                                    
                                    if ($data -is [byte[]]) {
                                        
                                        $asciiString = [System.Text.Encoding]::ASCII.GetString($data)
                                        $filePaths += [regex]::Matches($asciiString, "[a-zA-Z]:\\[^\x00]+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)") | ForEach-Object { $_.Value }
                                    }
                                    elseif ($data -is [string]) {
                                        # Direct string might contain path
                                        if ($data -match "[a-zA-Z]:\\[^\x00]+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)") {
                                            $filePaths += $matches[0]
                                        }
                                    }
                                    
                                    # Process found file paths
                                    foreach ($filePath in $filePaths) {
                                        if ($filePath -and (Test-Path $filePath)) {
                                            $file = Get-Item $filePath -ErrorAction SilentlyContinue
                                            if ($file -and -not ($file -is [System.IO.DirectoryInfo])) {
                                                $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "BAM" -ArtifactFile $entry.PSPath -Timestamp $file.LastWriteTime
                                                if ($result) { 
                                                    $results += $result
                                                    Write-Log "BAM found suspicious - $filePath"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Log "Error processing BAM entry $($entry.Name) - $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error accessing BAM registry path $bamPath - $($_.Exception.Message)"
            }
        }
    }

    Write-Log "BAM scan completed - $($results.Count) suspicious entries found"
    return $results
}

# IMPROVED ShimCache scanning
function Get-ShimCacheEntries {
    Write-Log "Scanning ShimCache entries with improved parsing..."
    $results = @()

    try {
        $shimCachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        if (Test-Path $shimCachePath) {
            Write-Log "Accessing ShimCache registry..."
            
            # Try multiple property names that might contain the cache data
            $propertyNames = @("AppCompatCache", "AppCompatCache256", "AppCompatCache1024")
            
            foreach ($propName in $propertyNames) {
                try {
                    $cacheData = Get-ItemProperty -Path $shimCachePath -Name $propName -ErrorAction SilentlyContinue
                    if ($cacheData -and $cacheData.$propName -is [byte[]]) {
                        Write-Log "Found ShimCache data in property - $propName"
                        $binaryData = $cacheData.$propName
                        $asciiContent = [System.Text.Encoding]::ASCII.GetString($binaryData)
                        
                        # Multiple patterns to catch different path formats
                        $patterns = @(
                            "[a-zA-Z]:\\[^\x00]{10,}\.(exe|dll|scr)",
                            "\\Device\\HarddiskVolume[^\\]+\\[^\x00]+\.(exe|dll|scr)",
                            "[a-zA-Z]:\\Windows[^\x00]*\.(exe|dll|scr)",
                            "[a-zA-Z]:\\Program[^\x00]*\.(exe|dll|scr)"
                        )
                        
                        foreach ($pattern in $patterns) {
                            $paths = [regex]::Matches($asciiContent, $pattern) | ForEach-Object { $_.Value } | Select-Object -Unique
                            foreach ($filePath in $paths) {
                                # Convert device path if needed
                                if ($filePath -match "^\\Device\\HarddiskVolume") {
                                    # Simple conversion - replace with C: for common case
                                    $filePath = $filePath -replace "^\\Device\\HarddiskVolume[0-9]+\\", "C:\"
                                }
                                
                                if ($filePath -and (Test-Path $filePath)) {
                                    $file = Get-Item $filePath -ErrorAction SilentlyContinue
                                    if ($file -and -not ($file -is [System.IO.DirectoryInfo])) {
                                        $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "ShimCache" -ArtifactFile $shimCachePath -Timestamp $file.LastWriteTime
                                        if ($result) { 
                                            $results += $result
                                            Write-Log "ShimCache found - $filePath"
                                        }
                                    }
                                }
                            }
                        }
                        break  # Found working property, no need to check others
                    }
                }
                catch {
                    Write-Log "Error reading ShimCache property $propName - $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Log "Error accessing ShimCache - $($_.Exception.Message)"
    }

    Write-Log "ShimCache scan completed - $($results.Count) entries found"
    return $results
}

# IMPROVED AmCache scanning
function Get-AmCacheEntries {
    Write-Log "Scanning AmCache entries with alternative methods..."
    $results = @()

    try {
        # Try multiple AmCache locations
        $amCachePaths = @(
            "$env:SystemRoot\AppCompat\Programs\Amcache.hve",
            "HKLM:\System\AppCompat\Programs\Amcache.hve"
        )
        
        foreach ($amCachePath in $amCachePaths) {
            if (Test-Path $amCachePath) {
                Write-Log "Found AmCache at - $amCachePath"
                
                try {
                    # Method 1: Direct registry query
                    $tempFile = Join-Path $env:TEMP "amcache_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                    & reg.exe export "HKLM\System\AppCompat\Programs\Amcache.hve" "$tempFile" /y 2>$null
                    
                    if (Test-Path $tempFile) {
                        Write-Log "Processing exported AmCache data..."
                        $amCacheContent = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
                        if ($amCacheContent) {
                            # Look for executable paths in the exported data
                            $paths = [regex]::Matches($amCacheContent, "[a-zA-Z]:\\[^\x00\r\n]{10,}\.(exe|dll|scr)") | ForEach-Object { $_.Value } | Select-Object -Unique
                            
                            foreach ($filePath in $paths) {
                                if (Test-Path $filePath) {
                                    $file = Get-Item $filePath -ErrorAction SilentlyContinue
                                    if ($file -and -not ($file -is [System.IO.DirectoryInfo])) {
                                        $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "AmCache" -ArtifactFile $amCachePath -Timestamp $file.LastWriteTime
                                        if ($result) { 
                                            $results += $result
                                            Write-Log "AmCache found - $filePath"
                                        }
                                    }
                                }
                            }
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-Log "Error processing AmCache file $amCachePath - $($_.Exception.Message)"
                }
            }
        }
        
        # Alternative: Check recent file executions from other sources
        Write-Log "Checking for additional execution artifacts..."
        
        # Check UserAssist for recent executions
        $userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $userAssistPath) {
            try {
                $userAssistKeys = Get-ChildItem -Path $userAssistPath -Recurse -ErrorAction SilentlyContinue
                foreach ($key in $userAssistKeys) {
                    $keyValues = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    if ($keyValues) {
                        $keyValues.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                            if ($_.Value -is [byte[]]) {
                                $content = [System.Text.Encoding]::Unicode.GetString($_.Value)
                                if ($content -match "[a-zA-Z]:\\[^\x00]{10,}\.(exe|dll|scr)") {
                                    $filePath = $matches[0]
                                    if (Test-Path $filePath) {
                                        $result = Evaluate-FileSuspicion -FilePath $filePath -Source "UserAssist" -ArtifactFile $key.PSPath -Timestamp (Get-Date)
                                        if ($result) { $results += $result }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "Error reading UserAssist - $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "Error accessing AmCache - $($_.Exception.Message)"
    }

    Write-Log "AmCache scan completed - $($results.Count) entries found"
    return $results
}

# IMPROVED Event Log scanning with Sysmon workarounds
function Get-EventLogExecutions {
    Write-Log "Scanning Event Logs for process executions with enhanced error handling..."
    $results = @()

    $startTime = (Get-Date).AddDays(-30)

    # Security Event Log (4688 - Process Creation)
    try {
        Write-Log "Scanning Security event log for process creations..."
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$startTime} -MaxEvents 500 -ErrorAction SilentlyContinue
        
        foreach ($event in $events) {
            try {
                $message = $event.Message
                if ($message -match 'New Process Name:\s*(.*\.exe)') {
                    $exePath = $matches[1].Trim()
                    if (Test-Path $exePath) {
                        $result = Evaluate-FileSuspicion -FilePath $exePath -Source "EventLog_4688" -ArtifactFile "Security_Log" -Timestamp $event.TimeCreated
                        if ($result) { $results += $result }
                    }
                }
            }
            catch {
                # Skip individual event errors
                continue
            }
        }
        Write-Log "Security event log scan completed - $($events.Count) events processed"
    }
    catch {
        Write-Log "Error accessing Security event log - $($_.Exception.Message)"
    }

    # Sysmon Event Log with multiple fallback methods
    try {
        Write-Log "Attempting to access Sysmon event logs..."
        
        # Method 1: Try different Sysmon log names
        $sysmonLogNames = @('Microsoft-Windows-Sysmon/Operational', 'Sysmon', 'SysmonOperational')
        
        foreach ($logName in $sysmonLogNames) {
            try {
                Write-Log "Trying Sysmon log - $logName"
                $sysmonEvents = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 200 -ErrorAction SilentlyContinue
                
                if ($sysmonEvents) {
                    Write-Log "Successfully accessed Sysmon log - $logName - Found $($sysmonEvents.Count) events"
                    
                    foreach ($event in $sysmonEvents) {
                        try {
                            $eventXml = [xml]$event.ToXml()
                            $imageNode = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }
                            if ($imageNode -and $imageNode.'#text') {
                                $exePath = $imageNode.'#text'
                                if (Test-Path $exePath) {
                                    $result = Evaluate-FileSuspicion -FilePath $exePath -Source "Sysmon_1" -ArtifactFile "Sysmon_Log" -Timestamp $event.TimeCreated
                                    if ($result) { $results += $result }
                                }
                            }
                        }
                        catch {
                            continue
                        }
                    }
                    break  # Found working log, exit loop
                }
            }
            catch {
                Write-Log "Failed to access Sysmon log $logName - $($_.Exception.Message)"
            }
        }

        # Method 2: Try WMI event query as fallback
        if ($results.Count -eq 0) {
            Write-Log "Trying WMI event query as fallback..."
            try {
                $processEvents = Get-WmiObject -Query "SELECT * FROM Win32_ProcessStartTrace WHERE TimeCreated > '$((Get-Date).AddDays(-1).ToString('yyyyMMddHHmmss.ffffff-000'))'" -ErrorAction SilentlyContinue
                foreach ($event in $processEvents) {
                    if ($event.ProcessName -and (Test-Path $event.ProcessName)) {
                        $result = Evaluate-FileSuspicion -FilePath $event.ProcessName -Source "WMI_ProcessStart" -ArtifactFile "WMI_Events" -Timestamp (Get-Date)
                        if ($result) { $results += $result }
                    }
                }
            }
            catch {
                Write-Log "WMI event query also failed - $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "All Sysmon access methods failed - $($_.Exception.Message)"
    }

    # Application and System logs for suspicious entries
    try {
        Write-Log "Checking Application and System logs for suspicious entries..."
        $logNames = @('Application', 'System')
        
        foreach ($logName in $logNames) {
            try {
                $suspiciousEvents = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.Message -match ($SuspiciousKeywords -join '|') }
                
                foreach ($event in $suspiciousEvents) {
                    Write-Log "Suspicious event in $logName log - $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))"
                }
            }
            catch {
                Write-Log "Error accessing $logName log - $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "Error checking application/system logs - $($_.Exception.Message)"
    }

    Write-Log "Event log scan completed - $($results.Count) process executions found"
    return $results
}

# COMPREHENSIVE folder scanning with enhanced signature checking
function Get-RecentExecutions {
    Write-Log "Comprehensive scan of target folders with enhanced detection..."
    $results = @()

    foreach ($folder in $HighPriorityFolders) {
        if (Test-Path $folder) {
            try {
                Write-Log "Scanning all executable files in - $folder"
                
                # Scan all executable file types
                $fileTypes = @("*.exe", "*.dll", "*.scr", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.msi", "*.com", "*.pif")
                $allFiles = @()
                
                foreach ($fileType in $fileTypes) {
                    $files = Get-ChildItem -Path $folder -Recurse -Filter $fileType -File -ErrorAction SilentlyContinue
                    $allFiles += $files
                }
                
                Write-Log "Found $($allFiles.Count) files in $folder"

                # Process each file with enhanced checks
                foreach ($file in $allFiles) {
                    # Enhanced signature checking
                    $signature = Get-DigitalSignatureCached -FilePath $file.FullName
                    
                    # Enhanced entropy checking for all files
                    $entropy = Get-FileEntropyCached -FilePath $file.FullName
                    
                    $suspiciousReasons = @()
                    
                    # Check for suspicious keywords in filename
                    foreach ($keyword in $SuspiciousKeywords) {
                        if ($file.Name -match [regex]::Escape($keyword)) {
                            $suspiciousReasons += "SUSPICIOUS_KEYWORD_$($keyword.ToUpper())"
                        }
                    }
                    
                    # Enhanced entropy checks
                    if ($entropy -gt 6.8) {
                        $suspiciousReasons += "HIGH_ENTROPY_$entropy"
                    }
                    
                    # Check for unsigned files with high entropy
                    if ($signature -match "Unsigned" -and $entropy -gt 6.5) {
                        $suspiciousReasons += "UNSIGNED_HIGH_ENTROPY_$entropy"
                    }
                    
                    # Check file extension spoofing
                    $extension = [System.IO.Path]::GetExtension($file.FullName).ToLower()
                    if ($extension -in $SpoofedExtensions) {
                        $suspiciousReasons += "SPOOFED_EXTENSION_$($extension.ToUpper().Replace('.',''))"
                    }
                    
                    if ($suspiciousReasons.Count -gt 0 -or $signature -match "SUSPICIOUS_SIGNER") {
                        $priority = Get-SuspiciousPriority -SuspiciousActivity ($suspiciousReasons -join " | ") -FileName $file.Name
                        $confidence = if ($suspiciousReasons.Count -gt 3 -or $priority -gt 1500) { "HIGH" } elseif ($suspiciousReasons.Count -gt 1 -or $priority -gt 800) { "MEDIUM" } else { "LOW" }

                        $result = [PSCustomObject]@{
                            Source = "Folder_Scan"
                            FullPath = $file.FullName.ToLower()
                            Timestamp = $file.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                            FileExists = $true
                            Signature = $signature
                            SHA256 = Get-FileHashCached -FilePath $file.FullName
                            ArtifactFile = $folder
                            SuspiciousActivity = if ($suspiciousReasons.Count -gt 0) { ($suspiciousReasons -join " | ") } else { "N/A" }
                            USNReason = "N/A"
                            RawReason = "N/A"
                            Priority = $priority
                            Confidence = $confidence
                        }
                        $results += $result
                    }
                }
            }
            catch {
                Write-Log "Error scanning folder $folder - $($_.Exception.Message)"
            }
        }
    }

    return $results
}

# FAST LNK file scanning - only 10 most recent
function Get-RecentLNKFiles {
    Write-Log "Scanning 10 most recent LNK files..."
    $results = @()

    try {
        $lnkPaths = @(
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent",
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent"
        )

        foreach ($lnkPath in $lnkPaths) {
            if (Test-Path $lnkPath) {
                # Get only the 10 most recent LNK files
                $lnkFiles = Get-ChildItem -Path $lnkPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue | 
                           Sort-Object LastWriteTime -Descending | 
                           Select-Object -First 10
                
                Write-Log "Found $($lnkFiles.Count) LNK files in $lnkPath"
                
                foreach ($lnk in $lnkFiles) {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($lnk.FullName)
                        $targetPath = $shortcut.TargetPath
                        
                        if ($targetPath -and (Test-Path $targetPath)) {
                            $file = Get-Item $targetPath -ErrorAction SilentlyContinue
                            if ($file -and -not ($file -is [System.IO.DirectoryInfo])) {
                                $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "LNK_File" -ArtifactFile $lnk.FullName -Timestamp $lnk.LastWriteTime
                                if ($result) { $results += $result }
                            }
                        }
                    }
                    catch {
                        # Skip problematic LNK files
                        continue
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error scanning LNK files - $($_.Exception.Message)"
    }

    Write-Log "LNK files scan completed - $($results.Count) entries found"
    return $results
}

function Export-Results {
    param(
        [array]$Results,
        [string]$OutputPath
    )

    $separator = "=" * 80
    Add-Content -Path $OutputPath -Value "COMPREHENSIVE EXECUTION ANALYSIS REPORT"
    Add-Content -Path $OutputPath -Value "Generated: $(Get-Date)"
    Add-Content -Path $OutputPath -Value "Scan Target: Enhanced detection with focus on BAM, ShimCache, AmCache"
    Add-Content -Path $OutputPath -Value $separator

    $header = "Source`tFullPath`tTimestamp`tFileExists`tSignature`tSHA256`tArtifactFile`tSuspiciousActivity`tUSNReason`tRawReason`tPriority`tConfidence"
    Add-Content -Path $OutputPath -Value $header

    foreach ($result in $Results) {
        $line = "$($result.Source)`t$($result.FullPath)`t$($result.Timestamp)`t$($result.FileExists)`t$($result.Signature)`t$($result.SHA256)`t$($result.ArtifactFile)`t$($result.SuspiciousActivity)`t$($result.USNReason)`t$($result.RawReason)`t$($result.Priority)`t$($result.Confidence)"
        Add-Content -Path $OutputPath -Value $line
    }
}

function Export-JsonResults {
    param(
        [array]$Results,
        [string]$OutputPath
    )

    $jsonResults = @()
    foreach ($result in $Results) {
        $jsonResults += @{
            Source = $result.Source
            FullPath = $result.FullPath
            Timestamp = $result.Timestamp
            FileExists = $result.FileExists
            Signature = $result.Signature
            SHA256 = $result.SHA256
            ArtifactFile = $result.ArtifactFile
            SuspiciousActivity = $result.SuspiciousActivity
            USNReason = $result.USNReason
            RawReason = $result.RawReason
            Priority = $result.Priority
            Confidence = $result.Confidence
        }
    }

    $jsonResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Show-ResultsGUI {
    param([array]$Results)

    try {
        if ([Environment]::UserInteractive -eq $false) {
            Write-Log "Non-interactive session detected - skipping GUI"
            return
        }

        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop

        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Enhanced Execution Analysis Results"
        $form.Size = New-Object System.Drawing.Size(1200, 600)
        $form.StartPosition = "CenterScreen"
        $form.MaximizeBox = $true
        $form.MinimizeBox = $true

        $dataGridView = New-Object System.Windows.Forms.DataGridView
        $dataGridView.Location = New-Object System.Drawing.Point(10, 40)
        $dataGridView.Size = New-Object System.Drawing.Size(1160, 450)
        $dataGridView.AutoSizeColumnsMode = "Fill"
        $dataGridView.SelectionMode = "FullRowSelect"
        $dataGridView.ReadOnly = $true
        $dataGridView.AllowUserToAddRows = $false
        $dataGridView.AllowUserToDeleteRows = $false
        $dataGridView.RowHeadersVisible = $false
        $dataGridView.AllowUserToResizeRows = $false

        $columns = @(
            @{Name="Source"; HeaderText="Source"; Width=100},
            @{Name="FullPath"; HeaderText="File Path"; Width=250},
            @{Name="Timestamp"; HeaderText="Timestamp"; Width=120},
            @{Name="Signature"; HeaderText="Signature"; Width=150},
            @{Name="SuspiciousActivity"; HeaderText="Suspicious Activity"; Width=200},
            @{Name="Priority"; HeaderText="Priority"; Width=70},
            @{Name="Confidence"; HeaderText="Confidence"; Width=80}
        )

        foreach ($column in $columns) {
            $dataGridView.Columns.Add($column.Name, $column.HeaderText) | Out-Null
            if ($column.Width) {
                $dataGridView.Columns[$column.Name].Width = $column.Width
            }
        }

        $sortedResults = $Results | Sort-Object Priority -Descending | Select-Object Source, FullPath, Timestamp, Signature, SuspiciousActivity, Priority, Confidence
        
        foreach ($item in $sortedResults) {
            $dataGridView.Rows.Add($item.Source, $item.FullPath, $item.Timestamp, $item.Signature, $item.SuspiciousActivity, $item.Priority, $item.Confidence) | Out-Null
        }

        $dataGridView.Add_CellFormatting({
            param($sender, $e)
            
            if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) {
                $row = $dataGridView.Rows[$e.RowIndex]
                $confidence = $row.Cells["Confidence"].Value
                $suspiciousActivity = $row.Cells["SuspiciousActivity"].Value
                $signature = $row.Cells["Signature"].Value
                
                if ($confidence -eq "HIGH") {
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightCoral
                } elseif ($confidence -eq "MEDIUM") {
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightYellow
                }
                
                if ($e.ColumnIndex -eq 4 -and $suspiciousActivity -ne "N/A") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::OrangeRed
                    $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                }
                
                if ($e.ColumnIndex -eq 3 -and $signature -match "SUSPICIOUS_SIGNER") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::DarkRed
                    $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                } elseif ($e.ColumnIndex -eq 3 -and $signature -match "Unsigned") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::LightPink
                }
            }
        })

        $filterLabel = New-Object System.Windows.Forms.Label
        $filterLabel.Location = New-Object System.Drawing.Point(10, 15)
        $filterLabel.Size = New-Object System.Drawing.Size(100, 20)
        $filterLabel.Text = "Filter:"

        $filterTextBox = New-Object System.Windows.Forms.TextBox
        $filterTextBox.Location = New-Object System.Drawing.Point(50, 12)
        $filterTextBox.Size = New-Object System.Drawing.Size(200, 20)
        $filterTextBox.Add_TextChanged({
            $filter = $filterTextBox.Text.ToLower()
            foreach ($row in $dataGridView.Rows) {
                $visible = $false
                if ($row.Cells["FullPath"].Value -match $filter -or 
                    $row.Cells["Source"].Value -match $filter -or 
                    $row.Cells["SuspiciousActivity"].Value -match $filter -or
                    $row.Cells["Signature"].Value -match $filter) {
                    $visible = $true
                }
                $row.Visible = $visible
            }
        })

        $summaryLabel = New-Object System.Windows.Forms.Label
        $summaryLabel.Location = New-Object System.Drawing.Point(10, 500)
        $summaryLabel.Size = New-Object System.Drawing.Size(800, 20)
        $suspiciousCount = ($Results | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
        $highConfidenceCount = ($Results | Where-Object { $_.Confidence -eq "HIGH" }).Count
        $mediumConfidenceCount = ($Results | Where-Object { $_.Confidence -eq "MEDIUM" }).Count
        $unsignedCount = ($Results | Where-Object { $_.Signature -match "Unsigned" }).Count
        $suspiciousSignerCount = ($Results | Where-Object { $_.Signature -match "SUSPICIOUS_SIGNER" }).Count
        
        $summaryLabel.Text = "Files: $($Results.Count) | Suspicious: $suspiciousCount | High: $highConfidenceCount | Medium: $mediumConfidenceCount | Unsigned: $unsignedCount | Bad Signers: $suspiciousSignerCount"

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Location = New-Object System.Drawing.Point(1050, 500)
        $closeButton.Size = New-Object System.Drawing.Size(120, 30)
        $closeButton.Text = "Close"
        $closeButton.Add_Click({ $form.Close() })

        $exportButton = New-Object System.Windows.Forms.Button
        $exportButton.Location = New-Object System.Drawing.Point(920, 500)
        $exportButton.Size = New-Object System.Drawing.Size(120, 30)
        $exportButton.Text = "Export to CSV"
        $exportButton.Add_Click({
            $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $saveFileDialog.Filter = "CSV files (*.csv)|*.csv"
            $saveFileDialog.FileName = "ExecutionAnalysis_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $Results | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
                [System.Windows.Forms.MessageBox]::Show("Data exported to: $($saveFileDialog.FileName)", "Export Complete", "OK", "Information")
            }
        })

        $form.Controls.Add($dataGridView)
        $form.Controls.Add($filterLabel)
        $form.Controls.Add($filterTextBox)
        $form.Controls.Add($summaryLabel)
        $form.Controls.Add($closeButton)
        $form.Controls.Add($exportButton)

        $form.Add_Shown({$form.Activate()})
        $form.ShowDialog() | Out-Null
        
        Write-Log "GUI displayed successfully"
    }
    catch {
        Write-Log "GUI display error - $($_.Exception.Message)"
        Write-Host "GUI interface unavailable. Check output files for complete results." -ForegroundColor Yellow
    }
}

# MAIN EXECUTION - FOCUSED ON DETECTION
Write-Log "Starting enhanced execution analysis with focus on detection..."
Write-Log "Target folders: $($HighPriorityFolders -join ', ')"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Log "Administrative privileges not detected - some features may be limited"
}

if (Test-Path $OutputFile) {
    try {
        Remove-Item $OutputFile -Force
    }
    catch {
        Write-Log "Could not remove existing output file"
    }
}

Write-Log "Running focused detection scans..."

# Run only the effective detection functions
$Artifacts += Get-PrefetchFiles  # Fast keyword-based prefetch scanning
$Artifacts += Get-BAMEntries     # Enhanced BAM with better SID handling
$Artifacts += Get-ShimCacheEntries  # Improved ShimCache parsing
$Artifacts += Get-AmCacheEntries    # Enhanced AmCache with alternative methods
$Artifacts += Get-EventLogExecutions  # Enhanced event log scanning with Sysmon workarounds
$Artifacts += Get-RecentExecutions  # Comprehensive folder scanning
$Artifacts += Get-RecentLNKFiles    # Only 10 most recent LNK files

# Process and group results
$groupedResults = $Artifacts | Group-Object FullPath | ForEach-Object {
    $fileGroup = $_.Group
    $occurrenceCount = $fileGroup.Count
    $highestPriority = $fileGroup | Sort-Object Priority -Descending | Select-Object -First 1
    $highestPriority | Add-Member -NotePropertyName "OccurrenceCount" -NotePropertyValue $occurrenceCount -Force
    $highestPriority
} | Sort-Object Priority -Descending

# Export results
Flush-LogBuffer
Export-Results -Results $groupedResults -OutputPath $OutputFile
Export-JsonResults -Results $groupedResults -OutputPath $JsonOutputFile

# Summary statistics
$suspiciousCount = ($groupedResults | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
$unsignedCount = ($groupedResults | Where-Object { $_.Signature -match "Unsigned" }).Count
$suspiciousSignerCount = ($groupedResults | Where-Object { $_.Signature -match "SUSPICIOUS_SIGNER" }).Count
$keywordCount = ($groupedResults | Where-Object { $_.SuspiciousActivity -match "SUSPICIOUS_KEYWORD_" }).Count
$highConfidenceCount = ($groupedResults | Where-Object { $_.Confidence -eq "HIGH" }).Count
$mediumConfidenceCount = ($groupedResults | Where-Object { $_.Confidence -eq "MEDIUM" }).Count

Write-Log "Analysis completed successfully"
Write-Log "Total files analyzed: $($groupedResults.Count)"
Write-Log "Suspicious files identified: $suspiciousCount"
Write-Log "High confidence detections: $highConfidenceCount"
Write-Log "Medium confidence detections: $mediumConfidenceCount"
Write-Log "Unsigned executables: $unsignedCount"
Write-Log "Suspicious signers detected: $suspiciousSignerCount"
Write-Log "Results saved to: $OutputFile"
Write-Log "JSON results saved to: $JsonOutputFile"

Write-Host "`nANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "Files analyzed: $($groupedResults.Count)" -ForegroundColor Cyan
Write-Host "Detection summary:" -ForegroundColor White
Write-Host "  Suspicious files: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { "Red" } else { "Green" })
Write-Host "  High confidence: $highConfidenceCount" -ForegroundColor $(if ($highConfidenceCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Medium confidence: $mediumConfidenceCount" -ForegroundColor $(if ($mediumConfidenceCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Keywords detected: $keywordCount" -ForegroundColor $(if ($keywordCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Unsigned executables: $unsignedCount" -ForegroundColor $(if ($unsignedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Suspicious signers: $suspiciousSignerCount" -ForegroundColor $(if ($suspiciousSignerCount -gt 0) { "Red" } else { "Green" })
Write-Host "`nOutput files:" -ForegroundColor Cyan
Write-Host "  $OutputFile" -ForegroundColor White
Write-Host "  $JsonOutputFile" -ForegroundColor White

# Show GUI
Show-ResultsGUI -Results $groupedResults
