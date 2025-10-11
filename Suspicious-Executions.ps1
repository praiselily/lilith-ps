Write-Host @"
___       ___  ___       ___  _________  ___  ___     
|\  \     |\  \|\  \     |\  \|\___   ___\\  \|\  \    
\ \  \    \ \  \ \  \    \ \  \|___ \  \_\ \  \\\  \   
 \ \  \    \ \  \ \  \    \ \  \   \ \  \ \ \   __  \  
  \ \  \____\ \  \ \  \____\ \  \   \ \  \ \ \  \ \  \ 
   \ \_______\ \__\ \_______\ \__\   \ \__\ \ \__\ \__\
    \|_______|\|__|\|_______|\|__|    \|__|  \|__|\|__|
Made with love by lily<3                                                       
                                                       
                      SUSPICIOUS EXECUTIONS                                 
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

$SuspiciousKeywords = @("clicker", "vape", "cheat", "hack", "inject", "bot", "macro", "manthe", "ghost", "spoofer", "aim", "killaura", "keyauth", "velocity", "scaffold")
$SuspiciousSigners = @("manthe", "cheat", "hack", "inject", "spoofer", "ghost")
$SpoofedExtensions = @(".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".wsf", ".cpl", ".com", ".pif")

$HighPriorityFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\AppData\Local\Temp", 
    "$env:TEMP"
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
        if ($extension -notin @('.exe', '.dll', '.scr', '.sys')) {
            return 0
        }
        
        if (-not (Test-Path $FilePath)) { return 0 }
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) { return 0 }
        if ($fileInfo.Length -eq 0) { return 0 }
        
        if ($Global:EntropyCache.ContainsKey($FilePath)) {
            return $Global:EntropyCache[$FilePath]
        }
        
        $sampleSize = 1MB
        $bytes = @()
        
        if ($fileInfo.Length -le $sampleSize * 3) {
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        } else {
            $stream = [System.IO.File]::OpenRead($FilePath)
            try {
                $buffer = New-Object byte[] $sampleSize
                
                $stream.Read($buffer, 0, $sampleSize) | Out-Null
                $bytes += $buffer
                
                $stream.Seek($fileInfo.Length / 2, [System.IO.SeekOrigin]::Begin) | Out-Null
                $stream.Read($buffer, 0, $sampleSize) | Out-Null
                $bytes += $buffer
                
                $stream.Seek(-$sampleSize, [System.IO.SeekOrigin]::End) | Out-Null
                $stream.Read($buffer, 0, $sampleSize) | Out-Null
                $bytes += $buffer
            }
            finally {
                $stream.Close()
            }
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
        if ($fileInfo.Length -gt 50MB) { return @() }
        
        if ($Global:StringScanCache.ContainsKey($FilePath)) {
            return $Global:StringScanCache[$FilePath]
        }
        
        $suspiciousStrings = @("clicker", "hwid", "aim", "aura", "macro", "vape", "cheat", "inject", "spoofer")
        $foundStrings = @()
        
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $sampleSize = [Math]::Min($bytes.Length, 8192)
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
    if ($SuspiciousActivity -match "SPOOFED_EXTENSION_") { $priority += 250 }
    if ($SuspiciousActivity -match "SUSPICIOUS_SIGNER") { $priority += 1000 }
    if ($SuspiciousActivity -match "HIGH_ENTROPY") { $priority += 200 }
    if ($SuspiciousActivity -match "CONTAINS_") { $priority += 150 }
    if ($SuspiciousActivity -match "Internet_Download") { $priority += 175 }
    if ($SuspiciousActivity -ne "N/A") { $priority += 50 }
    
    return $priority
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
        
        if ($fileName -match '^[^\.]+\.[^\.]+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$') {
            $suspiciousReasons += "DOUBLE_EXTENSION"
        }
        
        $extension = [System.IO.Path]::GetExtension($normalizedPath).ToLower()
        if ($extension -in @('.exe', '.dll', '.scr', '.sys')) {
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
        
        if ($suspiciousReasons.Count -gt 0 -or $signature -match "SUSPICIOUS_SIGNER") {
            $priority = Get-SuspiciousPriority -SuspiciousActivity ($suspiciousReasons -join " | ") -FileName $fileName
            $confidence = if ($suspiciousReasons.Count -gt 3 -or $priority -gt 1000) { "HIGH" } elseif ($suspiciousReasons.Count -gt 1 -or $priority -gt 500) { "MEDIUM" } else { "LOW" }
            
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
    Write-Log "Scanning Prefetch files..."
    $results = @()
    
    try {
        $prefetchPath = "$env:SystemRoot\Prefetch"
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        
        foreach ($pf in $prefetchFiles) {
            $exeName = $pf.Name.Split('-')[0] + ".exe"
            
            foreach ($folder in $HighPriorityFolders) {
                if (Test-Path $folder) {
                    $foundFiles = Get-ChildItem -Path $folder -Recurse -Depth 3 -Filter $exeName -File -ErrorAction SilentlyContinue
                    foreach ($file in $foundFiles) {
                        $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "Prefetch" -ArtifactFile $pf.FullName -Timestamp $pf.LastWriteTime
                        if ($result) { $results += $result }
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error accessing prefetch directory: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-BAMEntries {
    Write-Log "Scanning BAM entries..."
    $results = @()
    
    $bamPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
    )
    
    foreach ($bamPath in $bamPaths) {
        if (Test-Path $bamPath) {
            $users = Get-ChildItem -Path $bamPath -ErrorAction SilentlyContinue
            foreach ($user in $users) {
                $userPath = Join-Path $bamPath $user.PSChildName
                $entries = Get-ChildItem -Path $userPath -ErrorAction SilentlyContinue
                
                foreach ($entry in $entries) {
                    $entryValue = Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue
                    if ($entryValue) {
                        $propertyNames = $entryValue.PSObject.Properties | Where-Object { 
                            $_.Name -notlike "PS*" -and $_.Name -ne "Path" 
                        }
                        
                        foreach ($prop in $propertyNames) {
                            $binaryData = $prop.Value
                            if ($binaryData -is [byte[]] -and $binaryData.Length -gt 0) {
                                $asciiString = [System.Text.Encoding]::ASCII.GetString($binaryData)
                                
                                if ($asciiString -match "[a-zA-Z]:\\[^\x00]+\.(exe|dll|scr|bat|cmd|ps1)") {
                                    $filePath = $matches[0]
                                    if (Test-Path $filePath) {
                                        $file = Get-Item $filePath -ErrorAction SilentlyContinue
                                        if ($file -and -not ($file -is [System.IO.DirectoryInfo])) {
                                            $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "BAM" -ArtifactFile $entry.PSPath -Timestamp $file.LastWriteTime
                                            if ($result) { $results += $result }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    foreach ($folder in $HighPriorityFolders) {
        if (Test-Path $folder) {
            $recentExecutables = Get-ChildItem -Path $folder -Recurse -Depth 3 -Include "*.exe", "*.dll" -File -ErrorAction SilentlyContinue | 
                                Where-Object { $_.LastAccessTime -gt (Get-Date).AddDays(-7) } |
                                Select-Object -First 20
                                
            foreach ($file in $recentExecutables) {
                $result = Evaluate-FileSuspicion -FilePath $file.FullName -Source "BAM_Recent" -ArtifactFile "Recent_Access" -Timestamp $file.LastAccessTime
                if ($result) { $results += $result }
            }
        }
    }
    
    return $results
}
function Get-EventLogExecutions {
    Write-Log "Scanning Event Logs for process executions..."
    $results = @()
    
    try {
        $startTime = (Get-Date).AddHours(-24)
        
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$startTime} -ErrorAction SilentlyContinue
        
        foreach ($event in $events) {
            $message = $event.Message
            if ($message -match 'vape|inject|macro|clicker|spoofer|cheat|ghost|manthe') {
                if ($message -match 'New Process Name:\s*(.*\.exe)') {
                    $exePath = $matches[1]
                    $result = Evaluate-FileSuspicion -FilePath $exePath -Source "EventLog_4688" -ArtifactFile "Security_Log" -Timestamp $event.TimeCreated
                    if ($result) { $results += $result }
                }
            }
        }
    }
    catch {
        Write-Log "Error scanning event logs: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-StartupItems {
    Write-Log "Scanning startup items and scheduled tasks..."
    $results = @()
    
    try {
        $startupPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($regPath in $startupPaths) {
            if (Test-Path $regPath) {
                $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($items) {
                    $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                        if ($_.Value -match '\.exe' -and $_.Value -match 'vape|inject|cheat|spoofer') {
                            $exePath = $_.Value -replace '^"|"$', ''
                            $result = Evaluate-FileSuspicion -FilePath $exePath -Source "Startup_Item" -ArtifactFile $regPath -Timestamp (Get-Date)
                            if ($result) { $results += $result }
                        }
                    }
                }
            }
        }
        
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'vape|inject|cheat|spoofer' }
        foreach ($task in $tasks) {
            Write-Log "Suspicious scheduled task: $($task.TaskName)"
        }
    }
    catch {
        Write-Log "Error scanning startup items: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-PowerShellHistory {
    Write-Log "Scanning PowerShell history..."
    $results = @()
    
    try {
        $historyPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        if (Test-Path $historyPath) {
            $history = Get-Content $historyPath -ErrorAction SilentlyContinue
            $suspiciousCommands = $history | Where-Object { $_ -match 'vape|inject|cheat|spoofer|clicker|macro' }
            
            foreach ($cmd in $suspiciousCommands) {
                Write-Log "Suspicious PowerShell command: $cmd"
            }
        }
    }
    catch {
        Write-Log "Error scanning PowerShell history: $($_.Exception.Message)"
    }
    
    return $results
}

function Export-Results {
    param(
        [array]$Results,
        [string]$OutputPath
    )
    
    $separator = "=" * 80
    Add-Content -Path $OutputPath -Value "SUSPICIOUS EXECUTED FILES SCAN REPORT"
    Add-Content -Path $OutputPath -Value "Generated: $(Get-Date)"
    Add-Content -Path $OutputPath -Value "Scan Target: High priority folders only"
    Add-Content -Path $OutputPath -Value $separator
    Add-Content -Path $OutputPath -Value "Source`tFullPath`tTimestamp`tFileExists`tSignature`tSHA256`tArtifactFile`tSuspiciousActivity`tUSNReason`tRawReason`tPriority`tConfidence"

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
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Suspicious Executed Files Scan Results"
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
            @{Name="Source"; HeaderText="Source"; Width=80},
            @{Name="FullPath"; HeaderText="File Path"; Width=400},
            @{Name="Signature"; HeaderText="Signature"; Width=150},
            @{Name="SuspiciousActivity"; HeaderText="Suspicious Activity"; Width=200},
            @{Name="Priority"; HeaderText="Priority"; Width=70},
            @{Name="Confidence"; HeaderText="Confidence"; Width=80}
        )

        foreach ($column in $columns) {
            $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
            $col.Name = $column.Name
            $col.HeaderText = $column.HeaderText
            if ($column.Width) { $col.Width = $column.Width }
            $dataGridView.Columns.Add($col) | Out-Null
        }

        $filterLabel = New-Object System.Windows.Forms.Label
        $filterLabel.Location = New-Object System.Drawing.Point(10, 15)
        $filterLabel.Size = New-Object System.Drawing.Size(100, 20)
        $filterLabel.Text = "Filter:"

        $filterTextBox = New-Object System.Windows.Forms.TextBox
        $filterTextBox.Location = New-Object System.Drawing.Point(50, 12)
        $filterTextBox.Size = New-Object System.Drawing.Size(200, 20)

        $dataGridView.Add_CellFormatting({
            param($sender, $e)
            
            if ($e.ColumnIndex -eq 3) {
                $activity = $sender.Rows[$e.RowIndex].Cells[3].Value
                if ($activity -ne "N/A" -and $activity -ne $null) {
                    if ($activity -match "SUSPICIOUS_KEYWORD_") {
                        $e.CellStyle.BackColor = [System.Drawing.Color]::Red
                        $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                    } else {
                        $e.CellStyle.BackColor = [System.Drawing.Color]::LightCoral
                    }
                }
            }
            
            if ($e.ColumnIndex -eq 2) {
                $signature = $sender.Rows[$e.RowIndex].Cells[2].Value
                if ($signature -match "SUSPICIOUS_SIGNER") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::LightYellow
                }
            }
            
            if ($e.ColumnIndex -eq 4) {
                $priority = $sender.Rows[$e.RowIndex].Cells[4].Value
                if ($priority -gt 1000) {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::DarkRed
                    $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                } elseif ($priority -gt 500) {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::OrangeRed
                    $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                } elseif ($priority -gt 200) {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::Orange
                }
            }
            
            if ($e.ColumnIndex -eq 5) {
                $confidence = $sender.Rows[$e.RowIndex].Cells[5].Value
                if ($confidence -eq "HIGH") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::Red
                    $e.CellStyle.ForeColor = [System.Drawing.Color]::White
                } elseif ($confidence -eq "MEDIUM") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::Orange
                } elseif ($confidence -eq "LOW") {
                    $e.CellStyle.BackColor = [System.Drawing.Color]::LightYellow
                }
            }
        })

        $filterTextBox.Add_TextChanged({
            $filter = $filterTextBox.Text
            if ([string]::IsNullOrWhiteSpace($filter)) {
                $dataGridView.DataSource = [System.Collections.ArrayList]@($dataSource)
            } else {
                $filtered = $dataSource | Where-Object { 
                    $_.FullPath -match $filter -or 
                    $_.Source -match $filter -or
                    $_.SuspiciousActivity -match $filter
                }
                $dataGridView.DataSource = [System.Collections.ArrayList]@($filtered)
            }
        })

        $dataSource = $Results | Sort-Object Priority -Descending | Select-Object Source, FullPath, Signature, SuspiciousActivity, Priority, Confidence
        $dataGridView.DataSource = [System.Collections.ArrayList]@($dataSource)

        $summaryLabel = New-Object System.Windows.Forms.Label
        $summaryLabel.Location = New-Object System.Drawing.Point(10, 500)
        $summaryLabel.Size = New-Object System.Drawing.Size(800, 20)
        $suspiciousCount = ($Results | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
        $unsignedCount = ($Results | Where-Object { $_.Signature -match "Unsigned" }).Count
        $suspiciousSignerCount = ($Results | Where-Object { $_.Signature -match "SUSPICIOUS_SIGNER" }).Count
        $keywordCount = ($Results | Where-Object { $_.SuspiciousActivity -match "SUSPICIOUS_KEYWORD_" }).Count
        $highConfidenceCount = ($Results | Where-Object { $_.Confidence -eq "HIGH" }).Count
        
        $summaryLabel.Text = "Files: $($Results.Count) | Suspicious: $suspiciousCount | High Confidence: $highConfidenceCount | Keywords: $keywordCount | Unsigned: $unsignedCount | Bad Signers: $suspiciousSignerCount"

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
            $saveFileDialog.FileName = "SuspiciousFiles_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
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
    }
    catch {
        Write-Log "GUI Error: $($_.Exception.Message)"
        Write-Host "GUI failed to load. Check output files for results." -ForegroundColor Red
    }
}

Write-Log "Starting focused suspicious executed files scan..."
Write-Log "Output file: $OutputFile"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Log "Not running as administrator. Some artifacts may not be accessible."
}

if (Test-Path $OutputFile) {
    try {
        Remove-Item $OutputFile -Force
    }
    catch {
    }
}

Write-Log "Collecting data from execution artifacts..."

$Artifacts += Get-PrefetchFiles
$Artifacts += Get-BAMEntries
$Artifacts += Get-EventLogExecutions
$Artifacts += Get-StartupItems
$Artifacts += Get-PowerShellHistory

$groupedResults = $Artifacts | Group-Object FullPath | ForEach-Object {
    $fileGroup = $_.Group
    $occurrenceCount = $fileGroup.Count
    $highestPriority = $fileGroup | Sort-Object Priority -Descending | Select-Object -First 1
    $highestPriority | Add-Member -NotePropertyName "OccurrenceCount" -NotePropertyValue $occurrenceCount -Force
    $highestPriority
} | Sort-Object Priority -Descending

Flush-LogBuffer
Export-Results -Results $groupedResults -OutputPath $OutputFile
Export-JsonResults -Results $groupedResults -OutputPath $JsonOutputFile

$suspiciousCount = ($groupedResults | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
$unsignedCount = ($groupedResults | Where-Object { $_.Signature -match "Unsigned" }).Count
$suspiciousSignerCount = ($groupedResults | Where-Object { $_.Signature -match "SUSPICIOUS_SIGNER" }).Count
$keywordCount = ($groupedResults | Where-Object { $_.SuspiciousActivity -match "SUSPICIOUS_KEYWORD_" }).Count
$highConfidenceCount = ($groupedResults | Where-Object { $_.Confidence -eq "HIGH" }).Count
$mediumConfidenceCount = ($groupedResults | Where-Object { $_.Confidence -eq "MEDIUM" }).Count

Write-Log "Scan completed!"
Write-Log "Total files found: $($groupedResults.Count)"
Write-Log "Suspicious files: $suspiciousCount"
Write-Log "High confidence detections: $highConfidenceCount"
Write-Log "Medium confidence detections: $mediumConfidenceCount"
Write-Log "Unsigned files: $unsignedCount"
Write-Log "Results saved to: $OutputFile"
Write-Log "JSON results saved to: $JsonOutputFile"

Write-Host "`nSCAN COMPLETED" -ForegroundColor Green
Write-Host "Files analyzed: $($groupedResults.Count)" -ForegroundColor Cyan
Write-Host "Suspicious indicators:" -ForegroundColor Red
Write-Host "  Suspicious files: $suspiciousCount" -ForegroundColor Red
Write-Host "  High confidence: $highConfidenceCount" -ForegroundColor Red
Write-Host "  Medium confidence: $mediumConfidenceCount" -ForegroundColor Yellow
Write-Host "  Keywords detected: $keywordCount" -ForegroundColor Red
Write-Host "  Unsigned executables: $unsignedCount" -ForegroundColor Red
Write-Host "  Suspicious signers: $suspiciousSignerCount" -ForegroundColor Red

Show-ResultsGUI -Results $groupedResults
