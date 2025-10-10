<#
.SYNOPSIS
    Scans all drives except C: for executed files and USN Journal for file modifications
.DESCRIPTION
    This script scans Prefetch, ShimCache, AmCache, ActivityCache for executed files
    and USN Journal for file modifications on all drives except C:
#>

# path
$OutputDirectory = "C:\Screenshare"
$OutputFile = Join-Path $OutputDirectory "output.txt"
$Artifacts = @()


if (-not (Test-Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create output directory: $OutputDirectory"
        Write-Error "Error: $($_.Exception.Message)"
        exit 1
    }
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    Add-Content -Path $OutputFile -Value $logEntry
}

function Get-DigitalSignature {
    param([string]$FilePath)
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq "Valid") {
            return "Signed - $($sig.SignerCertificate.Subject)"
        } elseif ($sig -and $sig.Status -ne "Valid") {
            return "Invalid - $($sig.Status)"
        } else {
            return "Not Signed"
        }
    }
    catch {
        return "Error checking signature"
    }
}

# usn
$USN_REASON_DATA_OVERWRITE = 0x00000001
$USN_REASON_DATA_EXTEND = 0x00000002
$USN_REASON_DATA_TRUNCATION = 0x00000004
$USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
$USN_REASON_NAMED_DATA_EXTEND = 0x00000020
$USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
$USN_REASON_FILE_CREATE = 0x00000100
$USN_REASON_FILE_DELETE = 0x00000200
$USN_REASON_EA_CHANGE = 0x00000400
$USN_REASON_SECURITY_CHANGE = 0x00000800
$USN_REASON_RENAME_OLD_NAME = 0x00001000
$USN_REASON_RENAME_NEW_NAME = 0x00002000
$USN_REASON_INDEXABLE_CHANGE = 0x00004000
$USN_REASON_BASIC_INFO_CHANGE = 0x00008000
$USN_REASON_HARD_LINK_CHANGE = 0x00010000
$USN_REASON_COMPRESSION_CHANGE = 0x00020000
$USN_REASON_ENCRYPTION_CHANGE = 0x00040000
$USN_REASON_OBJECT_ID_CHANGE = 0x00080000
$USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
$USN_REASON_STREAM_CHANGE = 0x00200000
$USN_REASON_TRANSACTED_CHANGE = 0x00400000
$USN_REASON_INTEGRITY_CHANGE = 0x00800000
$USN_REASON_DESIRED_STORAGE_CLASS_CHANGE = 0x01000000
$USN_REASON_CLOSE = 0x80000000

function Get-USNReasonDescription {
    param([uint32]$Reason)
    
    $reasons = @()
    
    if ($Reason -band $USN_REASON_DATA_OVERWRITE) { $reasons += "DATA_OVERWRITE" }
    if ($Reason -band $USN_REASON_DATA_EXTEND) { $reasons += "DATA_EXTEND" }
    if ($Reason -band $USN_REASON_DATA_TRUNCATION) { $reasons += "DATA_TRUNCATION" }
    if ($Reason -band $USN_REASON_NAMED_DATA_OVERWRITE) { $reasons += "NAMED_DATA_OVERWRITE" }
    if ($Reason -band $USN_REASON_NAMED_DATA_EXTEND) { $reasons += "NAMED_DATA_EXTEND" }
    if ($Reason -band $USN_REASON_NAMED_DATA_TRUNCATION) { $reasons += "NAMED_DATA_TRUNCATION" }
    if ($Reason -band $USN_REASON_FILE_CREATE) { $reasons += "FILE_CREATE" }
    if ($Reason -band $USN_REASON_FILE_DELETE) { $reasons += "FILE_DELETE" }
    if ($Reason -band $USN_REASON_EA_CHANGE) { $reasons += "EA_CHANGE" }
    if ($Reason -band $USN_REASON_SECURITY_CHANGE) { $reasons += "SECURITY_CHANGE" }
    if ($Reason -band $USN_REASON_RENAME_OLD_NAME) { $reasons += "RENAME_OLD_NAME" }
    if ($Reason -band $USN_REASON_RENAME_NEW_NAME) { $reasons += "RENAME_NEW_NAME" }
    if ($Reason -band $USN_REASON_INDEXABLE_CHANGE) { $reasons += "INDEXABLE_CHANGE" }
    if ($Reason -band $USN_REASON_BASIC_INFO_CHANGE) { $reasons += "BASIC_INFO_CHANGE" }
    if ($Reason -band $USN_REASON_HARD_LINK_CHANGE) { $reasons += "HARD_LINK_CHANGE" }
    if ($Reason -band $USN_REASON_COMPRESSION_CHANGE) { $reasons += "COMPRESSION_CHANGE" }
    if ($Reason -band $USN_REASON_ENCRYPTION_CHANGE) { $reasons += "ENCRYPTION_CHANGE" }
    if ($Reason -band $USN_REASON_OBJECT_ID_CHANGE) { $reasons += "OBJECT_ID_CHANGE" }
    if ($Reason -band $USN_REASON_REPARSE_POINT_CHANGE) { $reasons += "REPARSE_POINT_CHANGE" }
    if ($Reason -band $USN_REASON_STREAM_CHANGE) { $reasons += "STREAM_CHANGE" }
    if ($Reason -band $USN_REASON_TRANSACTED_CHANGE) { $reasons += "TRANSACTED_CHANGE" }
    if ($Reason -band $USN_REASON_CLOSE) { $reasons += "CLOSE" }
    
    return ($reasons -join ", ")
}

function Get-USNJournalEntries {
    Write-Log "Scanning USN Journal for suspicious file modifications..."
    $results = @()
    
    try {
        
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
            $_.Root -ne "C:\" -and $_.Root -ne $env:SystemDrive -and $_.Used -gt 0
        }
        
        foreach ($drive in $drives) {
            Write-Log "Scanning USN Journal on drive: $($drive.Root)"
            
            try {
                
                $driveLetter = $drive.Root.TrimEnd('\')
                $usnData = fsutil usn readJournal $driveLetter | Out-String
                
                
                $entries = $usnData -split "USN_RECORD" | Where-Object { $_ -match "File" }
                
                foreach ($entry in $entries) {
                    try {
                        
                        if ($entry -match "File Name\s+:\s+(.+)") {
                            $fileName = $matches[1].Trim()
                            
                            if ($entry -match "Reason\s+:\s+0x([0-9a-fA-F]+)") {
                                $reasonHex = $matches[1]
                                $reason = [Convert]::ToUInt32($reasonHex, 16)
                                $reasonDesc = Get-USNReasonDescription -Reason $reason
                                
                                
                                $isSuspicious = $false
                                $suspiciousReasons = @()
                                
                                
                                if ($reason -band $USN_REASON_FILE_DELETE) {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "FILE_DELETED"
                                }
                                
                                
                                if (($reason -band $USN_REASON_DATA_OVERWRITE) -and 
                                    ($reason -band $USN_REASON_CLOSE)) {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "FILE_REPLACED"
                                }
                                
                                
                                if (($reason -band $USN_REASON_FILE_CREATE) -and 
                                    ($reason -band $USN_REASON_DATA_OVERWRITE)) {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "RAPID_CREATE_OVERWRITE"
                                }
                                
                                
                                if ($fileName -match "\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "EXECUTABLE_MODIFIED"
                                }
                                
                                
                                if ($fileName -match "\.tmp$|temp\\|tmp\\|~$") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "TEMPORARY_FILE_ACTIVITY"
                                }
                                
                                if ($isSuspicious) {
                                    $fullPath = Join-Path $drive.Root $fileName
                                    $fileExists = Test-Path $fullPath
                                    $signature = if ($fileExists -and $fullPath -match "\.(exe|dll)$") { 
                                        Get-DigitalSignature -FilePath $fullPath 
                                    } else { 
                                        "N/A" 
                                    }
                                    
                                    # timestamps
                                    $timestamp = "N/A"
                                    if ($entry -match "Time Stamp:\s+(.+)") {
                                        $timestamp = $matches[1].Trim()
                                    }
                                    
                                    $result = [PSCustomObject]@{
                                        Source = "USN_Journal"
                                        FullPath = $fullPath
                                        Timestamp = $timestamp
                                        FileExists = $fileExists
                                        Signature = $signature
                                        ArtifactFile = $drive.Root + "\$UsnJrnl"
                                        SuspiciousActivity = ($suspiciousReasons -join " | ")
                                        USNReason = $reasonDesc
                                        RawReason = "0x$reasonHex"
                                    }
                                    $results += $result
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log "Error parsing USN entry: $($_.Exception.Message)"
                    }
                }
            }
            catch {
                Write-Log "Error accessing USN Journal on drive $($drive.Root): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "Error scanning USN Journal: $($_.Exception.Message)"
    }
    
    Write-Log "USN Journal scan completed. Found $($results.Count) suspicious entries."
    return $results
}

function Get-PrefetchFiles {
    Write-Log "Scanning Prefetch files..."
    $prefetchPath = "$env:SystemRoot\Prefetch"
    $results = @()
    
    try {
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        foreach ($pf in $prefetchFiles) {
            try {
                
                $exeName = $pf.Name.Split('-')[0] + ".exe"
                
                
                $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" -and $_.Root -ne $env:SystemDrive }
                foreach ($drive in $drives) {
                    $potentialPaths = @(
                        "$($drive.Root)$exeName",
                        "$($drive.Root)Windows\System32\$exeName",
                        "$($drive.Root)Program Files\*\$exeName",
                        "$($drive.Root)Program Files (x86)\*\$exeName",
                        "$($drive.Root)Users\*\AppData\**\$exeName"
                    )
                    
                    foreach ($pattern in $potentialPaths) {
                        $foundFiles = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
                        foreach ($file in $foundFiles) {
                            $fileExists = Test-Path $file.FullName
                            $signature = if ($fileExists) { Get-DigitalSignature -FilePath $file.FullName } else { "N/A" }
                            $lastRunTime = $pf.LastWriteTime
                            
                            $result = [PSCustomObject]@{
                                Source = "Prefetch"
                                FullPath = $file.FullName
                                Timestamp = $lastRunTime
                                FileExists = $fileExists
                                Signature = $signature
                                ArtifactFile = $pf.FullName
                                SuspiciousActivity = "N/A"
                                USNReason = "N/A"
                                RawReason = "N/A"
                            }
                            $results += $result
                        }
                    }
                }
            }
            catch {
                Write-Log "Error processing prefetch file $($pf.Name): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "Error accessing prefetch directory: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-ShimCacheEntries {
    Write-Log "Scanning ShimCache entries..."
    $results = @()
    
    try {
        # shimcaches
        $shimPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility"
        )
        
        foreach ($regPath in $shimPaths) {
            try {
                $cache = Get-ItemProperty -Path $regPath -Name "AppCompatCache" -ErrorAction SilentlyContinue
                if ($cache) {
                    
                    
                    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" -and $_.Root -ne $env:SystemDrive }
                    
                    foreach ($drive in $drives) {
                        
                        $patterns = @(
                            "$($drive.Root)*.exe",
                            "$($drive.Root)Program Files\**\*.exe",
                            "$($drive.Root)Program Files (x86)\**\*.exe",
                            "$($drive.Root)Users\**\*.exe"
                        )
                        
                        foreach ($pattern in $patterns) {
                            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 50
                            foreach ($file in $files) {
                                $fileExists = Test-Path $file.FullName
                                $signature = if ($fileExists) { Get-DigitalSignature -FilePath $file.FullName } else { "N/A" }
                                
                                $result = [PSCustomObject]@{
                                    Source = "ShimCache"
                                    FullPath = $file.FullName
                                    Timestamp = "N/A" 
                                    FileExists = $fileExists
                                    Signature = $signature
                                    ArtifactFile = $regPath
                                    SuspiciousActivity = "N/A"
                                    USNReason = "N/A"
                                    RawReason = "N/A"
                                }
                                $results += $result
                            }
                        }
                    }
                }
            }
            catch {
                
                $errorMsg = "Error accessing registry path " + $regPath + ": " + $_.Exception.Message
                Write-Log $errorMsg
            }
        }
    }
    catch {
        Write-Log "Error scanning ShimCache: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-AmCacheEntries {
    Write-Log "Scanning AmCache hive..."
    $results = @()
    
    try {
        $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
        if (Test-Path $amcachePath) {
            
            
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" -and $_.Root -ne $env:SystemDrive }
            
            foreach ($drive in $drives) {
                
                $searchPaths = @(
                    "$($drive.Root)Users\*\AppData\Local\Temp\*.exe",
                    "$($drive.Root)Users\*\Downloads\*.exe",
                    "$($drive.Root)Windows\Temp\*.exe",
                    "$($drive.Root)*.exe"
                )
                
                foreach ($pattern in $searchPaths) {
                    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | 
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                            Select-Object -First 20
                    
                    foreach ($file in $files) {
                        $fileExists = Test-Path $file.FullName
                        $signature = if ($fileExists) { Get-DigitalSignature -FilePath $file.FullName } else { "N/A" }
                        
                        $result = [PSCustomObject]@{
                            Source = "AmCache"
                            FullPath = $file.FullName
                            Timestamp = $file.LastWriteTime
                            FileExists = $fileExists
                            Signature = $signature
                            ArtifactFile = $amcachePath
                            SuspiciousActivity = "N/A"
                            USNReason = "N/A"
                            RawReason = "N/A"
                        }
                        $results += $result
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error scanning AmCache: $($_.Exception.Message)"
    }
    
    return $results
}

function Get-ActivityCache {
    Write-Log "Scanning for ActivityCache/RecentFileCache..."
    $results = @()
    
    try {
        
        $recentCache = "$env:LocalAppData\ConnectedDevicesPlatform\*\ActivitiesCache.db"
        $cacheFiles = Get-ChildItem -Path $recentCache -ErrorAction SilentlyContinue
        
        foreach ($cacheFile in $cacheFiles) {
            try {
                
                $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" -and $_.Root -ne $env:SystemDrive }
                
                foreach ($drive in $drives) {
                    
                    $files = Get-ChildItem -Path "$($drive.Root)*.exe" -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastAccessTime -gt (Get-Date).AddDays(-60) } |
                            Select-Object -First 30
                    
                    foreach ($file in $files) {
                        $fileExists = Test-Path $file.FullName
                        $signature = if ($fileExists) { Get-DigitalSignature -FilePath $file.FullName } else { "N/A" }
                        
                        $result = [PSCustomObject]@{
                            Source = "ActivityCache"
                            FullPath = $file.FullName
                            Timestamp = $file.LastAccessTime
                            FileExists = $fileExists
                            Signature = $signature
                            ArtifactFile = $cacheFile.FullName
                            SuspiciousActivity = "N/A"
                            USNReason = "N/A"
                            RawReason = "N/A"
                        }
                        $results += $result
                    }
                }
            }
            catch {
                Write-Log "Error processing cache file $($cacheFile.FullName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "Error scanning ActivityCache: $($_.Exception.Message)"
    }
    
    return $results
}

function Show-ResultsGUI {
    param(
        [array]$Results
    )
    
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Executed Files & USN Journal Scan Results"
    $form.Size = New-Object System.Drawing.Size(1400, 700)
    $form.StartPosition = "CenterScreen"
    $form.MaximizeBox = $true
    $form.MinimizeBox = $true

    # griddy
    $dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Location = New-Object System.Drawing.Point(10, 10)
    $dataGridView.Size = New-Object System.Drawing.Size(1360, 550)
    $dataGridView.AutoSizeColumnsMode = "Fill"
    $dataGridView.SelectionMode = "FullRowSelect"
    $dataGridView.ReadOnly = $true
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.AllowUserToDeleteRows = $false
    $dataGridView.RowHeadersVisible = $false

    
    $columns = @(
        @{Name="Timestamp"; HeaderText="Timestamp"},
        @{Name="FilePath"; HeaderText="File Path"},
        @{Name="Signature"; HeaderText="Signature"},
        @{Name="FileStatus"; HeaderText="File Status"},
        @{Name="Source"; HeaderText="Artifact Source"},
        @{Name="SuspiciousActivity"; HeaderText="Suspicious Activity"},
        @{Name="USNReason"; HeaderText="USN Reason"}
    )

    foreach ($column in $columns) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $column.Name
        $col.HeaderText = $column.HeaderText
        $dataGridView.Columns.Add($col) | Out-Null
    }

    
    $dataGridView.Add_CellFormatting({
        param($sender, $e)
        
        if ($e.ColumnIndex -eq 5) { 
            $activity = $sender.Rows[$e.RowIndex].Cells[5].Value
            if ($activity -ne "N/A" -and $activity -ne $null) {
                $e.CellStyle.BackColor = [System.Drawing.Color]::LightCoral
                $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed
            }
        }
    })

    
    foreach ($result in $Results) {
        
        $timestamp = if ($result.Timestamp -eq "N/A") { "N/A" } else { 
            try {
                if ($result.Timestamp -is [datetime]) {
                    $result.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                } else {
                    $result.Timestamp
                }
            }
            catch {
                "N/A"
            }
        }
        
        
        $fileStatus = if ($result.FileExists) { "File is still present" } else { "File is not present" }
        
        
        $signature = $result.Signature
        if ($signature.Length -gt 50) {
            $signature = $signature.Substring(0, 47) + "..."
        }

        $row = New-Object System.Windows.Forms.DataGridViewRow
        $row.CreateCells($dataGridView, $timestamp, $result.FullPath, $signature, $fileStatus, $result.Source, $result.SuspiciousActivity, $result.USNReason)
        $dataGridView.Rows.Add($row) | Out-Null
    }

    
    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.Location = New-Object System.Drawing.Point(10, 570)
    $summaryLabel.Size = New-Object System.Drawing.Size(1000, 20)
    $suspiciousCount = ($Results | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
    $summaryLabel.Text = "Total files found: $($Results.Count) | Suspicious activities: $suspiciousCount | Output saved to: $OutputFile"

    
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(1250, 570)
    $closeButton.Size = New-Object System.Drawing.Size(120, 30)
    $closeButton.Text = "Close"
    $closeButton.Add_Click({ $form.Close() })

    
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Location = New-Object System.Drawing.Point(1120, 570)
    $exportButton.Size = New-Object System.Drawing.Size(120, 30)
    $exportButton.Text = "Export to CSV"
    $exportButton.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV files (*.csv)|*.csv"
        $saveFileDialog.FileName = "ExecutedFiles_USN_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $Results | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
            [System.Windows.Forms.MessageBox]::Show("Data exported to: $($saveFileDialog.FileName)", "Export Complete", "OK", "Information")
        }
    })

    
    $form.Controls.Add($dataGridView)
    $form.Controls.Add($summaryLabel)
    $form.Controls.Add($closeButton)
    $form.Controls.Add($exportButton)

    
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null
}


Write-Log "Starting executed files and USN Journal scan on non-C drives..."
Write-Log "Output file: $OutputFile"

# admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Warning "Not running as administrator. Some artifacts may not be accessible."
}


if (Test-Path $OutputFile) {
    try {
        Remove-Item $OutputFile -Force
        Write-Log "Cleared existing output file."
    }
    catch {
        Write-Log "Warning: Could not clear existing output file: $($_.Exception.Message)"
    }
}


Write-Log "Collecting data from various artifacts..."

$Artifacts += Get-PrefetchFiles
$Artifacts += Get-ShimCacheEntries
$Artifacts += Get-AmCacheEntries
$Artifacts += Get-ActivityCache
$Artifacts += Get-USNJournalEntries

# dupes
$uniqueResults = $Artifacts | Sort-Object FullPath, Source | Get-Unique -AsString


Write-Log "Writing results to output file..."


$header = "Source`tFullPath`tTimestamp`tFileExists`tSignature`tArtifactFile`tSuspiciousActivity`tUSNReason`tRawReason"
Add-Content -Path $OutputFile -Value "EXECUTED FILES & USN JOURNAL SCAN REPORT"
Add-Content -Path $OutputFile -Value "Generated: $(Get-Date)"
Add-Content -Path $OutputFile -Value "Scan Target: All drives except C:"
Add-Content -Path $OutputFile -Value "=" * 80
Add-Content -Path $OutputFile -Value $header


foreach ($result in $uniqueResults) {
    $line = "$($result.Source)`t$($result.FullPath)`t$($result.Timestamp)`t$($result.FileExists)`t$($result.Signature)`t$($result.ArtifactFile)`t$($result.SuspiciousActivity)`t$($result.USNReason)`t$($result.RawReason)"
    Add-Content -Path $OutputFile -Value $line
}


$suspiciousCount = ($uniqueResults | Where-Object { $_.SuspiciousActivity -ne "N/A" }).Count
Write-Log "Scan completed!"
Write-Log "Total unique files found: $($uniqueResults.Count)"
Write-Log "Suspicious activities detected: $suspiciousCount"
Write-Log "Results saved to: $OutputFile"


Write-Host "`n=== SCAN COMPLETED ===" -ForegroundColor Green
Write-Host "Opening results GUI..." -ForegroundColor Yellow
Write-Host "Total files found: $($uniqueResults.Count)" -ForegroundColor Yellow
Write-Host "Suspicious activities: $suspiciousCount" -ForegroundColor Red
Write-Host "File also saved to: C:\Screenshare\output.txt" -ForegroundColor Cyan


Show-ResultsGUI -Results $uniqueResults
