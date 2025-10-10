<#
.
    Scans all drives except C: for executed files
.DESCRIPTION
    Parses Prefetch, ShimCache, AmCache, and ActivityCache for and collects files
    on all drives except C: and outputs information, will also verify
    file existence, and digital signature status.
#>

# output
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
        # recentfilecache
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
    
    #gui
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Executed Files Scan Results"
    $form.Size = New-Object System.Drawing.Size(1200, 600)
    $form.StartPosition = "CenterScreen"
    $form.MaximizeBox = $true
    $form.MinimizeBox = $true

    # griddy
    $dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Location = New-Object System.Drawing.Point(10, 10)
    $dataGridView.Size = New-Object System.Drawing.Size(1160, 500)
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
        @{Name="Source"; HeaderText="Artifact Source"}
    )

    foreach ($column in $columns) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $column.Name
        $col.HeaderText = $column.HeaderText
        $dataGridView.Columns.Add($col) | Out-Null
    }

    
    foreach ($result in $Results) {
        
        $timestamp = if ($result.Timestamp -eq "N/A") { "N/A" } else { $result.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") }
        
        
        $fileStatus = if ($result.FileExists) { "File is still present" } else { "File is not present" }
        
        
        $signature = $result.Signature
        if ($signature.Length -gt 50) {
            $signature = $signature.Substring(0, 47) + "..."
        }

        $row = New-Object System.Windows.Forms.DataGridViewRow
        $row.CreateCells($dataGridView, $timestamp, $result.FullPath, $signature, $fileStatus, $result.Source)
        $dataGridView.Rows.Add($row) | Out-Null
    }

    
    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.Location = New-Object System.Drawing.Point(10, 520)
    $summaryLabel.Size = New-Object System.Drawing.Size(800, 20)
    $summaryLabel.Text = "Total files found: $($Results.Count) | Output saved to: $OutputFile"

    
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(1050, 520)
    $closeButton.Size = New-Object System.Drawing.Size(120, 30)
    $closeButton.Text = "Close"
    $closeButton.Add_Click({ $form.Close() })

    
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Location = New-Object System.Drawing.Point(920, 520)
    $exportButton.Size = New-Object System.Drawing.Size(120, 30)
    $exportButton.Text = "Export to CSV"
    $exportButton.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV files (*.csv)|*.csv"
        $saveFileDialog.FileName = "ExecutedFiles_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
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


Write-Log "Starting executed files scan on non-C drives..."
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

# dupes
$uniqueResults = $Artifacts | Sort-Object FullPath, Source | Get-Unique -AsString


Write-Log "Writing results to output file..."


$header = "Source`tFullPath`tTimestamp`tFileExists`tSignature`tArtifactFile"
Add-Content -Path $OutputFile -Value "EXECUTED FILES SCAN REPORT"
Add-Content -Path $OutputFile -Value "Generated: $(Get-Date)"
Add-Content -Path $OutputFile -Value "Scan Target: All drives except C:"
Add-Content -Path $OutputFile -Value "=" * 80
Add-Content -Path $OutputFile -Value $header


foreach ($result in $uniqueResults) {
    $line = "$($result.Source)`t$($result.FullPath)`t$($result.Timestamp)`t$($result.FileExists)`t$($result.Signature)`t$($result.ArtifactFile)"
    Add-Content -Path $OutputFile -Value $line
}


Write-Log "Scan completed!"
Write-Log "Total unique executed files found: $($uniqueResults.Count)"
Write-Log "Results saved to: $OutputFile"


Write-Host "`nSCAN COMPLETED" -ForegroundColor Green
Write-Host "Opening results GUI..." -ForegroundColor Yellow
Write-Host "Total files found: $($uniqueResults.Count)" -ForegroundColor Yellow
Write-Host "File also saved to: C:\Screenshare\output.txt" -ForegroundColor Cyan


Show-ResultsGUI -Results $uniqueResults
