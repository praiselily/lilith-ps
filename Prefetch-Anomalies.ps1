#    Made with love by lily<3

Write-Host @"
___       ___  ___       ___  _________  ___  ___     
|\  \     |\  \|\  \     |\  \|\___   ___\\  \|\  \    
\ \  \    \ \  \ \  \    \ \  \|___ \  \_\ \  \\\  \   
 \ \  \    \ \  \ \  \    \ \  \   \ \  \ \ \   __  \  
  \ \  \____\ \  \ \  \____\ \  \   \ \  \ \ \  \ \  \ 
   \ \_______\ \__\ \_______\ \__\   \ \__\ \ \__\ \__\
    \|_______|\|__|\|_______|\|__|    \|__|  \|__|\|__|
Made with love by lily<3
"@ -ForegroundColor Cyan

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Script:Results = @()
$Script:SuspicionLevels = @{
    "Critical" = 4
    "High" = 3
    "Medium" = 2
    "Low" = 1
    "Info" = 0
}

function Get-SysMainStatus {
    try {
        $service = Get-Service -Name "SysMain" -ErrorAction Stop
        return @{
            Status = $service.Status
            Enabled = ($service.StartType -ne "Disabled")
        }
    }
    catch {
        return @{
            Status = "Not Found"
            Enabled = $false
        }
    }
}

function Get-PrefetcherRegistry {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    try {
        $enablePrefetcher = Get-ItemProperty -Path $regPath -Name "EnablePrefetcher" -ErrorAction Stop
        return $enablePrefetcher.EnablePrefetcher
    }
    catch {
        return $null
    }
}

function Get-CurrentBootTime {
    try {
        return (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    }
    catch {
        return (Get-Date).AddDays(-1)
    }
}

function Get-PrefetchFiles {
    $prefetchPath = "$env:SystemRoot\Prefetch"
    try {
        $allFiles = Get-ChildItem -Path $prefetchPath -File -Force -ErrorAction Stop
        $bootTime = Get-CurrentBootTime
        $currentBootFiles = $allFiles | Where-Object { $_.LastWriteTime -gt $bootTime }
        return $currentBootFiles
    }
    catch {
        Write-Warning "Cannot access Prefetch folder: $($_.Exception.Message)"
        return @()
    }
}

function Analyze-PrefetchFile {
    param($File)
    
    $analysis = @{
        FileName = $File.Name
        FullPath = $File.FullName
        Size = $File.Length
        LastWriteTime = $File.LastWriteTime
        Attributes = $File.Attributes
        IsReadOnly = $File.IsReadOnly
        IsHidden = $File.Attributes -band [System.IO.FileAttributes]::Hidden
        SuspicionReasons = @()
        SuspicionLevel = "Info"
        Hash = $null
        ProcessName = $null
        Extension = $null
    }
    
    try {
        $analysis.Hash = (Get-FileHash -Path $File.FullName -Algorithm MD5).Hash
    }
    catch {
        $analysis.Hash = "Unable to calculate"
    }
    
    if ($File.Name -match '^(.+?)\-([A-F0-9]+)\.pf$') {
        $analysis.ProcessName = $matches[1]
        $analysis.Extension = [System.IO.Path]::GetExtension($matches[1])
    }
    
    $suspiciousExtensions = @('.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.com', '.scr', '.pif', '.hta', '.jar', '.ini', '.log', '.tmp', '.dat', '.bin', '.sys', '.ocx', '.cpl')
    
    if ($analysis.IsReadOnly) {
        $analysis.SuspicionReasons += "File is read-only"
    }
    if ($analysis.IsHidden) {
        $analysis.SuspicionReasons += "File is hidden"
    }
    
    if ($analysis.Extension) {
        if ($analysis.Extension -eq "") {
            $analysis.SuspicionReasons += "Process has no extension"
        }
        elseif ($suspiciousExtensions -contains $analysis.Extension.ToLower()) {
            $analysis.SuspicionReasons += "Suspicious process extension: $($analysis.Extension)"
        }
    }
    
    if (-not $analysis.ProcessName) {
        $analysis.SuspicionReasons += "Unable to parse process name from filename"
    }
    
    if ($analysis.Size -lt 1024) {
        $analysis.SuspicionReasons += "Unusually small file size: $($analysis.Size) bytes"
    }
    if ($analysis.Size -gt 104857600) {
        $analysis.SuspicionReasons += "Unusually large file size: $([math]::Round($analysis.Size/1MB,2)) MB"
    }
    
    $suspicionScore = 0
    
    if ($analysis.IsHidden -or $analysis.IsReadOnly) { $suspicionScore += 1 }
    if ($analysis.Extension -eq "" -or ($analysis.Extension -and $suspiciousExtensions -contains $analysis.Extension.ToLower())) { $suspicionScore += 2 }
    if (-not $analysis.ProcessName) { $suspicionScore += 2 }
    if ($analysis.Size -lt 1024 -or $analysis.Size -gt 104857600) { $suspicionScore += 1 }
    
    switch ($suspicionScore) {
        { $_ -ge 3 } { $analysis.SuspicionLevel = "Critical" }
        { $_ -eq 2 } { $analysis.SuspicionLevel = "High" }
        { $_ -eq 1 } { $analysis.SuspicionLevel = "Medium" }
        default { $analysis.SuspicionLevel = "Info" }
    }
    
    return $analysis
}

function Find-DuplicateProcessNames {
    $processGroups = $Script:Results | Group-Object ProcessName | Where-Object { $_.Count -gt 1 -and $_.Name }
    
    $duplicates = @()
    foreach ($group in $processGroups) {
        $hashes = ($group.Group | Where-Object { $_.Hash -ne "Unable to calculate" } | Group-Object Hash)
        if ($hashes.Count -gt 1) {
            $duplicates += @{
                ProcessName = $group.Name
                FileCount = $group.Count
                UniqueHashes = $hashes.Count
                Files = $group.Group
            }
        }
    }
    
    return $duplicates
}

function Show-PrefetchGUI {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Prefetch Anomalies Analyzer"
    $form.Size = New-Object System.Drawing.Size(1200, 700)
    $form.StartPosition = "CenterScreen"
    $form.MaximizeBox = $true
    
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = "Fill"
    
    $summaryTab = New-Object System.Windows.Forms.TabPage
    $summaryTab.Text = "Summary"
    $summaryTab.BackColor = "White"
    
    $sysMainStatus = Get-SysMainStatus
    $prefetcherReg = Get-PrefetcherRegistry
    
    $prefetcherRegText = if ($prefetcherReg -eq $null) { "Not Found" } else { "Value: $prefetcherReg" }
    
    $infoText = @"
SYSTEM INFORMATION:
SysMain Service: $($sysMainStatus.Status) (Enabled: $($sysMainStatus.Enabled))
Prefetcher Registry: $prefetcherRegText
Prefetch Files Analyzed: $($Script:Results.Count)
Current Boot Files Only: Yes

SUSPICION BREAKDOWN:
"@

    $breakdown = $Script:Results | Group-Object SuspicionLevel
    foreach ($level in $breakdown) {
        $count = $level.Count
        $infoText += "$($level.Name): $count files`n"
    }

    $infoText += "`nCRITICAL FINDINGS:`n"

    $criticalFiles = $Script:Results | Where-Object { $_.SuspicionLevel -eq "Critical" }
    if ($criticalFiles.Count -gt 0) {
        foreach ($file in $criticalFiles) {
            $infoText += "$($file.FileName) - $($file.SuspicionReasons -join ', ')`n"
        }
    } else {
        $infoText += "No critical findings detected.`n"
    }
    
    $summaryTextBox = New-Object System.Windows.Forms.RichTextBox
    $summaryTextBox.Location = New-Object System.Drawing.Point(10, 10)
    $summaryTextBox.Size = New-Object System.Drawing.Size(1150, 300)
    $summaryTextBox.Text = $infoText
    $summaryTextBox.ReadOnly = $true
    $summaryTextBox.BackColor = "White"
    $summaryTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Location = New-Object System.Drawing.Point(10, 320)
    $listView.Size = New-Object System.Drawing.Size(1150, 300)
    $listView.View = "Details"
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.MultiSelect = $false
    
    $listView.Columns.Add("Suspicion Level", 100) | Out-Null
    $listView.Columns.Add("Filename", 200) | Out-Null
    $listView.Columns.Add("Process", 150) | Out-Null
    $listView.Columns.Add("Size", 80) | Out-Null
    $listView.Columns.Add("Last Write", 120) | Out-Null
    $listView.Columns.Add("Reasons", 400) | Out-Null
    
    $suspiciousFiles = $Script:Results | Where-Object { $_.SuspicionLevel -ne "Info" } | Sort-Object @{
        Expression = {
            $Script:SuspicionLevels[$_.SuspicionLevel]
        }
        Descending = $true
    }, FileName
    
    foreach ($file in $suspiciousFiles) {
        $item = New-Object System.Windows.Forms.ListViewItem($file.SuspicionLevel)
        
        $processName = if ($file.ProcessName) { $file.ProcessName } else { "Unknown" }
        $sizeText = if ($file.Size) { "$([math]::Round($file.Size/1KB, 1)) KB" } else { "N/A" }
        $lastWrite = if ($file.LastWriteTime) { $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" }
        $reasons = if ($file.SuspicionReasons) { ($file.SuspicionReasons -join "; ") } else { "None" }
        
        $item.SubItems.Add($file.FileName) | Out-Null
        $item.SubItems.Add($processName) | Out-Null
        $item.SubItems.Add($sizeText) | Out-Null
        $item.SubItems.Add($lastWrite) | Out-Null
        $item.SubItems.Add($reasons) | Out-Null
        
        switch ($file.SuspicionLevel) {
            "Critical" { $item.BackColor = "LightCoral" }
            "High" { $item.BackColor = "LightSalmon" }
            "Medium" { $item.BackColor = "LightYellow" }
            "Low" { $item.BackColor = "LightGreen" }
        }
        
        $listView.Items.Add($item) | Out-Null
    }
    
    $summaryTab.Controls.Add($summaryTextBox)
    $summaryTab.Controls.Add($listView)
    
    $detailsTab = New-Object System.Windows.Forms.TabPage
    $detailsTab.Text = "File Details"
    
    $detailsListView = New-Object System.Windows.Forms.ListView
    $detailsListView.Dock = "Fill"
    $detailsListView.View = "Details"
    $detailsListView.FullRowSelect = $true
    $detailsListView.GridLines = $true
    
    $detailsListView.Columns.Add("Property", 150) | Out-Null
    $detailsListView.Columns.Add("Value", 900) | Out-Null
    
    $listView.Add_ItemSelectionChanged({
        if ($listView.SelectedItems.Count -gt 0) {
            $detailsListView.Items.Clear()
            $selectedIndex = $listView.SelectedIndices[0]
            if ($selectedIndex -ge 0 -and $selectedIndex -lt $suspiciousFiles.Count) {
                $selectedFile = $suspiciousFiles[$selectedIndex]
                
                $properties = @(
                    "FileName", "ProcessName", "SuspicionLevel", "Size", "Hash", 
                    "LastWriteTime", "Attributes", "IsReadOnly", "IsHidden", "SuspicionReasons"
                )
                
                foreach ($prop in $properties) {
                    $item = New-Object System.Windows.Forms.ListViewItem($prop)
                    $value = $selectedFile.$prop
                    if ($value -eq $null) {
                        $value = "N/A"
                    }
                    if ($prop -eq "SuspicionReasons") {
                        $value = if ($value) { $value -join " | " } else { "None" }
                    } elseif ($prop -eq "Size") {
                        $value = if ($value) { "$value bytes ($([math]::Round($value/1KB, 1)) KB)" } else { "N/A" }
                    }
                    $item.SubItems.Add($value.ToString()) | Out-Null
                    $detailsListView.Items.Add($item) | Out-Null
                }
            }
        }
    })
    
    $detailsTab.Controls.Add($detailsListView)
    
    $duplicatesTab = New-Object System.Windows.Forms.TabPage
    $duplicatesTab.Text = "Duplicate Processes"
    
    $duplicatesListView = New-Object System.Windows.Forms.ListView
    $duplicatesListView.Dock = "Fill"
    $duplicatesListView.View = "Details"
    $duplicatesListView.FullRowSelect = $true
    $duplicatesListView.GridLines = $true
    
    $duplicatesListView.Columns.Add("Process Name", 200) | Out-Null
    $duplicatesListView.Columns.Add("File Count", 80) | Out-Null
    $duplicatesListView.Columns.Add("Unique Hashes", 100) | Out-Null
    $duplicatesListView.Columns.Add("Files", 600) | Out-Null
    
    $duplicates = Find-DuplicateProcessNames
    foreach ($dup in $duplicates) {
        $item = New-Object System.Windows.Forms.ListViewItem($dup.ProcessName)
        $item.SubItems.Add($dup.FileCount.ToString()) | Out-Null
        $item.SubItems.Add($dup.UniqueHashes.ToString()) | Out-Null
        $item.SubItems.Add(($dup.Files.FileName -join "; ")) | Out-Null
        $item.BackColor = "LightCoral"
        $duplicatesListView.Items.Add($item) | Out-Null
    }
    
    if ($duplicates.Count -eq 0) {
        $item = New-Object System.Windows.Forms.ListViewItem("No duplicate processes with different hashes found")
        $duplicatesListView.Items.Add($item) | Out-Null
    }
    
    $duplicatesTab.Controls.Add($duplicatesListView)
    
    $tabControl.TabPages.Add($summaryTab)
    $tabControl.TabPages.Add($detailsTab)
    $tabControl.TabPages.Add($duplicatesTab)
    
    $form.Controls.Add($tabControl)
    
    $form.ShowDialog() | Out-Null
}

Write-Host "Prefetch Anomalies Analyzer" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Warning "Some features may require administrator privileges. Consider running as Administrator."
}

Write-Host "`n[1/4] Checking system configuration..." -ForegroundColor Yellow
$sysMainStatus = Get-SysMainStatus
$prefetcherReg = Get-PrefetcherRegistry

Write-Host "SysMain Service: $($sysMainStatus.Status) (Enabled: $($sysMainStatus.Enabled))"
Write-Host "Prefetcher Registry Value: $(if ($prefetcherReg -eq $null) { 'Not Found' } else { $prefetcherReg })"

Write-Host "`n[2/4] Scanning prefetch files from current boot only..." -ForegroundColor Yellow
$prefetchFiles = Get-PrefetchFiles
Write-Host "Found $($prefetchFiles.Count) prefetch files from current boot"

Write-Host "`n[3/4] Analyzing files for anomalies..." -ForegroundColor Yellow
$progress = 0
foreach ($file in $prefetchFiles) {
    $progress++
    Write-Progress -Activity "Analyzing Prefetch Files" -Status "Processing $($file.Name)" -PercentComplete (($progress / $prefetchFiles.Count) * 100)
    $Script:Results += Analyze-PrefetchFile -File $file
}
Write-Progress -Activity "Analyzing Prefetch Files" -Completed

$criticalCount = ($Script:Results | Where-Object { $_.SuspicionLevel -eq "Critical" }).Count
$highCount = ($Script:Results | Where-Object { $_.SuspicionLevel -eq "High" }).Count
$mediumCount = ($Script:Results | Where-Object { $_.SuspicionLevel -eq "Medium" }).Count
$lowCount = ($Script:Results | Where-Object { $_.SuspicionLevel -eq "Low" }).Count

Write-Host "`n[4/4] Analysis Complete!" -ForegroundColor Green
Write-Host "Suspicion Breakdown:" -ForegroundColor Cyan
Write-Host "  Critical: $criticalCount" -ForegroundColor Red
Write-Host "  High: $highCount" -ForegroundColor Yellow
Write-Host "  Medium: $mediumCount" -ForegroundColor Magenta
Write-Host "  Low: $lowCount" -ForegroundColor Blue
Write-Host "  Info: $(($Script:Results | Where-Object { $_.SuspicionLevel -eq "Info" }).Count)" -ForegroundColor Gray

Write-Host "`nOpening GUI interface..." -ForegroundColor Yellow
Show-PrefetchGUI

Write-Host "`nAnalysis complete. Check the GUI for detailed results." -ForegroundColor Green
