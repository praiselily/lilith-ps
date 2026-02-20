# query
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class DeviceResolver
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);
}
'@ -ErrorAction Stop

 map
function Build-DeviceMap {
    $map = @{}
    foreach ($letter in [char[]](65..90 | ForEach-Object { [char]$_ })) {
        $drive = "${letter}:"
        $sb    = [System.Text.StringBuilder]::new(260)
        if ([DeviceResolver]::QueryDosDevice($drive, $sb, $sb.Capacity) -ne 0) {
            $device = $sb.ToString()
            if (-not $map.ContainsKey($device)) {
                $map[$device] = $drive
            }
        }
    }
    return $map
}

function Convert-DevicePath {
    param([string]$Path, [hashtable]$Map)
    foreach ($kv in $Map.GetEnumerator()) {
        if ($Path.StartsWith($kv.Key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $kv.Value + $Path.Substring($kv.Key.Length)
        }
    }
    return $null
}

# exe extract
function Extract-DevicePaths {
    param([string]$Line)

    $paths      = [System.Collections.Generic.List[string]]::new()
    $normalised = $Line -replace '(?i)\b[A-Za-z]?\\HarddiskVolume', '\Device\HarddiskVolume'

    $regex = [System.Text.RegularExpressions.Regex]::new(
        '(?i)\\Device\\HarddiskVolume\d+\\[^\x00-\x1F"<>|:*?\r\n]+?\.exe',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    foreach ($match in $regex.Matches($normalised)) {
        $paths.Add($match.Value)
    }

    return $paths
}

Write-Host ""
Write-Host "  Hard Disk Converter" -ForegroundColor Cyan
Write-Host "  ==================" -ForegroundColor Cyan
Write-Host ""

do {
    $inputDir = Read-Host "  Enter the directory containing diskpaths.txt"
    $inputDir = $inputDir.Trim().Trim('"')

    if (-not (Test-Path $inputDir -PathType Container)) {
        Write-Host "  [!] Directory not found, please try again.`n" -ForegroundColor Red
        $validDir = $false
    } else {
        $validDir = $true
    }
} while (-not $validDir)

$inputFile = Join-Path $inputDir "diskpaths.txt"

if (-not (Test-Path $inputFile)) {
    Write-Host ""
    Write-Host "  [!] Could not find diskpaths.txt in: $inputDir" -ForegroundColor Red
    Write-Host "  Make sure the file is named exactly 'diskpaths.txt' and try again." -ForegroundColor Red
    Write-Host ""
    pause
    exit 1
}

Write-Host ""
Write-Host "  [+] Found: $inputFile" -ForegroundColor Green

$outputFile = Join-Path $inputDir "paths.txt"

# device map
Write-Host "  Resolving drive letters..." -ForegroundColor Cyan
$deviceMap = Build-DeviceMap
Write-Host ""
Write-Host "  Processing diskpaths.txt..." -ForegroundColor Cyan
$lines      = [System.IO.File]::ReadAllLines($inputFile)
$resolved   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$unresolved = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($line in $lines) {
    $devicePaths = Extract-DevicePaths -Line $line
    foreach ($dp in $devicePaths) {
        $dos = Convert-DevicePath -Path $dp -Map $deviceMap
        if ($dos) {
            $resolved.Add($dos)  | Out-Null
        } else {
            $unresolved.Add($dp) | Out-Null
        }
    }
}
$sortedResolved = $resolved | Sort-Object
[System.IO.File]::WriteAllLines($outputFile, $sortedResolved)

Write-Host ""
Write-Host "  - $($resolved.Count) unique path(s) resolved." -ForegroundColor Green
Write-Host "   Saved to: $outputFile" -ForegroundColor Green

Write-Host ""
Write-Host ""
Write-Host " Message @praiselily if u run into any issues"

if ($unresolved.Count -gt 0) {
    Write-Host ""
    Write-Host "  [!] $($unresolved.Count) path(s) could not be resolved (volume not mounted):" -ForegroundColor Yellow
    foreach ($u in $unresolved | Sort-Object) {
        Write-Host "      $u" -ForegroundColor DarkYellow
    }
}

Write-Host ""
pause
