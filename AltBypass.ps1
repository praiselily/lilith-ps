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
Write-Host ""
Write-Host ""

Write-Host "Alt bypass for minecraft" -ForegroundColor Cyan
Write-Host ""
Write-Host "this script will only delete alts from common clients, and is created for 1.8 versions of minecraft. Though it will work on later versions as well" -ForegroundColor Yellow
Write-Host ""

$username = $env:USERNAME
$pathsToClean = @(
    "C:\Users\$username\.lunarclient\profiles",
    "C:\Users\$username\.lunarclient\profiles",
    "C:\Users\$username\.lunarclient\settings",
    "C:\Users\$username\AppData\Roaming\.minecraft\logs",
    "C:\Users\$username\AppData\Roaming\.minecraft\usercache.json",
    "C:\Users\$username\AppData\Roaming\Badlion Client\logs\launcher",
    "C:\Users\$username\AppData\Roaming\Badlion Client\accounts.dat",
    "C:\Users\$username\AppData\Roaming\.minecraft\launcher_accounts.json",
    "C:\Users\$username\AppData\Roaming\.minecraft\launcher_profiles.json",
    "C:\Users\$username\AppData\Roaming\.minecraft\options.txt",
    "C:\Users\$username\AppData\Roaming\.minecraft\BLClient\accounts.json",
    "C:\Users\$username\AppData\Roaming\.tlauncher\accounts.json",
    "C:\Users\$username\AppData\Roaming\.technic\",
    "C:\Users\$username\AppData\Roaming\PrismLauncher\accounts.json",
    "C:\Users\$username\AppData\Roaming\MultiMC\accounts.json"
)

$deletedCount = 0
$notFoundCount = 0

Write-Host "deleting account instances" -ForegroundColor Green
Write-Host ""
foreach ($path in $pathsToClean) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host "" -ForegroundColor Green
            $deletedCount++
        }
        catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        $notFoundCount++
    }
}

$xboxPackages = Get-ChildItem "C:\Users\$username\AppData\Local\Packages\" -Filter "Microsoft.XboxApp*" -ErrorAction SilentlyContinue

if ($xboxPackages) {
    foreach ($package in $xboxPackages) {
        try {
            Remove-Item -Path $package.FullName -Recurse -Force -ErrorAction Stop
            $deletedCount++
        }
        catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Finished" -ForegroundColor Cyan
Write-Host "folders and locations deleted: $deletedCount" -ForegroundColor Green
Write-Host ""

$response = Read-Host "Would you like to clear the USN Journal? (yes/no)"

if ($response -eq "yes" -or $response -eq "y") {
    Write-Host ""
    Write-Host "Clearing USN Journal..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "fsutil" -ArgumentList "usn", "deletejournal", "/d", "C:" -Verb RunAs -Wait
        Write-Host "USN Journal cleared" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to clear USN Journal. Run this script with admin priv." -ForegroundColor Red
    }
}
else {
    Write-Host "USN Journal was not cleared." -ForegroundColor Yellow
}

Write-Host ""

$eventResponse = Read-Host "Would you like to clear Windows Event Logs? (yes/no)"

if ($eventResponse -eq "yes" -or $eventResponse -eq "y") {
    Write-Host ""
    Write-Host "Clearing Event Logs..." -ForegroundColor Yellow
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }
        $clearedCount = 0
        
        foreach ($log in $logs) {
            try {
                wevtutil cl $log.LogName
                $clearedCount++
            }
            catch {
            }
        }
        
        Write-Host "Event Logs cleared ($clearedCount logs)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to clear Event Logs. Run this script with admin priv." -ForegroundColor Red
    }
}
else {
    Write-Host "Event Logs were not cleared." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "remember to reset your pc before playing" -ForegroundColor Red -BackgroundColor White
Write-Host ""
Write-Host "hit up @praiselily if you run into any issues" -ForegroundColor Green
Write-Host "Press any key to exit"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
