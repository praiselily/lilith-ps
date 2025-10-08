# List of services to check
$servicesToCheck = @(
    "SysMain",
    "PcaSvc",
    "DPS",
    "EventLog",
    "Schedule",
    "Bam",
    "wsearch",
    "Appinfo",
    "SSDPSRV",
    "CDPSvc",
    "DcomLaunch",
    "PlugPlay"
)

foreach ($serviceName in $servicesToCheck) {
    # Get service status
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service) {
        if ($service.Status -ne 'Running') {
            Write-Host "Service '$serviceName' is currently $($service.Status)."

            # Prompt user to enable
            $response = Read-Host "Do you want to start and set '$serviceName' to Automatic? (Y/N)"
            if ($response -match '^[Yy]$') {
                try {
                    # Change startup type to Automatic
                    Set-Service -Name $serviceName -StartupType Automatic

                    # Start the service if not running
                    Start-Service -Name $serviceName
                    Write-Host "'$serviceName' has been started and set to Automatic."
                } catch {
                    Write-Warning "Failed to start or set '$serviceName'. You might need to run this script as Administrator."
                }
            }
        } else {
            Write-Host "Service '$serviceName' is running."
        }
    } else {
        Write-Warning "Service '$serviceName' not found on this system."
    }
}
