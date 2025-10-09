Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# servicess
$servicesToCheck = @(
    "SysMain","PcaSvc","DPS","EventLog","Schedule","Bam","wsearch",
    "Appinfo","SSDPSRV","CDPSvc","DcomLaunch","PlugPlay"
)

# buildin
$form = New-Object System.Windows.Forms.Form
$form.Text = "Service Checker"
$form.Size = New-Object System.Drawing.Size(500,400)
$form.StartPosition = "CenterScreen"

# building2
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Size = New-Object System.Drawing.Size(460,280)
$listBox.Location = New-Object System.Drawing.Point(10,10)
$form.Controls.Add($listBox)

# button to enable
$buttonEnable = New-Object System.Windows.Forms.Button
$buttonEnable.Text = "Enable Selected"
$buttonEnable.Size = New-Object System.Drawing.Size(460,30)
$buttonEnable.Location = New-Object System.Drawing.Point(10,300)
$form.Controls.Add($buttonEnable)

# list serv
function Refresh-List {
    $listBox.Items.Clear()
    foreach ($serviceName in $servicesToCheck) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            $status = $service.Status
            $startup = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
            $listBox.Items.Add("$serviceName - Status: $status - Startup: $startup")
        } else {
            $listBox.Items.Add("$serviceName - Not Found")
        }
    }
}

# start services
$buttonEnable.Add_Click({
    foreach ($item in $listBox.SelectedItems) {
        $serviceName = ($item -split " -")[0]
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            try {
                Set-Service -Name $serviceName -StartupType Automatic
                if ($service.Status -ne 'Running') {
                    Start-Service -Name $serviceName
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to start $serviceName. Run as Administrator.", "Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
    Refresh-List
})


Refresh-List


[void]$form.ShowDialog()
