# ShellSearch - by praiselily
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "Run as Administrator." -ForegroundColor Red; exit
}

Write-Host ""
Write-Host "  ShellSearch - by praiselily" -ForegroundColor Cyan
Write-Host ""

$targetLogs = @(
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell"
)

function J { $args -join '' }

$literals = @(
    (J 'amsi' 'InitFailed'),
    (J 'Amsi' 'Utils'),
    (J 'Amsi' 'Scan' 'Buffer'),
    (J 'etw' 'Event' 'Write'),
    (J 'Disable' 'Realtime' 'Monitoring'),
    (J 'Exclusion' 'Path'),
    (J 'Execution' 'Policy' ' Bypass'),
    (J '-ep' ' bypass'),
    (J 'Window' 'Style' ' Hidden'),
    (J '-w' ' hidden'),
    (J 'Encoded' 'Command'),
    (J 'Invoke' '-Web' 'Request'),
    (J 'Invoke' '-Rest' 'Method'),
    (J 'Start' '-Bits' 'Transfer'),
    (J 'Net.' 'Web' 'Client'),
    (J 'Down' 'load' 'String'),
    (J 'Down' 'load' 'File'),
    (J 'Down' 'load' 'Data'),
    (J 'Net.Http.' 'Http' 'Client'),
    (J 'Net.Sockets.' 'Tcp' 'Client'),
    (J 'Invoke' '-Expre' 'ssion'),
    (J 'Reflection' '.' 'Assembly'),
    (J 'Virtual' 'Alloc'),
    (J 'Write' 'Process' 'Memory'),
    (J 'Ptr' 'To' 'Structure'),
    (J 'GC' 'Handle'),
    (J 'Addr' 'Of' 'Pinned' 'Object'),
    (J 'Runtime.Interop' 'Services.' 'Marshal'),
    (J 'ASCII' 'Encoding'),
    (J 'Add' '-Type'),
    (J 'logon' 'pass' 'words'),
    (J 'sekur' 'lsa'),
    (J 'Invoke' '-Mimi' 'katz'),
    (J 'Current' 'Version' '\Run'),
    (J 'New-' 'Scheduled' 'Task'),
    (J 'Invoke' '-Wmi' 'Method'),
    (J 'Win32' '_Process'),
    (J '[array]' '::Reverse'),
    (J '[ch' 'ar]'),
    (J '$env' ':ComSpec'),
    (J 'Compress' '-Archive'),
    (J 'Import' '-Module'),
    (J 'ms' 'hta'),
    (J 'run' 'dll32'),
    (J 'reg' 'svr32'),
    (J 'ws' 'cript'),
    (J 'cs' 'cript'),
    (J 'wm' 'ic'),
    (J 'cert' 'util'),
    (J 'bits' 'admin'),
    (J 'install' 'util'),
    (J 'reg' 'asm'),
    (J 'reg' 'svcs'),
    (J 'msi' 'exec'),
    (J 'odbc' 'conf'),
    (J 'for' 'files'),
    (J 'Write' 'All' 'Bytes'),
    (J 'java' ' -jar'),
    (J 'git' 'hub.com'),
    'webhook',
    '.bat'
)
$rawRegex = @('\biwr\b', '\bwget\b', '\bcurl\b', '\birm\b', '\biex\b')
$escaped  = $literals | ForEach-Object { [regex]::Escape($_) }
$regex    = ($escaped + $rawRegex) -join '|'

$noiseList = @(
    # PS pipeline metadata
    '^\$__cmdletization',
    '^ParameterBinding\(',
    '^CommandInvocation\(',
    '^TerminatingError\(',
    '^Sequence Number\s*=\s*\d+$',
    '^(Context|User|Computer)\s*=',
    '^\$PSBoundParameters',
    '^\[object\]\$__',
    '^\$\{Disable',
    '^\$\{Exclusion',
    '^\${',
    "^'[^']{1,60}',?\s*$",
    '^\(J\s+''',
    '^\$t_[a-z]+\s*=',
    '^\$escaped\s*=',
    '^\$regex\s*=',
    '^\$literals\s*=',
    '^\$rawRegex\s*=',

    # Continuation fragments of cmdletization blocks
    '; IsValuePresent',
    'IsValuePresent\s*=\s*\$__cmdletization'
)

$noiseRegex = $noiseList -join '|'

$prefixRegex = '^(HostApplication\s*=\s*|Host Application\s*=\s*|CommandLine\s*=\s*|Pipeline execution details for command line:\s*|Command Name\s*=\s*)'

Write-Host "Scanning PowerShell event logs..." -ForegroundColor Cyan

$seen    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$results = [System.Collections.Generic.List[string]]::new()

foreach ($log in $targetLogs) {
    try {
        $events = Get-WinEvent -LogName $log -ErrorAction Stop
    } catch { continue }

    Write-Host "  $log — $($events.Count) events" -ForegroundColor DarkGray

    foreach ($evt in $events) {
        $raw = $evt.Message
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw -notmatch $regex)               { continue }

        foreach ($rawLine in ($raw -split "`r?`n")) {
            $line = $rawLine.Trim()
            if ($line.Length -lt 6)      { continue }
            if ($line -notmatch $regex)   { continue }
            if ($line -match $noiseRegex) { continue }

            $line = $line -replace $prefixRegex, ''
            $line = $line.Trim()

            if ($line.Length -lt 6)      { continue }
            if ($line -match $noiseRegex) { continue }  # re-check after prefix strip

            $key = $line -replace '\s+', ' '
            if ($seen.Add($key)) { $results.Add($line) }
        }
    }
}

if ($results.Count -eq 0) {
    Write-Host "`nNothing found." -ForegroundColor Green
    exit
}
$out = Join-Path $env:TEMP "ShellSearch_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt"
[System.IO.File]::WriteAllText($out, ($results -join "`r`n`r`n"), [System.Text.Encoding]::UTF8)

Write-Host "`n$($results.Count) unique hits — opening report..." -ForegroundColor Yellow
Start-Process notepad.exe $out
