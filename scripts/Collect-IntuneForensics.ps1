<#
.SYNOPSIS
    Tier-1 forensic collector for the "Advanced Intune Troubleshooting" (go rudy this) skill.

.DESCRIPTION
    Takes a read-only snapshot of the Intune evidence this device leaves behind and
    writes it to a bundle folder for analysis. Collects the Intune Management Extension
    logs, the relevant registry hives (IME, Enrollments, Provisioning/OMADM,
    PolicyManager), the MDM certificate state, scheduled tasks, services, device join
    state (dsregcmd), recent event logs from the management channels, the IME version
    and assembly inventory, and a summary.md that orients the analysis.

    Read-only: it does not modify device state. Uses only free, built-in tooling. Run
    elevated (administrator, or SYSTEM via Intune) for full access to logs, HKLM, and
    the certificate store.

.PARAMETER OutputPath
    Folder to write the bundle to. Defaults to a timestamped folder under %TEMP%.

.PARAMETER EventLogDays
    How many days of event-log history to pull. Default 7.

.PARAMETER MaxEventsPerChannel
    Cap on events pulled per channel, to keep the bundle readable. Default 2000.

.OUTPUTS
    Prints the bundle path. Point the skill at that folder (start with summary.md).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:TEMP ("RudyForensics_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [int]$EventLogDays = 7,
    [int]$MaxEventsPerChannel = 2000
)

$ErrorActionPreference = 'Continue'

# ----- Bundle layout -----
$logDir = Join-Path $OutputPath 'ime-logs'
$regDir = Join-Path $OutputPath 'registry'
$evtDir = Join-Path $OutputPath 'eventlogs'
foreach ($d in @($OutputPath, $logDir, $regDir, $evtDir)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
$collectionLog = Join-Path $OutputPath 'collection.log'

function Write-Step {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Add-Content -Path $collectionLog -Value $line
    Write-Host $line
}

# ----- Context -----
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.User.Value -eq 'S-1-5-18'
Write-Step ("Advanced Intune Troubleshooting forensic collector. Admin={0} System={1}" -f $isAdmin, $isSystem)
Write-Step ("Bundle: {0}" -f $OutputPath)
if (-not $isAdmin -and -not $isSystem) {
    Write-Step "Not elevated. Some IME logs, HKLM hives, and certificate private-key data may be inaccessible." 'WARN'
}

# ----- 1. IME logs (the primary timeline) -----
try {
    $imeLogPath = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
    if (Test-Path $imeLogPath) {
        Copy-Item -Path (Join-Path $imeLogPath '*') -Destination $logDir -Recurse -Force -ErrorAction Stop
        $count = (Get-ChildItem $logDir -File -Recurse -ErrorAction SilentlyContinue).Count
        Write-Step "IME logs copied ($count file(s))."
    } else {
        Write-Step "IME log folder not found: $imeLogPath (device may not be Intune-managed, or IME not installed)." 'WARN'
    }
} catch { Write-Step "IME logs failed: $($_.Exception.Message)" 'WARN' }

# ----- 2. Registry hives -----
$regTargets = @(
    @{ Name = 'IntuneManagementExtension'; Key = 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension' }
    @{ Name = 'Enrollments';               Key = 'HKLM\SOFTWARE\Microsoft\Enrollments' }
    @{ Name = 'Provisioning';              Key = 'HKLM\SOFTWARE\Microsoft\Provisioning' }
    @{ Name = 'PolicyManager-device';      Key = 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device' }
    @{ Name = 'EnterpriseResourceManager'; Key = 'HKLM\SOFTWARE\Microsoft\EnterpriseResourceManager' }
)
foreach ($t in $regTargets) {
    $outFile = Join-Path $regDir ($t.Name + '.reg')
    try {
        $null = reg.exe export $t.Key $outFile /y 2>$null
        if (Test-Path $outFile) { Write-Step "Registry exported: $($t.Name)" }
        else { Write-Step "Registry key absent or unreadable: $($t.Key)" 'WARN' }
    } catch { Write-Step "Registry export failed for $($t.Name): $($_.Exception.Message)" 'WARN' }
}

# ----- 3. MDM certificate (the Last Check-in tell) -----
try {
    $now  = Get-Date
    $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop
    $mdm = $certs | Where-Object { $_.Issuer -match 'Intune MDM' }
    $mdm | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey,
        @{ n = 'DaysToExpiry'; e = { [math]::Round(($_.NotAfter - $now).TotalDays, 1) } },
        @{ n = 'Expired';      e = { $_.NotAfter -lt $now } } |
        Format-List | Out-File (Join-Path $OutputPath 'mdm-certificate.txt') -Encoding utf8
    $certs | Select-Object Subject, Issuer, NotAfter, HasPrivateKey, Thumbprint |
        Out-File (Join-Path $OutputPath 'localmachine-my-certs.txt') -Encoding utf8
    Write-Step ("MDM certificate(s) captured: {0}" -f (@($mdm).Count))
} catch { Write-Step "Certificate capture failed: $($_.Exception.Message)" 'WARN' }

# ----- 4. Device join state -----
try {
    dsregcmd /status 2>$null | Out-File (Join-Path $OutputPath 'dsregcmd-status.txt') -Encoding utf8
    Write-Step "dsregcmd /status captured."
} catch { Write-Step "dsregcmd failed: $($_.Exception.Message)" 'WARN' }

# ----- 5. Scheduled tasks (EnterpriseMgmt / sync) -----
try {
    $tasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue
    $rows = foreach ($task in $tasks) {
        $info = $null
        try { $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
        [pscustomobject]@{
            TaskPath    = $task.TaskPath
            TaskName    = $task.TaskName
            State       = $task.State
            LastRunTime = $info.LastRunTime
            NextRunTime = $info.NextRunTime
            LastResult  = $info.LastTaskResult
        }
    }
    $rows | Format-Table -AutoSize | Out-File (Join-Path $OutputPath 'scheduled-tasks-enterprisemgmt.txt') -Encoding utf8 -Width 4096
    Write-Step ("EnterpriseMgmt scheduled tasks captured: {0}" -f (@($tasks).Count))
} catch { Write-Step "Scheduled task capture failed: $($_.Exception.Message)" 'WARN' }

# ----- 6. Services -----
try {
    $patterns = @('IntuneManagementExtension', 'dmwappushservice', 'DmEnrollmentSvc', 'wlidsvc', 'WpnService')
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object { $n = $_.Name; ($patterns | Where-Object { $n -like "$_*" }) } |
        Select-Object Name, State, StartMode, StartName, PathName |
        Format-List | Out-File (Join-Path $OutputPath 'services.txt') -Encoding utf8
    Write-Step "Relevant services captured."
} catch { Write-Step "Service capture failed: $($_.Exception.Message)" 'WARN' }

# ----- 7. IME version + assembly inventory (Tier-3 reference) -----
try {
    $imeDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension'
    if (Test-Path $imeDir) {
        $lines = @()
        $imeExe = Join-Path $imeDir 'Microsoft.Management.Services.IntuneWindowsAgent.exe'
        if (Test-Path $imeExe) { $lines += "IME agent: $((Get-Item $imeExe).VersionInfo.FileVersion)  ($imeExe)" }
        $lines += ''
        $lines += 'SideCar assemblies (for Tier-3 decompilation reference):'
        Get-ChildItem $imeDir -Filter *.dll -ErrorAction SilentlyContinue |
            ForEach-Object { $lines += ("  {0}  {1}" -f $_.Name, $_.VersionInfo.FileVersion) }
        $lines | Out-File (Join-Path $OutputPath 'ime-version.txt') -Encoding utf8
        Write-Step "IME version and assembly inventory captured."
    } else { Write-Step "IME install dir not found: $imeDir" 'WARN' }
} catch { Write-Step "IME version capture failed: $($_.Exception.Message)" 'WARN' }

# ----- 8. Event logs (management channels). Absence is evidence: log what is missing. -----
$since = (Get-Date).AddDays(-1 * [math]::Abs($EventLogDays))
$channels = @(
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
    'Microsoft-Windows-AAD/Operational'
    'Microsoft-Windows-User Device Registration/Admin'
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot'
    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Diagnostics'
    'Microsoft-Windows-Shell-Core/Operational'
    'Microsoft-Windows-PushNotification-Platform/Operational'
    'Microsoft-Windows-AppXDeploymentServer/Operational'
)
foreach ($ch in $channels) {
    $safeName = ($ch -replace '[\\/ ]', '_')
    $outFile = Join-Path $evtDir ($safeName + '.csv')
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $ch; StartTime = $since } -MaxEvents $MaxEventsPerChannel -ErrorAction Stop
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv -Path $outFile -NoTypeInformation -Encoding utf8
        Write-Step ("Event log {0}: {1} event(s)" -f $ch, @($events).Count)
    } catch {
        Write-Step ("Event log {0}: none (absent, disabled, or no events in window)" -f $ch)
    }
}

# ----- 9. System info -----
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    [pscustomobject]@{
        ComputerName = $cs.Name
        Domain       = $cs.Domain
        OS           = $os.Caption
        Version      = $os.Version
        Build        = $os.BuildNumber
        InstallDate  = $os.InstallDate
        LastBoot     = $os.LastBootUpTime
        CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    } | Format-List | Out-File (Join-Path $OutputPath 'system-info.txt') -Encoding utf8
    Write-Step "System info captured."
} catch { Write-Step "System info failed: $($_.Exception.Message)" 'WARN' }

# ----- 10. Summary -----
try {
    $now = Get-Date
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    $imeVer = 'unknown'
    $imeExe = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe'
    if (Test-Path $imeExe) { $imeVer = (Get-Item $imeExe).VersionInfo.FileVersion }

    $mdm = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Issuer -match 'Intune MDM' } | Sort-Object NotAfter -Descending | Select-Object -First 1
    $certLine = 'No Intune MDM certificate found in LocalMachine\My.'
    if ($mdm) {
        $days  = [math]::Round(($mdm.NotAfter - $now).TotalDays, 1)
        $state = if ($mdm.NotAfter -lt $now) { "EXPIRED $([math]::Abs($days)) day(s) ago" } else { "valid, $days day(s) left" }
        $certLine = "Intune MDM cert NotAfter $($mdm.NotAfter), HasPrivateKey $($mdm.HasPrivateKey), $state."
    }

    $dsFile = Join-Path $OutputPath 'dsregcmd-status.txt'
    $joinFlags = @()
    if (Test-Path $dsFile) {
        foreach ($pat in 'AzureAdJoined', 'EnterpriseJoined', 'DomainJoined', 'MdmUrl', 'TenantName') {
            $m = Select-String -Path $dsFile -Pattern ("^\s*{0}\s*:" -f $pat) -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($m) { $joinFlags += '  ' + $m.Line.Trim() }
        }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Advanced Intune Troubleshooting - forensic bundle')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Read this first, then dig into the files referenced below.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Device')
    [void]$sb.AppendLine(('- Computer: {0}' -f $(if ($cs) { $cs.Name } else { $env:COMPUTERNAME })))
    [void]$sb.AppendLine(('- OS: {0} (build {1})' -f $(if ($os) { $os.Caption } else { '?' }), $(if ($os) { $os.BuildNumber } else { '?' })))
    [void]$sb.AppendLine(('- IME agent version: {0}' -f $imeVer))
    [void]$sb.AppendLine(('- Collected (UTC): {0}' -f $now.ToUniversalTime().ToString('o')))
    [void]$sb.AppendLine(('- Elevated: admin={0} system={1}' -f $isAdmin, $isSystem))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Join state (from dsregcmd-status.txt)')
    if ($joinFlags.Count) { $joinFlags | ForEach-Object { [void]$sb.AppendLine($_) } } else { [void]$sb.AppendLine('  (see dsregcmd-status.txt)') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## MDM certificate (the Last Check-in tell)')
    [void]$sb.AppendLine('- ' + $certLine)
    [void]$sb.AppendLine('- Full detail: mdm-certificate.txt')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## What is in this bundle')
    [void]$sb.AppendLine('- ime-logs\   : Intune Management Extension logs (the primary timeline)')
    [void]$sb.AppendLine('- registry\   : IME, Enrollments, Provisioning/OMADM, PolicyManager hives (.reg)')
    [void]$sb.AppendLine('- eventlogs\  : management event channels (CSV). Note which are absent: absence is evidence')
    [void]$sb.AppendLine('- dsregcmd-status.txt, mdm-certificate.txt, scheduled-tasks-enterprisemgmt.txt,')
    [void]$sb.AppendLine('  services.txt, ime-version.txt, system-info.txt, collection.log')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Pointers for the analysis')
    [void]$sb.AppendLine('- OMA-DM last contact: decode the AcctInfo blob (ServerLastSuccessTime) under')
    [void]$sb.AppendLine('  HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts in registry\Provisioning.reg.')
    [void]$sb.AppendLine('- Script/remediation scheduling: read LastExecution under')
    [void]$sb.AppendLine('  ...IntuneManagementExtension\SideCarPolicies\Scripts\Execution in registry\IntuneManagementExtension.reg.')
    [void]$sb.AppendLine('- Reported vs actual: compare the portal Last Check-in to the MDM cert expiry above.')
    $sb.ToString() | Out-File (Join-Path $OutputPath 'summary.md') -Encoding utf8
    Write-Step "Summary written: summary.md"
} catch { Write-Step "Summary generation failed: $($_.Exception.Message)" 'WARN' }

Write-Step "Collection complete."
Write-Host ''
Write-Host ("Bundle ready: {0}" -f $OutputPath)
Write-Host "Point the skill at that folder (start with summary.md)."
