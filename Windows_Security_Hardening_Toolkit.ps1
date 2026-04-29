<#
.SYNOPSIS
    Interactive Windows Security Audit + Safe Hardening Toolkit

.DESCRIPTION
    This script audits common Windows security settings and optionally applies safe hardening changes.
    It asks before making each change.

    It does NOT:
    - Delete files
    - Remove users
    - Uninstall software
    - Delete scheduled tasks
    - Enable BitLocker automatically
    - Disable random services

.NOTES
    Run PowerShell as Administrator.
#>

# ==============================
# INITIAL SETUP
# ==============================

$ErrorActionPreference = "Continue"

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportDir = "$env:USERPROFILE\Desktop\Windows_Security_Hardening_Report_$Timestamp"
$SummaryFile = "$ReportDir\Security_Summary.txt"
$FullReportFile = "$ReportDir\Security_Full_Report.txt"
$RiskCsv = "$ReportDir\Risk_Findings.csv"

New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$RiskFindings = @()
$ActionsTaken = @()
$ActionsSkipped = @()

function Write-Header {
    param([string]$Title)

    $line = "`n============================================================"
    $output = @(
        $line
        $Title
        $line
    )

    foreach ($item in $output) {
        Write-Host $item
        Add-Content -Path $FullReportFile -Value $item
    }
}

function Write-Info {
    param([string]$Text)

    Write-Host $Text
    Add-Content -Path $FullReportFile -Value $Text
}

function Add-Finding {
    param(
        [string]$Id,
        [string]$Severity,
        [string]$Category,
        [string]$Finding,
        [string]$Evidence,
        [string]$Recommendation
    )

    $global:RiskFindings += [PSCustomObject]@{
        ID             = $Id
        Severity       = $Severity
        Category       = $Category
        Finding        = $Finding
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
}

function Confirm-Action {
    param([string]$Question)

    while ($true) {
        $answer = Read-Host "$Question [Y/N]"
        switch ($answer.ToUpper()) {
            "Y" { return $true }
            "N" { return $false }
            default { Write-Host "Please enter Y or N." }
        }
    }
}

function Record-Action {
    param(
        [string]$Action,
        [string]$Status
    )

    if ($Status -eq "Taken") {
        $global:ActionsTaken += $Action
    } else {
        $global:ActionsSkipped += $Action
    }
}

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==============================
# ADMIN CHECK
# ==============================

if (-not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "ERROR: Please run PowerShell as Administrator."
    Write-Host "Right-click PowerShell > Run as administrator, then run this script again."
    exit
}

Clear-Host

Write-Header "WINDOWS SECURITY AUDIT + SAFE HARDENING TOOLKIT"
Write-Info "Generated: $(Get-Date)"
Write-Info "Computer Name: $env:COMPUTERNAME"
Write-Info "User: $env:USERNAME"
Write-Info "Report Folder: $ReportDir"

# ==============================
# CREATE RESTORE POINT
# ==============================

Write-Header "0. SYSTEM RESTORE POINT"

try {
    $restoreEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue

    if (Confirm-Action "Create a system restore point before making changes?") {
        try {
            Checkpoint-Computer -Description "Before Windows Security Hardening $Timestamp" -RestorePointType "MODIFY_SETTINGS"
            Write-Info "Restore point creation attempted successfully."
            Record-Action "Created system restore point" "Taken"
        } catch {
            Write-Info "Could not create restore point. This may happen if System Protection is disabled."
            Write-Info "Error: $($_.Exception.Message)"
            Add-Finding "WIN-RP-001" "Medium" "Recovery" "System restore point could not be created" "Checkpoint-Computer failed" "Enable System Protection manually and create a restore point."
            Record-Action "Create system restore point" "Skipped"
        }
    } else {
        Write-Info "Restore point skipped by user."
        Record-Action "Create system restore point" "Skipped"
    }
} catch {
    Write-Info "System restore check failed."
}

# ==============================
# SYSTEM INFORMATION
# ==============================

Write-Header "1. SYSTEM INFORMATION"

try {
    $computerInfo = Get-ComputerInfo | Select-Object `
        WindowsProductName,
        WindowsVersion,
        OsHardwareAbstractionLayer,
        CsManufacturer,
        CsModel,
        CsTotalPhysicalMemory

    $computerInfo | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $computerInfo | Export-Csv "$ReportDir\System_Info.csv" -NoTypeInformation
} catch {
    Write-Info "Could not collect system information."
}

# ==============================
# WINDOWS FIREWALL
# ==============================

Write-Header "2. WINDOWS FIREWALL STATUS"

try {
    $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $firewallProfiles | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $firewallProfiles | Export-Csv "$ReportDir\Firewall_Status.csv" -NoTypeInformation

    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -ne $true) {
            Add-Finding `
                "WIN-FW-001-$($profile.Name)" `
                "High" `
                "Firewall" `
                "Windows Firewall is disabled for $($profile.Name) profile" `
                "Enabled = $($profile.Enabled)" `
                "Enable Windows Firewall for the $($profile.Name) profile."
        }
    }

    $disabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -ne $true }

    if ($disabledProfiles.Count -gt 0) {
        if (Confirm-Action "One or more firewall profiles are disabled. Enable firewall for Domain, Private, and Public profiles?") {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            Write-Info "Firewall enabled for Domain, Private, and Public profiles."
            Record-Action "Enabled Windows Firewall for all profiles" "Taken"
        } else {
            Write-Info "Firewall fix skipped by user."
            Record-Action "Enable Windows Firewall for all profiles" "Skipped"
        }
    } else {
        Write-Info "Firewall is enabled for all profiles."
    }
} catch {
    Write-Info "Could not check or configure Windows Firewall."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# REMOTE DESKTOP
# ==============================

Write-Header "3. REMOTE DESKTOP STATUS"

try {
    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"

    if ($rdp.fDenyTSConnections -eq 0) {
        Write-Info "RDP Status: ENABLED"
        Add-Finding `
            "WIN-RDP-001" `
            "Medium" `
            "Remote Access" `
            "Remote Desktop is enabled" `
            "fDenyTSConnections = 0" `
            "Disable Remote Desktop if you do not use it."

        if (Confirm-Action "Remote Desktop is enabled. Disable it?") {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Write-Info "Remote Desktop disabled at registry level."
            Record-Action "Disabled Remote Desktop" "Taken"

            try {
                Get-NetFirewallRule |
                Where-Object {
                    $_.DisplayName -like "*Remote Desktop*" -or
                    $_.DisplayName -like "*RDP*" -or
                    $_.DisplayName -like "*Terminal*"
                } |
                Disable-NetFirewallRule

                Write-Info "Matching Remote Desktop firewall rules disabled where found."
                Record-Action "Disabled matching Remote Desktop firewall rules" "Taken"
            } catch {
                Write-Info "No matching Remote Desktop firewall rules found, or firewall rules could not be changed."
            }
        } else {
            Write-Info "Remote Desktop left enabled by user choice."
            Record-Action "Disable Remote Desktop" "Skipped"
        }
    } else {
        Write-Info "RDP Status: DISABLED"
    }

    $rdpPort = Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue
    if ($rdpPort) {
        Write-Info "WARNING: Port 3389 appears to be listening."
        $rdpPort | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

        Add-Finding `
            "WIN-RDP-002" `
            "Medium" `
            "Remote Access" `
            "RDP port 3389 is listening" `
            "Get-NetTCPConnection returned listener on 3389" `
            "Confirm RDP is required. If not, disable RDP and related firewall rules."
    } else {
        Write-Info "Port 3389 is not listening."
    }
} catch {
    Write-Info "Could not check Remote Desktop status."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# MICROSOFT DEFENDER
# ==============================

Write-Header "4. MICROSOFT DEFENDER STATUS"

try {
    $defender = Get-MpComputerStatus

    $defenderSummary = $defender | Select-Object `
        AMServiceEnabled,
        AntivirusEnabled,
        AntispywareEnabled,
        RealTimeProtectionEnabled,
        BehaviorMonitorEnabled,
        IoavProtectionEnabled,
        NISEnabled,
        AntivirusSignatureLastUpdated,
        QuickScanEndTime,
        FullScanEndTime

    $defenderSummary | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $defenderSummary | Export-Csv "$ReportDir\Defender_Status.csv" -NoTypeInformation

    if ($defender.RealTimeProtectionEnabled -ne $true) {
        Add-Finding "WIN-DEF-001" "High" "Defender" "Real-time protection is disabled" "RealTimeProtectionEnabled = False" "Enable Defender real-time protection."
    }

    if ($defender.BehaviorMonitorEnabled -ne $true) {
        Add-Finding "WIN-DEF-002" "High" "Defender" "Behavior monitoring is disabled" "BehaviorMonitorEnabled = False" "Enable Defender behavior monitoring."
    }

    if (Confirm-Action "Update Microsoft Defender signatures now?") {
        Update-MpSignature
        Write-Info "Defender signatures update started/completed."
        Record-Action "Updated Defender signatures" "Taken"
    } else {
        Record-Action "Update Defender signatures" "Skipped"
    }

    if (Confirm-Action "Enable/confirm Defender real-time, behavior, and IOAV protection?") {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Write-Info "Defender core protections enabled or confirmed."
        Record-Action "Enabled Defender core protections" "Taken"
    } else {
        Record-Action "Enable Defender core protections" "Skipped"
    }

} catch {
    Write-Info "Could not read or configure Microsoft Defender."
    Write-Info "This may happen if another antivirus manages protection."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# DEFENDER PUA / CLOUD PROTECTION
# ==============================

Write-Header "5. DEFENDER ADVANCED PROTECTION SETTINGS"

try {
    $mpPref = Get-MpPreference

    $prefSummary = $mpPref | Select-Object `
        PUAProtection,
        MAPSReporting,
        SubmitSamplesConsent,
        EnableControlledFolderAccess

    $prefSummary | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $prefSummary | Export-Csv "$ReportDir\Defender_Preferences.csv" -NoTypeInformation

    if ($mpPref.PUAProtection -eq 0) {
        Add-Finding "WIN-DEF-003" "Medium" "Defender" "Potentially unwanted app protection is disabled" "PUAProtection = 0" "Enable Defender PUA protection."
    }

    if (Confirm-Action "Enable Potentially Unwanted App protection?") {
        Set-MpPreference -PUAProtection Enabled
        Write-Info "PUA protection enabled."
        Record-Action "Enabled Defender PUA protection" "Taken"
    } else {
        Record-Action "Enable Defender PUA protection" "Skipped"
    }

    if (Confirm-Action "Enable advanced Microsoft cloud protection and safe sample submission?") {
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
        Write-Info "Advanced cloud protection and safe sample submission configured."
        Record-Action "Enabled Defender cloud protection settings" "Taken"
    } else {
        Record-Action "Enable Defender cloud protection settings" "Skipped"
    }

    if (Confirm-Action "Enable Controlled Folder Access ransomware protection? This may block some trusted apps until allowed.") {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Write-Info "Controlled Folder Access enabled."
        Record-Action "Enabled Controlled Folder Access" "Taken"
    } else {
        Record-Action "Enable Controlled Folder Access" "Skipped"
    }

} catch {
    Write-Info "Could not configure Defender advanced preferences."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# DEFENDER SCAN
# ==============================

Write-Header "6. MICROSOFT DEFENDER SCAN"

try {
    if (Confirm-Action "Start a Defender Quick Scan now?") {
        Start-MpScan -ScanType QuickScan
        Write-Info "Defender Quick Scan started."
        Record-Action "Started Defender Quick Scan" "Taken"
    } else {
        Record-Action "Start Defender Quick Scan" "Skipped"
    }

    if (Confirm-Action "Start a Defender Full Scan now? This can take a long time.") {
        Start-MpScan -ScanType FullScan
        Write-Info "Defender Full Scan started."
        Record-Action "Started Defender Full Scan" "Taken"
    } else {
        Record-Action "Start Defender Full Scan" "Skipped"
    }
} catch {
    Write-Info "Could not start Defender scan."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# BITLOCKER / DEVICE ENCRYPTION
# ==============================

Write-Header "7. DRIVE ENCRYPTION STATUS"

try {
    $bitlocker = Get-BitLockerVolume
    $bitlocker | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, ProtectionStatus |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $bitlocker | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, ProtectionStatus |
    Export-Csv "$ReportDir\BitLocker_Status.csv" -NoTypeInformation

    foreach ($vol in $bitlocker) {
        if ($vol.ProtectionStatus -ne "On") {
            Add-Finding `
                "WIN-BL-001-$($vol.MountPoint)" `
                "Medium" `
                "Encryption" `
                "Drive encryption protection is off for $($vol.MountPoint)" `
                "VolumeStatus = $($vol.VolumeStatus), ProtectionStatus = $($vol.ProtectionStatus)" `
                "Enable BitLocker or Device Encryption after backing up your recovery key."
        }
    }

    Write-Info "This script does not automatically enable BitLocker. Enable it manually after saving your recovery key."
} catch {
    Write-Info "Could not check BitLocker status. This may be limited by Windows edition."
}

# ==============================
# TPM STATUS
# ==============================

Write-Header "8. TPM STATUS"

try {
    $tpm = Get-Tpm
    $tpm | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned, RestartPending |
    Export-Csv "$ReportDir\TPM_Status.csv" -NoTypeInformation

    if ($tpm.TpmPresent -ne $true -or $tpm.TpmReady -ne $true) {
        Add-Finding "WIN-TPM-001" "Medium" "TPM" "TPM is not ready" "TPM not present or not ready" "Check BIOS/UEFI TPM settings."
    }

    if ($tpm.RestartPending -eq $true) {
        Add-Finding "WIN-TPM-002" "Low" "TPM" "TPM restart pending" "RestartPending = True" "Restart Windows before enabling drive encryption."
    }
} catch {
    Write-Info "Could not check TPM status."
}

# ==============================
# PASSWORD / LOCKOUT POLICY
# ==============================

Write-Header "9. PASSWORD AND LOCKOUT POLICY"

try {
    $netAccounts = net accounts
    $netAccounts | Tee-Object -FilePath $FullReportFile -Append

    if ($netAccounts -match "Lockout threshold:\s+Never") {
        Add-Finding `
            "WIN-PWD-001" `
            "Medium" `
            "Account Policy" `
            "Account lockout threshold is not configured" `
            "Lockout threshold = Never" `
            "Set account lockout threshold to reduce brute-force risk."
    }

    if (Confirm-Action "Set account lockout threshold to 5 failed attempts, 30-minute lockout, 30-minute window?") {
        net accounts /lockoutthreshold:5 | Out-Null
        net accounts /lockoutduration:30 | Out-Null
        net accounts /lockoutwindow:30 | Out-Null
        Write-Info "Account lockout policy configured."
        Record-Action "Configured account lockout policy" "Taken"
    } else {
        Record-Action "Configure account lockout policy" "Skipped"
    }
} catch {
    Write-Info "Could not check or configure account policy."
}

# ==============================
# LOCAL ADMINISTRATORS
# ==============================

Write-Header "10. LOCAL ADMINISTRATORS"

try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    $admins | Select-Object Name, ObjectClass, PrincipalSource |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $admins | Select-Object Name, ObjectClass, PrincipalSource |
    Export-Csv "$ReportDir\Local_Admins.csv" -NoTypeInformation

    if ($admins.Count -gt 2) {
        Add-Finding `
            "WIN-ADM-001" `
            "Medium" `
            "Local Admins" `
            "More than two local administrators found" `
            "Admin count = $($admins.Count)" `
            "Review local Administrators group and remove unnecessary admin access manually."
    }

    Write-Info "This script does not remove administrator accounts automatically."
} catch {
    Write-Info "Could not read local administrators."
}

# ==============================
# LOCAL USERS
# ==============================

Write-Header "11. LOCAL USERS"

try {
    $users = Get-LocalUser
    $users | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $users | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
    Export-Csv "$ReportDir\Local_Users.csv" -NoTypeInformation

    foreach ($user in $users) {
        if ($user.Enabled -eq $true -and $user.PasswordRequired -ne $true) {
            Add-Finding `
                "WIN-USR-001-$($user.Name)" `
                "High" `
                "Local Users" `
                "Enabled local user does not require a password" `
                "User = $($user.Name)" `
                "Manually require a password or disable the account if not needed."
        }
    }

    Write-Info "This script does not disable or modify user accounts automatically."
} catch {
    Write-Info "Could not read local users."
}

# ==============================
# SMB CONFIGURATION
# ==============================

Write-Header "12. SMB CONFIGURATION"

try {
    $smb = Get-SmbServerConfiguration
    $smbSummary = $smb | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature

    $smbSummary | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $smbSummary | Export-Csv "$ReportDir\SMB_Config.csv" -NoTypeInformation

    if ($smb.EnableSMB1Protocol -eq $true) {
        Add-Finding `
            "WIN-SMB-001" `
            "High" `
            "SMB" `
            "SMBv1 is enabled" `
            "EnableSMB1Protocol = True" `
            "Disable SMBv1 unless absolutely required."

        if (Confirm-Action "SMBv1 is enabled. Disable SMBv1?") {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
            Write-Info "SMBv1 disable command executed. Restart may be required."
            Record-Action "Disabled SMBv1" "Taken"
        } else {
            Record-Action "Disable SMBv1" "Skipped"
        }
    } else {
        Write-Info "SMBv1 is disabled."
    }

    if ($smb.RequireSecuritySignature -ne $true) {
        Add-Finding `
            "WIN-SMB-002" `
            "Low" `
            "SMB" `
            "SMB signing is not required" `
            "RequireSecuritySignature = False" `
            "For stronger security, require SMB signing if compatible with your environment."
    }

} catch {
    Write-Info "Could not check SMB configuration."
}

# ==============================
# SHARED FOLDERS
# ==============================

Write-Header "13. SHARED FOLDERS"

try {
    $shares = Get-SmbShare
    $shares | Select-Object Name, Path, Description |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $shares | Select-Object Name, Path, Description |
    Export-Csv "$ReportDir\Shared_Folders.csv" -NoTypeInformation

    $nonDefaultShares = $shares | Where-Object {
        $_.Name -notin @("ADMIN$", "C$", "D$", "E$", "IPC$", "print$")
    }

    if ($nonDefaultShares.Count -gt 0) {
        Add-Finding `
            "WIN-SHARE-001" `
            "Medium" `
            "File Sharing" `
            "Non-default SMB shares found" `
            "Share count = $($nonDefaultShares.Count)" `
            "Review shared folders and remove unnecessary shares manually."
    }

    Write-Info "This script does not remove shares automatically."
} catch {
    Write-Info "Could not check SMB shares."
}

# ==============================
# OPEN PORTS
# ==============================

Write-Header "14. LISTENING NETWORK PORTS"

try {
    $ports = Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort

    $ports | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $ports | Export-Csv "$ReportDir\Listening_Ports.csv" -NoTypeInformation

    $portProcessList = foreach ($port in $ports) {
        $procName = "Unknown"
        try {
            $proc = Get-Process -Id $port.OwningProcess -ErrorAction Stop
            $procName = $proc.ProcessName
        } catch {}

        [PSCustomObject]@{
            LocalAddress  = $port.LocalAddress
            LocalPort     = $port.LocalPort
            PID           = $port.OwningProcess
            ProcessName   = $procName
        }
    }

    $portProcessList | Export-Csv "$ReportDir\Listening_Ports_With_Processes.csv" -NoTypeInformation

    $externalListeners = $portProcessList | Where-Object {
        $_.LocalAddress -eq "0.0.0.0" -or
        $_.LocalAddress -eq "::" -or
        $_.LocalAddress -match "^10\." -or
        $_.LocalAddress -match "^192\.168\." -or
        $_.LocalAddress -match "^172\."
    }

    if ($externalListeners.Count -gt 0) {
        Add-Finding `
            "WIN-NET-001" `
            "Low" `
            "Network" `
            "Network-facing listening ports detected" `
            "Count = $($externalListeners.Count)" `
            "Review Listening_Ports_With_Processes.csv. Ensure firewall is enabled and unnecessary services are disabled manually."
    }

    Write-Info "Open ports exported to CSV for review."
} catch {
    Write-Info "Could not collect listening ports."
}

# ==============================
# INSTALLED PROGRAMS
# ==============================

Write-Header "15. INSTALLED PROGRAMS"

try {
    $installedPrograms = @()

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        $installedPrograms += Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }

    $installedPrograms = $installedPrograms |
    Where-Object { $_.DisplayName } |
    Sort-Object DisplayName -Unique

    $installedPrograms | Export-Csv "$ReportDir\Installed_Programs.csv" -NoTypeInformation

    $installedPrograms |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $reviewKeywords = @("WinRAR", "PuTTY", "Java", "Python", "Anaconda", "Node", "Go ", "OpenSSL", "Npcap", "SQL Server")

    foreach ($keyword in $reviewKeywords) {
        $matches = $installedPrograms | Where-Object { $_.DisplayName -like "*$keyword*" }
        foreach ($match in $matches) {
            Add-Finding `
                "WIN-SW-REVIEW" `
                "Low" `
                "Software Inventory" `
                "Software should be reviewed and kept updated" `
                "$($match.DisplayName) $($match.DisplayVersion)" `
                "Update this software from the official vendor or uninstall it if no longer needed."
        }
    }

    Write-Info "Installed programs exported to Installed_Programs.csv."
    Write-Info "This script does not uninstall software automatically."
} catch {
    Write-Info "Could not collect installed programs."
}

# ==============================
# STARTUP APPS
# ==============================

Write-Header "16. STARTUP APPLICATIONS"

try {
    $startup = Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User

    $startup | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $startup | Export-Csv "$ReportDir\Startup_Apps.csv" -NoTypeInformation

    foreach ($item in $startup) {
        if ($item.Command -match "\\AppData\\" -or $item.Command -match "\\Temp\\") {
            Add-Finding `
                "WIN-STARTUP-001" `
                "Medium" `
                "Startup" `
                "Startup item runs from user-writable location" `
                "$($item.Name): $($item.Command)" `
                "Review this startup item. User-writable startup locations are commonly abused by malware."
        }
    }

    Write-Info "Startup applications exported to Startup_Apps.csv."
    Write-Info "This script does not disable startup apps automatically."
} catch {
    Write-Info "Could not collect startup applications."
}

# ==============================
# SCHEDULED TASKS
# ==============================

Write-Header "17. ENABLED SCHEDULED TASKS"

try {
    $tasks = Get-ScheduledTask |
    Where-Object { $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, State

    $tasks | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $tasks | Export-Csv "$ReportDir\Scheduled_Tasks.csv" -NoTypeInformation

    Write-Info "Scheduled tasks exported to Scheduled_Tasks.csv."
    Write-Info "This script does not delete or disable scheduled tasks automatically."
} catch {
    Write-Info "Could not collect scheduled tasks."
}

# ==============================
# SERVICES
# ==============================

Write-Header "18. SERVICES REVIEW"

try {
    $services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName

    $services | Export-Csv "$ReportDir\Services.csv" -NoTypeInformation

    $unquotedThirdParty = $services |
    Where-Object {
        $_.PathName -and
        $_.PathName -match " " -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '^C:\\WINDOWS\\' -and
        $_.PathName -notmatch '^C:\\Windows\\'
    }

    $unquotedThirdParty |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $unquotedThirdParty |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Export-Csv "$ReportDir\Unquoted_ThirdParty_Service_Paths.csv" -NoTypeInformation

    if ($unquotedThirdParty.Count -gt 0) {
        Add-Finding `
            "WIN-SVC-001" `
            "Medium" `
            "Services" `
            "Third-party services with unquoted paths found" `
            "Count = $($unquotedThirdParty.Count)" `
            "Review Unquoted_ThirdParty_Service_Paths.csv. Fix manually only after confirming the correct service path."
    }

    Write-Info "Services exported to Services.csv."
    Write-Info "This script does not modify services automatically."
} catch {
    Write-Info "Could not collect services."
}

# ==============================
# BROWSER EXTENSION LOCATIONS
# ==============================

Write-Header "19. BROWSER EXTENSION LOCATIONS"

try {
    $chromeExt = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    $edgeExt = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

    $browserExtResults = @()

    if (Test-Path $chromeExt) {
        $chromeItems = Get-ChildItem $chromeExt -Directory -ErrorAction SilentlyContinue
        foreach ($item in $chromeItems) {
            $browserExtResults += [PSCustomObject]@{
                Browser = "Chrome"
                ExtensionId = $item.Name
                Path = $item.FullName
            }
        }
    }

    if (Test-Path $edgeExt) {
        $edgeItems = Get-ChildItem $edgeExt -Directory -ErrorAction SilentlyContinue
        foreach ($item in $edgeItems) {
            $browserExtResults += [PSCustomObject]@{
                Browser = "Edge"
                ExtensionId = $item.Name
                Path = $item.FullName
            }
        }
    }

    if ($browserExtResults.Count -gt 0) {
        $browserExtResults | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
        $browserExtResults | Export-Csv "$ReportDir\Browser_Extension_Folders.csv" -NoTypeInformation

        Add-Finding `
            "WIN-BROWSER-001" `
            "Low" `
            "Browser" `
            "Browser extensions found" `
            "Extension folder count = $($browserExtResults.Count)" `
            "Review Chrome/Edge extensions manually and remove anything unused or unknown."
    } else {
        Write-Info "No Chrome/Edge extension folders found in default profile locations."
    }

    Write-Info "This script does not remove browser extensions automatically."
} catch {
    Write-Info "Could not collect browser extension folders."
}

# ==============================
# WINDOWS UPDATE HOTFIXES
# ==============================

Write-Header "20. WINDOWS UPDATE HOTFIXES"

try {
    $hotfixes = Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object HotFixID, Description, InstalledOn

    $hotfixes | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $hotfixes | Export-Csv "$ReportDir\Windows_Hotfixes.csv" -NoTypeInformation

    Write-Info "Windows update history exported to Windows_Hotfixes.csv."
} catch {
    Write-Info "Could not collect Windows hotfixes."
}

# ==============================
# ANTIVIRUS PRODUCTS
# ==============================

Write-Header "21. REGISTERED ANTIVIRUS PRODUCTS"

try {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, productState, pathToSignedProductExe

    $av | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $av | Export-Csv "$ReportDir\Registered_Antivirus.csv" -NoTypeInformation
} catch {
    Write-Info "Could not collect registered antivirus products."
}

# ==============================
# FINAL RISK REPORT
# ==============================

Write-Header "22. RISK FINDINGS SUMMARY"

if ($RiskFindings.Count -eq 0) {
    Write-Info "No major findings detected by this toolkit."
} else {
    $RiskFindings |
    Sort-Object @{Expression={
        switch ($_.Severity) {
            "High" {1}
            "Medium" {2}
            "Low" {3}
            default {4}
        }
    }}, Category |
    Format-Table ID, Severity, Category, Finding -AutoSize |
    Out-String | Tee-Object -FilePath $FullReportFile -Append

    $RiskFindings | Export-Csv $RiskCsv -NoTypeInformation
}

# ==============================
# ACTIONS TAKEN / SKIPPED
# ==============================

Write-Header "23. ACTIONS TAKEN"

if ($ActionsTaken.Count -eq 0) {
    Write-Info "No changes were applied."
} else {
    foreach ($action in $ActionsTaken) {
        Write-Info "TAKEN: $action"
    }
}

Write-Header "24. ACTIONS SKIPPED"

if ($ActionsSkipped.Count -eq 0) {
    Write-Info "No actions skipped."
} else {
    foreach ($action in $ActionsSkipped) {
        Write-Info "SKIPPED: $action"
    }
}

# ==============================
# SUMMARY FILE
# ==============================

$highCount = ($RiskFindings | Where-Object { $_.Severity -eq "High" }).Count
$mediumCount = ($RiskFindings | Where-Object { $_.Severity -eq "Medium" }).Count
$lowCount = ($RiskFindings | Where-Object { $_.Severity -eq "Low" }).Count

$summary = @"
WINDOWS SECURITY HARDENING SUMMARY
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME

REPORT LOCATION:
$ReportDir

RISK COUNTS:
High:   $highCount
Medium: $mediumCount
Low:    $lowCount

ACTIONS TAKEN:
$($ActionsTaken -join "`n")

ACTIONS SKIPPED:
$($ActionsSkipped -join "`n")

RECOMMENDED NEXT STEPS:
1. Review Risk_Findings.csv first.
2. Review Listening_Ports_With_Processes.csv.
3. Review Installed_Programs.csv and update/remove old software manually.
4. Review Startup_Apps.csv.
5. Review Browser_Extension_Folders.csv.
6. If BitLocker/Device Encryption is off, enable it manually after saving your recovery key.
7. Re-run this script after making changes.
"@

Set-Content -Path $SummaryFile -Value $summary

Write-Header "25. COMPLETE"

Write-Info "Security toolkit completed."
Write-Info "Summary report: $SummaryFile"
Write-Info "Full report: $FullReportFile"
Write-Info "Risk CSV: $RiskCsv"

Write-Host ""
Write-Host "Done. Reports saved here:"
Write-Host $ReportDir
Write-Host ""