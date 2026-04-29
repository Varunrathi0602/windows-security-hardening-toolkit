<#
.SYNOPSIS
    Windows Security Hardening Toolkit v1.1

.DESCRIPTION
    Interactive Windows security audit and safe hardening toolkit.

    v1.1 adds:
    - HTML dashboard report
    - Security score out of 100
    - Pass / Fail / Review status
    - CIS-style control mapping
    - Evidence-based recommendations
    - Remediation commands
    - Auto-open dashboard at the end

.NOTES
    Run PowerShell as Administrator.
#>

$ErrorActionPreference = "Continue"

$ScriptVersion = "1.1"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportDir = "$env:USERPROFILE\Desktop\Windows_Security_Hardening_Report_$Timestamp"

$SummaryFile = "$ReportDir\Security_Summary.txt"
$FullReportFile = "$ReportDir\Security_Full_Report.txt"
$HtmlReportFile = "$ReportDir\Security_Dashboard.html"
$RiskCsv = "$ReportDir\Risk_Findings.csv"
$ControlCsv = "$ReportDir\Control_Results.csv"
$ActionsCsv = "$ReportDir\Actions_Taken.csv"

New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$ControlResults = @()
$RiskFindings = @()
$ActionsTaken = @()
$ActionsSkipped = @()

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

function Get-ScoreImpact {
    param([string]$Severity)

    switch ($Severity) {
        "High"   { return 15 }
        "Medium" { return 7 }
        "Low"    { return 2 }
        default  { return 0 }
    }
}

function Add-ControlResult {
    param(
        [string]$Id,
        [string]$ControlMapping,
        [string]$Severity,
        [string]$Status,
        [string]$Finding,
        [string]$Evidence,
        [string]$WhyItMatters,
        [string]$Recommendation,
        [string]$RemediationCommand,
        [string]$ManualSteps,
        [string]$RestartRequired = "No"
    )

    $scoreImpact = 0

    if ($Status -eq "Fail") {
        $scoreImpact = Get-ScoreImpact -Severity $Severity
    }

    $item = [PSCustomObject]@{
        ID                 = $Id
        ControlMapping     = $ControlMapping
        Severity           = $Severity
        Status             = $Status
        Finding            = $Finding
        Evidence           = $Evidence
        WhyItMatters       = $WhyItMatters
        Recommendation     = $Recommendation
        RemediationCommand = $RemediationCommand
        ManualSteps        = $ManualSteps
        RestartRequired    = $RestartRequired
        ScoreImpact        = $scoreImpact
    }

    $global:ControlResults += $item

    if ($Status -eq "Fail") {
        $global:RiskFindings += $item
    }
}

function Record-Action {
    param(
        [string]$Action,
        [string]$Status
    )

    $actionObject = [PSCustomObject]@{
        Timestamp = Get-Date
        Action    = $Action
        Status    = $Status
    }

    if ($Status -eq "Taken") {
        $global:ActionsTaken += $actionObject
    } else {
        $global:ActionsSkipped += $actionObject
    }
}

function Get-SecurityScore {
    $deduction = ($global:ControlResults | Measure-Object -Property ScoreImpact -Sum).Sum

    if (-not $deduction) {
        $deduction = 0
    }

    $score = 100 - [int]$deduction

    if ($score -lt 0) {
        $score = 0
    }

    return $score
}

function Get-SecurityRating {
    param([int]$Score)

    if ($Score -ge 90) {
        return "Excellent"
    } elseif ($Score -ge 75) {
        return "Good"
    } elseif ($Score -ge 60) {
        return "Needs Improvement"
    } elseif ($Score -ge 40) {
        return "High Risk"
    } else {
        return "Critical"
    }
}

function Get-HtmlEncoded {
    param([string]$Text)

    if ($null -eq $Text) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-BadgeClass {
    param(
        [string]$Type,
        [string]$Value
    )

    if ($Type -eq "Severity") {
        switch ($Value) {
            "High"   { return "badge badge-high" }
            "Medium" { return "badge badge-medium" }
            "Low"    { return "badge badge-low" }
            default  { return "badge" }
        }
    }

    if ($Type -eq "Status") {
        switch ($Value) {
            "Pass"   { return "badge badge-pass" }
            "Fail"   { return "badge badge-fail" }
            "Review" { return "badge badge-review" }
            default  { return "badge" }
        }
    }

    return "badge"
}

function New-HtmlDashboard {
    param(
        [string]$Path,
        [int]$SecurityScore,
        [string]$SecurityRating,
        [int]$HighCount,
        [int]$MediumCount,
        [int]$LowCount,
        [int]$PassCount,
        [int]$FailCount,
        [int]$ReviewCount
    )

    $computerName = Get-HtmlEncoded $env:COMPUTERNAME
    $userName = Get-HtmlEncoded $env:USERNAME
    $scanDate = Get-HtmlEncoded (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $windowsName = "Unknown"

    try {
        $windowsName = (Get-ComputerInfo).WindowsProductName
    } catch {}

    $windowsName = Get-HtmlEncoded $windowsName

    $controlRows = ""

    foreach ($control in $global:ControlResults) {
        $severityClass = Get-BadgeClass -Type "Severity" -Value $control.Severity
        $statusClass = Get-BadgeClass -Type "Status" -Value $control.Status

        $remediationBlock = ""

        if ($control.RemediationCommand -and $control.RemediationCommand.Trim() -ne "") {
            $encodedCommand = Get-HtmlEncoded $control.RemediationCommand
            $remediationBlock = "<code>$encodedCommand</code>"
        } else {
            $remediationBlock = "<span class='muted'>Manual review required</span>"
        }

        $controlRows += @"
<tr>
  <td><strong>$(Get-HtmlEncoded $control.ID)</strong></td>
  <td>$(Get-HtmlEncoded $control.ControlMapping)</td>
  <td><span class="$severityClass">$(Get-HtmlEncoded $control.Severity)</span></td>
  <td><span class="$statusClass">$(Get-HtmlEncoded $control.Status)</span></td>
  <td>$(Get-HtmlEncoded $control.Finding)</td>
  <td><code>$(Get-HtmlEncoded $control.Evidence)</code></td>
  <td>$(Get-HtmlEncoded $control.Recommendation)</td>
  <td>$remediationBlock</td>
  <td>$(Get-HtmlEncoded $control.RestartRequired)</td>
</tr>
"@
    }

    $topFindings = ($global:ControlResults |
        Where-Object { $_.Status -eq "Fail" } |
        Sort-Object @{Expression={
            switch ($_.Severity) {
                "High" {1}
                "Medium" {2}
                "Low" {3}
                default {4}
            }
        }} |
        Select-Object -First 5)

    $topFindingItems = ""

    foreach ($finding in $topFindings) {
    $sev = Get-HtmlEncoded $finding.Severity
    $find = Get-HtmlEncoded $finding.Finding
    $rec = Get-HtmlEncoded $finding.Recommendation

    $topFindingItems += "<li><strong>$sev</strong>: $find - $rec</li>"
}

if ($topFindingItems -eq "") {
    $topFindingItems = "<li>No failed controls were detected by this toolkit.</li>"
}

    $actionsTakenItems = ""

    foreach ($action in $global:ActionsTaken) {
        $actionsTakenItems += "<li>$(Get-HtmlEncoded $action.Action)</li>"
    }

    if ($actionsTakenItems -eq "") {
        $actionsTakenItems = "<li>No configuration changes were applied.</li>"
    }

    $actionsSkippedItems = ""

    foreach ($action in $global:ActionsSkipped) {
        $actionsSkippedItems += "<li>$(Get-HtmlEncoded $action.Action)</li>"
    }

    if ($actionsSkippedItems -eq "") {
        $actionsSkippedItems = "<li>No actions were skipped.</li>"
    }

    $highWidth = [Math]::Min($HighCount * 20, 100)
    $mediumWidth = [Math]::Min($MediumCount * 15, 100)
    $lowWidth = [Math]::Min($LowCount * 10, 100)

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Windows Security Hardening Dashboard</title>

  <style>
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: #f4f6f8;
      color: #1f2937;
    }

    .container {
      max-width: 1300px;
      margin: 30px auto;
      padding: 20px;
    }

    .header {
      background: #111827;
      color: white;
      padding: 28px;
      border-radius: 16px;
      margin-bottom: 24px;
    }

    .header h1 {
      margin: 0;
      font-size: 30px;
    }

    .header p {
      margin: 8px 0 0;
      color: #d1d5db;
    }

    .score-card {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: white;
      padding: 24px;
      border-radius: 16px;
      margin-bottom: 24px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.06);
      gap: 20px;
    }

    .score {
      font-size: 54px;
      font-weight: bold;
    }

    .rating {
      font-size: 22px;
      font-weight: bold;
      padding: 10px 18px;
      border-radius: 999px;
      background: #dcfce7;
      color: #166534;
      display: inline-block;
    }

    .meta {
      color: #6b7280;
      font-size: 14px;
      line-height: 1.7;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }

    .kpi {
      background: white;
      padding: 20px;
      border-radius: 14px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }

    .kpi-title {
      color: #6b7280;
      font-size: 14px;
      margin-bottom: 8px;
    }

    .kpi-value {
      font-size: 30px;
      font-weight: bold;
    }

    .high { color: #b91c1c; }
    .medium { color: #b45309; }
    .low { color: #1d4ed8; }
    .pass { color: #15803d; }
    .fail { color: #b91c1c; }
    .review { color: #7c3aed; }

    .section {
      background: white;
      padding: 24px;
      border-radius: 16px;
      margin-bottom: 24px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }

    .section h2 {
      margin-top: 0;
      font-size: 22px;
    }

    .bar-row {
      margin: 16px 0;
    }

    .bar-label {
      margin-bottom: 6px;
      font-weight: bold;
    }

    .bar-bg {
      background: #e5e7eb;
      border-radius: 999px;
      height: 14px;
      overflow: hidden;
    }

    .bar-fill-high {
      height: 14px;
      width: $highWidth%;
      background: #dc2626;
    }

    .bar-fill-medium {
      height: 14px;
      width: $mediumWidth%;
      background: #f59e0b;
    }

    .bar-fill-low {
      height: 14px;
      width: $lowWidth%;
      background: #2563eb;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      background: #f9fafb;
      padding: 12px;
      border-bottom: 1px solid #e5e7eb;
      white-space: nowrap;
    }

    td {
      padding: 12px;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: top;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: bold;
      white-space: nowrap;
    }

    .badge-high {
      background: #fee2e2;
      color: #991b1b;
    }

    .badge-medium {
      background: #fef3c7;
      color: #92400e;
    }

    .badge-low {
      background: #dbeafe;
      color: #1e40af;
    }

    .badge-pass {
      background: #dcfce7;
      color: #166534;
    }

    .badge-fail {
      background: #fee2e2;
      color: #991b1b;
    }

    .badge-review {
      background: #ede9fe;
      color: #5b21b6;
    }

    code {
      background: #f3f4f6;
      padding: 3px 6px;
      border-radius: 6px;
      font-size: 12px;
      display: inline-block;
      max-width: 280px;
      overflow-wrap: anywhere;
    }

    ul {
      line-height: 1.8;
    }

    .muted {
      color: #6b7280;
    }

    .footer {
      text-align: center;
      color: #6b7280;
      font-size: 13px;
      margin-top: 30px;
    }

    .table-wrap {
      overflow-x: auto;
    }

    @media (max-width: 1000px) {
      .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
      }

      .score-card {
        flex-direction: column;
        align-items: flex-start;
      }

      table {
        font-size: 12px;
      }
    }
  </style>
</head>

<body>
  <div class="container">

    <div class="header">
      <h1>Windows Security Hardening Toolkit</h1>
      <p>Security audit dashboard generated from local Windows endpoint checks. Version $ScriptVersion.</p>
    </div>

    <div class="score-card">
      <div>
        <div class="score">$SecurityScore / 100</div>
        <div class="meta">Overall Security Score</div>
      </div>

      <div>
        <div class="rating">$SecurityRating</div>
      </div>

      <div class="meta">
        <strong>Scan Date:</strong> $scanDate<br />
        <strong>Computer:</strong> $computerName<br />
        <strong>User:</strong> $userName<br />
        <strong>Windows:</strong> $windowsName
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-title">High Findings</div>
        <div class="kpi-value high">$HighCount</div>
      </div>

      <div class="kpi">
        <div class="kpi-title">Medium Findings</div>
        <div class="kpi-value medium">$MediumCount</div>
      </div>

      <div class="kpi">
        <div class="kpi-title">Low Findings</div>
        <div class="kpi-value low">$LowCount</div>
      </div>

      <div class="kpi">
        <div class="kpi-title">Passed Controls</div>
        <div class="kpi-value pass">$PassCount</div>
      </div>

      <div class="kpi">
        <div class="kpi-title">Failed Controls</div>
        <div class="kpi-value fail">$FailCount</div>
      </div>

      <div class="kpi">
        <div class="kpi-title">Review Items</div>
        <div class="kpi-value review">$ReviewCount</div>
      </div>
    </div>

    <div class="section">
      <h2>Executive Summary</h2>
      <p>
        This dashboard summarizes the endpoint security posture based on local Windows configuration checks.
        Findings are mapped to CIS-style security control areas and include evidence, recommended remediation,
        and copy-ready PowerShell commands where appropriate.
      </p>
    </div>

    <div class="section">
      <h2>Top Recommended Fixes</h2>
      <ul>
        $topFindingItems
      </ul>
    </div>

    <div class="section">
      <h2>Risk Breakdown</h2>

      <div class="bar-row">
        <div class="bar-label high">High Findings: $HighCount</div>
        <div class="bar-bg">
          <div class="bar-fill-high"></div>
        </div>
      </div>

      <div class="bar-row">
        <div class="bar-label medium">Medium Findings: $MediumCount</div>
        <div class="bar-bg">
          <div class="bar-fill-medium"></div>
        </div>
      </div>

      <div class="bar-row">
        <div class="bar-label low">Low Findings: $LowCount</div>
        <div class="bar-bg">
          <div class="bar-fill-low"></div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Control Results</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>CIS-Style Mapping</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Finding</th>
              <th>Evidence</th>
              <th>Recommendation</th>
              <th>Command</th>
              <th>Restart</th>
            </tr>
          </thead>

          <tbody>
            $controlRows
          </tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Actions Taken</h2>
      <ul>
        $actionsTakenItems
      </ul>
    </div>

    <div class="section">
      <h2>Actions Skipped</h2>
      <ul>
        $actionsSkippedItems
      </ul>
    </div>

    <div class="section">
      <h2>Report Files</h2>
      <ul>
        <li><strong>Summary:</strong> $(Get-HtmlEncoded $SummaryFile)</li>
        <li><strong>Full Report:</strong> $(Get-HtmlEncoded $FullReportFile)</li>
        <li><strong>Risk Findings CSV:</strong> $(Get-HtmlEncoded $RiskCsv)</li>
        <li><strong>Control Results CSV:</strong> $(Get-HtmlEncoded $ControlCsv)</li>
      </ul>
    </div>

    <div class="footer">
      Generated by Windows Security Hardening Toolkit v$ScriptVersion
    </div>

  </div>
</body>
</html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8
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

Write-Header "WINDOWS SECURITY HARDENING TOOLKIT v$ScriptVersion"
Write-Info "Generated: $(Get-Date)"
Write-Info "Computer Name: $env:COMPUTERNAME"
Write-Info "User: $env:USERNAME"
Write-Info "Report Folder: $ReportDir"

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
# RESTORE POINT
# ==============================

Write-Header "2. SYSTEM RESTORE POINT"

if (Confirm-Action "Create a system restore point before making changes?") {
    try {
        Checkpoint-Computer -Description "Before Windows Security Hardening $Timestamp" -RestorePointType "MODIFY_SETTINGS"
        Write-Info "Restore point creation attempted successfully."
        Record-Action "Created system restore point" "Taken"

        Add-ControlResult `
            -Id "WIN-RP-001" `
            -ControlMapping "Recovery / System Restore" `
            -Severity "Low" `
            -Status "Pass" `
            -Finding "System restore point was created or attempted." `
            -Evidence "Checkpoint-Computer executed" `
            -WhyItMatters "A restore point provides a recovery option before configuration changes." `
            -Recommendation "Keep System Protection enabled for safer system changes." `
            -RemediationCommand "" `
            -ManualSteps "Control Panel > System > System Protection" `
            -RestartRequired "No"
    } catch {
        Write-Info "Could not create restore point. System Protection may be disabled."
        Record-Action "Create system restore point" "Skipped"

        Add-ControlResult `
            -Id "WIN-RP-001" `
            -ControlMapping "Recovery / System Restore" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "System restore point could not be created." `
            -Evidence $_.Exception.Message `
            -WhyItMatters "A restore point helps recover from problematic configuration changes." `
            -Recommendation "Enable System Protection manually and create a restore point." `
            -RemediationCommand "" `
            -ManualSteps "Control Panel > System > System Protection > Configure" `
            -RestartRequired "No"
    }
} else {
    Write-Info "Restore point skipped by user."
    Record-Action "Create system restore point" "Skipped"
}

# ==============================
# FIREWALL
# ==============================

Write-Header "3. WINDOWS FIREWALL STATUS"

try {
    $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $firewallProfiles | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $firewallProfiles | Export-Csv "$ReportDir\Firewall_Status.csv" -NoTypeInformation

    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -eq $true) {
            Add-ControlResult `
                -Id "WIN-FW-001-$($profile.Name)" `
                -ControlMapping "Network Security / Host Firewall" `
                -Severity "High" `
                -Status "Pass" `
                -Finding "Windows Firewall is enabled for $($profile.Name) profile." `
                -Evidence "Enabled = True" `
                -WhyItMatters "The host firewall reduces exposure to unwanted inbound traffic." `
                -Recommendation "No action required." `
                -RemediationCommand "" `
                -ManualSteps "Windows Security > Firewall & network protection" `
                -RestartRequired "No"
        } else {
            Add-ControlResult `
                -Id "WIN-FW-001-$($profile.Name)" `
                -ControlMapping "Network Security / Host Firewall" `
                -Severity "High" `
                -Status "Fail" `
                -Finding "Windows Firewall is disabled for $($profile.Name) profile." `
                -Evidence "Enabled = False" `
                -WhyItMatters "A disabled firewall can expose local services to network-based attacks." `
                -Recommendation "Enable Windows Firewall for this profile." `
                -RemediationCommand "Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True" `
                -ManualSteps "Windows Security > Firewall & network protection > Turn on firewall" `
                -RestartRequired "No"
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
# RDP
# ==============================

Write-Header "4. REMOTE DESKTOP STATUS"

try {
    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"

    if ($rdp.fDenyTSConnections -eq 0) {
        Write-Info "RDP Status: ENABLED"

        Add-ControlResult `
            -Id "WIN-RDP-001" `
            -ControlMapping "Remote Access Management" `
            -Severity "Medium" `
            -Status "Fail" `
            -Finding "Remote Desktop is enabled." `
            -Evidence "fDenyTSConnections = 0" `
            -WhyItMatters "RDP can expose the endpoint to brute-force attempts and remote access risk if not properly restricted." `
            -Recommendation "Disable Remote Desktop if it is not required." `
            -RemediationCommand 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1' `
            -ManualSteps "Settings > System > Remote Desktop > Off" `
            -RestartRequired "No"

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

        Add-ControlResult `
            -Id "WIN-RDP-001" `
            -ControlMapping "Remote Access Management" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Remote Desktop is disabled." `
            -Evidence "fDenyTSConnections = 1" `
            -WhyItMatters "Disabling unused remote access reduces attack surface." `
            -Recommendation "No action required unless RDP is intentionally needed." `
            -RemediationCommand "" `
            -ManualSteps "Settings > System > Remote Desktop" `
            -RestartRequired "No"
    }

    $rdpPort = Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue

    if ($rdpPort) {
        Add-ControlResult `
            -Id "WIN-RDP-002" `
            -ControlMapping "Remote Access Management / Network Exposure" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "Port 3389 appears to be listening." `
            -Evidence "Get-NetTCPConnection returned listener on 3389" `
            -WhyItMatters "Port 3389 is commonly associated with Remote Desktop." `
            -Recommendation "Confirm whether RDP is required. If not, disable Remote Desktop." `
            -RemediationCommand "Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue" `
            -ManualSteps "Review RDP settings and firewall rules." `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-RDP-002" `
            -ControlMapping "Remote Access Management / Network Exposure" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Port 3389 is not listening." `
            -Evidence "No listener returned for LocalPort 3389" `
            -WhyItMatters "No active RDP listener reduces remote access exposure." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }
} catch {
    Write-Info "Could not check Remote Desktop status."
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# DEFENDER
# ==============================

Write-Header "5. MICROSOFT DEFENDER STATUS"

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

    if ($defender.RealTimeProtectionEnabled -eq $true) {
        Add-ControlResult `
            -Id "WIN-DEF-001" `
            -ControlMapping "Malware Defense / Real-Time Protection" `
            -Severity "High" `
            -Status "Pass" `
            -Finding "Microsoft Defender real-time protection is enabled." `
            -Evidence "RealTimeProtectionEnabled = True" `
            -WhyItMatters "Real-time protection helps block malware as files and processes are accessed." `
            -Recommendation "Keep Defender enabled and updated." `
            -RemediationCommand "" `
            -ManualSteps "Windows Security > Virus & threat protection" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-DEF-001" `
            -ControlMapping "Malware Defense / Real-Time Protection" `
            -Severity "High" `
            -Status "Fail" `
            -Finding "Microsoft Defender real-time protection is disabled." `
            -Evidence "RealTimeProtectionEnabled = False" `
            -WhyItMatters "Disabled real-time protection can allow malware to execute without immediate detection." `
            -Recommendation "Enable Defender real-time protection." `
            -RemediationCommand 'Set-MpPreference -DisableRealtimeMonitoring $false' `
            -ManualSteps "Windows Security > Virus & threat protection > Manage settings" `
            -RestartRequired "No"
    }

    if ($defender.BehaviorMonitorEnabled -eq $true) {
        Add-ControlResult `
            -Id "WIN-DEF-002" `
            -ControlMapping "Malware Defense / Behavior Monitoring" `
            -Severity "High" `
            -Status "Pass" `
            -Finding "Defender behavior monitoring is enabled." `
            -Evidence "BehaviorMonitorEnabled = True" `
            -WhyItMatters "Behavior monitoring helps detect suspicious activity and malware behavior." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-DEF-002" `
            -ControlMapping "Malware Defense / Behavior Monitoring" `
            -Severity "High" `
            -Status "Fail" `
            -Finding "Defender behavior monitoring is disabled." `
            -Evidence "BehaviorMonitorEnabled = False" `
            -WhyItMatters "Disabled behavior monitoring reduces malware detection capability." `
            -Recommendation "Enable Defender behavior monitoring." `
            -RemediationCommand 'Set-MpPreference -DisableBehaviorMonitoring $false' `
            -ManualSteps "Windows Security > Virus & threat protection" `
            -RestartRequired "No"
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
    Write-Info "Error: $($_.Exception.Message)"
}

# ==============================
# DEFENDER ADVANCED SETTINGS
# ==============================

Write-Header "6. DEFENDER ADVANCED SETTINGS"

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
        Add-ControlResult `
            -Id "WIN-DEF-003" `
            -ControlMapping "Malware Defense / Potentially Unwanted Applications" `
            -Severity "Medium" `
            -Status "Fail" `
            -Finding "Potentially unwanted app protection is disabled." `
            -Evidence "PUAProtection = 0" `
            -WhyItMatters "PUA protection helps block unwanted bundled software and suspicious applications." `
            -Recommendation "Enable Defender PUA protection." `
            -RemediationCommand "Set-MpPreference -PUAProtection Enabled" `
            -ManualSteps "Windows Security > App & browser control > Reputation-based protection" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-DEF-003" `
            -ControlMapping "Malware Defense / Potentially Unwanted Applications" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Potentially unwanted app protection is enabled." `
            -Evidence "PUAProtection = $($mpPref.PUAProtection)" `
            -WhyItMatters "PUA protection helps reduce unwanted software risk." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
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

    if ($mpPref.EnableControlledFolderAccess -eq 1) {
        Add-ControlResult `
            -Id "WIN-DEF-004" `
            -ControlMapping "Malware Defense / Ransomware Protection" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Controlled Folder Access is enabled." `
            -Evidence "EnableControlledFolderAccess = Enabled" `
            -WhyItMatters "Controlled Folder Access can protect key folders from unauthorized modification." `
            -Recommendation "Review allowed apps if business applications are blocked." `
            -RemediationCommand "" `
            -ManualSteps "Windows Security > Virus & threat protection > Ransomware protection" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-DEF-004" `
            -ControlMapping "Malware Defense / Ransomware Protection" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "Controlled Folder Access is not enabled." `
            -Evidence "EnableControlledFolderAccess = $($mpPref.EnableControlledFolderAccess)" `
            -WhyItMatters "Controlled Folder Access can reduce ransomware impact but may require app allowlisting." `
            -Recommendation "Consider enabling Controlled Folder Access after testing important apps." `
            -RemediationCommand "Set-MpPreference -EnableControlledFolderAccess Enabled" `
            -ManualSteps "Windows Security > Virus & threat protection > Ransomware protection" `
            -RestartRequired "No"
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

Write-Header "7. MICROSOFT DEFENDER SCAN"

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
# BITLOCKER
# ==============================

Write-Header "8. DRIVE ENCRYPTION STATUS"

try {
    $bitlocker = Get-BitLockerVolume

    $bitlocker | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, ProtectionStatus |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $bitlocker | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, ProtectionStatus |
    Export-Csv "$ReportDir\BitLocker_Status.csv" -NoTypeInformation

    foreach ($vol in $bitlocker) {
        if ($vol.ProtectionStatus -eq "On") {
            Add-ControlResult `
                -Id "WIN-BL-001-$($vol.MountPoint)" `
                -ControlMapping "Data Protection / Drive Encryption" `
                -Severity "Medium" `
                -Status "Pass" `
                -Finding "Drive encryption protection is on for $($vol.MountPoint)." `
                -Evidence "VolumeStatus = $($vol.VolumeStatus), ProtectionStatus = $($vol.ProtectionStatus)" `
                -WhyItMatters "Drive encryption protects data if the device is lost or stolen." `
                -Recommendation "Keep recovery key stored safely." `
                -RemediationCommand "" `
                -ManualSteps "Control Panel > BitLocker Drive Encryption" `
                -RestartRequired "No"
        } else {
            Add-ControlResult `
                -Id "WIN-BL-001-$($vol.MountPoint)" `
                -ControlMapping "Data Protection / Drive Encryption" `
                -Severity "Medium" `
                -Status "Fail" `
                -Finding "Drive encryption protection is off for $($vol.MountPoint)." `
                -Evidence "VolumeStatus = $($vol.VolumeStatus), ProtectionStatus = $($vol.ProtectionStatus)" `
                -WhyItMatters "Without drive encryption, data may be readable if the laptop or drive is stolen." `
                -Recommendation "Enable BitLocker or Device Encryption after saving the recovery key." `
                -RemediationCommand "Get-BitLockerVolume" `
                -ManualSteps "Settings > Update & Security > Device encryption OR Control Panel > BitLocker Drive Encryption" `
                -RestartRequired "Possibly"
        }
    }

    Write-Info "This script does not automatically enable BitLocker."
} catch {
    Write-Info "Could not check BitLocker status. This may be limited by Windows edition."

    Add-ControlResult `
        -Id "WIN-BL-001" `
        -ControlMapping "Data Protection / Drive Encryption" `
        -Severity "Medium" `
        -Status "Review" `
        -Finding "Drive encryption status could not be checked." `
        -Evidence $_.Exception.Message `
        -WhyItMatters "Drive encryption protects local data at rest." `
        -Recommendation "Check Device Encryption or BitLocker manually." `
        -RemediationCommand "Get-BitLockerVolume" `
        -ManualSteps "Settings > Update & Security > Device encryption" `
        -RestartRequired "No"
}

# ==============================
# TPM
# ==============================

Write-Header "9. TPM STATUS"

try {
    $tpm = Get-Tpm
    $tpm | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned, RestartPending |
    Export-Csv "$ReportDir\TPM_Status.csv" -NoTypeInformation

    if ($tpm.TpmPresent -eq $true -and $tpm.TpmReady -eq $true -and $tpm.TpmEnabled -eq $true) {
        Add-ControlResult `
            -Id "WIN-TPM-001" `
            -ControlMapping "Hardware Security / TPM" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "TPM is present and ready." `
            -Evidence "TpmPresent=$($tpm.TpmPresent), TpmReady=$($tpm.TpmReady), TpmEnabled=$($tpm.TpmEnabled)" `
            -WhyItMatters "TPM supports stronger device encryption and key protection." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "BIOS/UEFI TPM settings" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-TPM-001" `
            -ControlMapping "Hardware Security / TPM" `
            -Severity "Medium" `
            -Status "Fail" `
            -Finding "TPM is not ready." `
            -Evidence "TpmPresent=$($tpm.TpmPresent), TpmReady=$($tpm.TpmReady), TpmEnabled=$($tpm.TpmEnabled)" `
            -WhyItMatters "TPM readiness is important for secure device encryption." `
            -Recommendation "Check BIOS/UEFI TPM settings." `
            -RemediationCommand "Get-Tpm" `
            -ManualSteps "BIOS/UEFI > Security > TPM / Intel PTT" `
            -RestartRequired "Yes"
    }

    if ($tpm.RestartPending -eq $true) {
        Add-ControlResult `
            -Id "WIN-TPM-002" `
            -ControlMapping "Hardware Security / TPM" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "TPM restart is pending." `
            -Evidence "RestartPending = True" `
            -WhyItMatters "Some TPM state changes require a restart before encryption changes." `
            -Recommendation "Restart Windows before enabling drive encryption." `
            -RemediationCommand "Restart-Computer" `
            -ManualSteps "Start > Power > Restart" `
            -RestartRequired "Yes"
    }
} catch {
    Write-Info "Could not check TPM status."
}

# ==============================
# ACCOUNT POLICY
# ==============================

Write-Header "10. PASSWORD AND LOCKOUT POLICY"

try {
    $netAccounts = net accounts
    $netAccounts | Tee-Object -FilePath $FullReportFile -Append

    if ($netAccounts -match "Lockout threshold:\s+Never") {
        Add-ControlResult `
            -Id "WIN-PWD-001" `
            -ControlMapping "Account Security Policy / Lockout" `
            -Severity "Medium" `
            -Status "Fail" `
            -Finding "Account lockout threshold is not configured." `
            -Evidence "Lockout threshold = Never" `
            -WhyItMatters "No lockout threshold may allow repeated password guessing attempts." `
            -Recommendation "Set lockout threshold to reduce brute-force risk." `
            -RemediationCommand "net accounts /lockoutthreshold:5" `
            -ManualSteps "Use local security policy where available or net accounts command." `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-PWD-001" `
            -ControlMapping "Account Security Policy / Lockout" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Account lockout threshold appears configured." `
            -Evidence "Lockout threshold is not Never" `
            -WhyItMatters "Lockout policies help reduce brute-force password attacks." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
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
# LOCAL ADMINS
# ==============================

Write-Header "11. LOCAL ADMINISTRATORS"

try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    $admins | Select-Object Name, ObjectClass, PrincipalSource |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $admins | Select-Object Name, ObjectClass, PrincipalSource |
    Export-Csv "$ReportDir\Local_Admins.csv" -NoTypeInformation

    if ($admins.Count -gt 2) {
        Add-ControlResult `
            -Id "WIN-ADM-001" `
            -ControlMapping "Privileged Access Management / Local Administrators" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "More than two local administrators found." `
            -Evidence "Admin count = $($admins.Count)" `
            -WhyItMatters "Excessive local admin membership increases privilege abuse risk." `
            -Recommendation "Review local Administrators group and remove unnecessary admin access manually." `
            -RemediationCommand "Get-LocalGroupMember -Group Administrators" `
            -ManualSteps "Computer Management > Local Users and Groups > Groups > Administrators" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-ADM-001" `
            -ControlMapping "Privileged Access Management / Local Administrators" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "Local administrator count appears limited." `
            -Evidence "Admin count = $($admins.Count)" `
            -WhyItMatters "Limiting local admins reduces privilege escalation risk." `
            -Recommendation "Review periodically." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "This script does not remove administrator accounts automatically."
} catch {
    Write-Info "Could not read local administrators."
}

# ==============================
# LOCAL USERS
# ==============================

Write-Header "12. LOCAL USERS"

try {
    $users = Get-LocalUser
    $users | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $users | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
    Export-Csv "$ReportDir\Local_Users.csv" -NoTypeInformation

    $enabledNoPasswordUsers = $users | Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -ne $true }

    if ($enabledNoPasswordUsers.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-USR-001" `
            -ControlMapping "Account Security / Local Users" `
            -Severity "High" `
            -Status "Fail" `
            -Finding "One or more enabled users do not require a password." `
            -Evidence "Count = $($enabledNoPasswordUsers.Count)" `
            -WhyItMatters "Enabled accounts without password requirements create unauthorized access risk." `
            -Recommendation "Require passwords or disable unnecessary accounts." `
            -RemediationCommand "Get-LocalUser" `
            -ManualSteps "Computer Management > Local Users and Groups > Users" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-USR-001" `
            -ControlMapping "Account Security / Local Users" `
            -Severity "High" `
            -Status "Pass" `
            -Finding "No enabled local users without password requirement detected." `
            -Evidence "Enabled no-password users = 0" `
            -WhyItMatters "Password-required accounts reduce unauthorized access risk." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "This script does not disable or modify user accounts automatically."
} catch {
    Write-Info "Could not read local users."
}

# ==============================
# SMB
# ==============================

Write-Header "13. SMB CONFIGURATION"

try {
    $smb = Get-SmbServerConfiguration
    $smbSummary = $smb | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature

    $smbSummary | Format-List | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $smbSummary | Export-Csv "$ReportDir\SMB_Config.csv" -NoTypeInformation

    if ($smb.EnableSMB1Protocol -eq $true) {
        Add-ControlResult `
            -Id "WIN-SMB-001" `
            -ControlMapping "Legacy Protocol Hardening / SMB" `
            -Severity "High" `
            -Status "Fail" `
            -Finding "SMBv1 is enabled." `
            -Evidence "EnableSMB1Protocol = True" `
            -WhyItMatters "SMBv1 is a legacy protocol associated with serious security risks." `
            -Recommendation "Disable SMBv1 unless absolutely required." `
            -RemediationCommand "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -ManualSteps "Windows Features > SMB 1.0/CIFS File Sharing Support > Off" `
            -RestartRequired "Yes"

        if (Confirm-Action "SMBv1 is enabled. Disable SMBv1?") {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
            Write-Info "SMBv1 disable command executed. Restart may be required."
            Record-Action "Disabled SMBv1" "Taken"
        } else {
            Record-Action "Disable SMBv1" "Skipped"
        }
    } else {
        Add-ControlResult `
            -Id "WIN-SMB-001" `
            -ControlMapping "Legacy Protocol Hardening / SMB" `
            -Severity "High" `
            -Status "Pass" `
            -Finding "SMBv1 is disabled." `
            -Evidence "EnableSMB1Protocol = False" `
            -WhyItMatters "Disabling SMBv1 removes a legacy attack surface." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    if ($smb.RequireSecuritySignature -eq $true) {
        Add-ControlResult `
            -Id "WIN-SMB-002" `
            -ControlMapping "Network Security / SMB Signing" `
            -Severity "Low" `
            -Status "Pass" `
            -Finding "SMB signing is required." `
            -Evidence "RequireSecuritySignature = True" `
            -WhyItMatters "SMB signing helps protect against tampering and relay-style attacks." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-SMB-002" `
            -ControlMapping "Network Security / SMB Signing" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "SMB signing is not required." `
            -Evidence "RequireSecuritySignature = False" `
            -WhyItMatters "Requiring SMB signing can strengthen file sharing security, but may affect compatibility." `
            -Recommendation "Consider requiring SMB signing if compatible with your environment." `
            -RemediationCommand "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
            -ManualSteps "Review SMB compatibility before enforcing." `
            -RestartRequired "No"
    }
} catch {
    Write-Info "Could not check SMB configuration."
}

# ==============================
# SHARED FOLDERS
# ==============================

Write-Header "14. SHARED FOLDERS"

try {
    $shares = Get-SmbShare
    $shares | Select-Object Name, Path, Description |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append

    $shares | Select-Object Name, Path, Description |
    Export-Csv "$ReportDir\Shared_Folders.csv" -NoTypeInformation

    $defaultShares = @("ADMIN$", "C$", "D$", "E$", "IPC$", "print$")
    $nonDefaultShares = $shares | Where-Object { $_.Name -notin $defaultShares }

    if ($nonDefaultShares.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-SHARE-001" `
            -ControlMapping "File Sharing / SMB Shares" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "Non-default SMB shares were found." `
            -Evidence "Share count = $($nonDefaultShares.Count)" `
            -WhyItMatters "Unnecessary shares may expose files to other network users." `
            -Recommendation "Review shared folders and remove unnecessary shares manually." `
            -RemediationCommand "Get-SmbShare" `
            -ManualSteps "Computer Management > Shared Folders > Shares" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-SHARE-001" `
            -ControlMapping "File Sharing / SMB Shares" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "No non-default SMB shares found." `
            -Evidence "Non-default share count = 0" `
            -WhyItMatters "Fewer shares reduce network file exposure." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "This script does not remove shares automatically."
} catch {
    Write-Info "Could not check SMB shares."
}

# ==============================
# OPEN PORTS
# ==============================

Write-Header "15. LISTENING NETWORK PORTS"

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
            LocalAddress = $port.LocalAddress
            LocalPort    = $port.LocalPort
            PID          = $port.OwningProcess
            ProcessName  = $procName
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
        Add-ControlResult `
            -Id "WIN-NET-001" `
            -ControlMapping "Network Exposure Review / Listening Ports" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "Network-facing listening ports detected." `
            -Evidence "External listener count = $($externalListeners.Count)" `
            -WhyItMatters "Network-facing listeners may expose services to the local network." `
            -Recommendation "Review listening ports and confirm they are expected." `
            -RemediationCommand "Get-NetTCPConnection -State Listen" `
            -ManualSteps "Review Listening_Ports_With_Processes.csv" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-NET-001" `
            -ControlMapping "Network Exposure Review / Listening Ports" `
            -Severity "Low" `
            -Status "Pass" `
            -Finding "No network-facing listening ports detected." `
            -Evidence "External listener count = 0" `
            -WhyItMatters "Lower network exposure reduces attack surface." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "Open ports exported to CSV for review."
} catch {
    Write-Info "Could not collect listening ports."
}

# ==============================
# INSTALLED PROGRAMS
# ==============================

Write-Header "16. INSTALLED PROGRAMS"

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

    $reviewKeywords = @("WinRAR", "PuTTY", "Java", "Python", "Anaconda", "Node", "Go ", "OpenSSL", "Npcap", "SQL Server")

    $softwareReviewMatches = @()

    foreach ($keyword in $reviewKeywords) {
        $softwareReviewMatches += $installedPrograms | Where-Object { $_.DisplayName -like "*$keyword*" }
    }

    if ($softwareReviewMatches.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-SW-001" `
            -ControlMapping "Software Inventory / Patch Hygiene" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "Software requiring periodic update review was found." `
            -Evidence "Review match count = $($softwareReviewMatches.Count)" `
            -WhyItMatters "Outdated developer tools, archive tools, and network tools may increase exploitation risk." `
            -Recommendation "Review Installed_Programs.csv and update or remove unused software." `
            -RemediationCommand "" `
            -ManualSteps "Settings > Apps > Installed apps" `
            -RestartRequired "Possibly"
    } else {
        Add-ControlResult `
            -Id "WIN-SW-001" `
            -ControlMapping "Software Inventory / Patch Hygiene" `
            -Severity "Low" `
            -Status "Pass" `
            -Finding "No software matched the review keyword list." `
            -Evidence "Review match count = 0" `
            -WhyItMatters "Fewer outdated tools reduce attack surface." `
            -Recommendation "Continue keeping software updated." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "Installed programs exported to Installed_Programs.csv."
} catch {
    Write-Info "Could not collect installed programs."
}

# ==============================
# STARTUP APPS
# ==============================

Write-Header "17. STARTUP APPLICATIONS"

try {
    $startup = Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User

    $startup | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $startup | Export-Csv "$ReportDir\Startup_Apps.csv" -NoTypeInformation

    $userWritableStartup = $startup | Where-Object {
        $_.Command -match "\\AppData\\" -or $_.Command -match "\\Temp\\"
    }

    if ($userWritableStartup.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-STARTUP-001" `
            -ControlMapping "Persistence Review / Startup Applications" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "Startup items running from user-writable locations were found." `
            -Evidence "Count = $($userWritableStartup.Count)" `
            -WhyItMatters "User-writable startup locations are commonly abused for persistence." `
            -Recommendation "Review Startup_Apps.csv and disable unknown or unnecessary items." `
            -RemediationCommand "" `
            -ManualSteps "Task Manager > Startup apps" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-STARTUP-001" `
            -ControlMapping "Persistence Review / Startup Applications" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "No startup items from common user-writable locations detected." `
            -Evidence "Count = 0" `
            -WhyItMatters "This reduces common persistence risk." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "Startup applications exported to Startup_Apps.csv."
} catch {
    Write-Info "Could not collect startup applications."
}

# ==============================
# SCHEDULED TASKS
# ==============================

Write-Header "18. ENABLED SCHEDULED TASKS"

try {
    $tasks = Get-ScheduledTask |
    Where-Object { $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, State

    $tasks | Export-Csv "$ReportDir\Scheduled_Tasks.csv" -NoTypeInformation

    Add-ControlResult `
        -Id "WIN-TASK-001" `
        -ControlMapping "Persistence Review / Scheduled Tasks" `
        -Severity "Low" `
        -Status "Review" `
        -Finding "Enabled scheduled tasks were exported for review." `
        -Evidence "Task count = $($tasks.Count)" `
        -WhyItMatters "Scheduled tasks are a common legitimate mechanism and also a persistence technique." `
        -Recommendation "Review Scheduled_Tasks.csv for unknown or suspicious tasks." `
        -RemediationCommand "Get-ScheduledTask | Where-Object { `$_.State -ne 'Disabled' }" `
        -ManualSteps "Task Scheduler" `
        -RestartRequired "No"

    Write-Info "Scheduled tasks exported to Scheduled_Tasks.csv."
} catch {
    Write-Info "Could not collect scheduled tasks."
}

# ==============================
# SERVICES
# ==============================

Write-Header "19. SERVICES REVIEW"

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
    Export-Csv "$ReportDir\Unquoted_ThirdParty_Service_Paths.csv" -NoTypeInformation

    if ($unquotedThirdParty.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-SVC-001" `
            -ControlMapping "Service Hardening / Unquoted Paths" `
            -Severity "Medium" `
            -Status "Review" `
            -Finding "Third-party services with unquoted paths found." `
            -Evidence "Count = $($unquotedThirdParty.Count)" `
            -WhyItMatters "Unquoted service paths can sometimes create privilege escalation risk." `
            -Recommendation "Review Unquoted_ThirdParty_Service_Paths.csv before changing anything." `
            -RemediationCommand "" `
            -ManualSteps "Review service path and vendor documentation manually." `
            -RestartRequired "Possibly"
    } else {
        Add-ControlResult `
            -Id "WIN-SVC-001" `
            -ControlMapping "Service Hardening / Unquoted Paths" `
            -Severity "Medium" `
            -Status "Pass" `
            -Finding "No third-party unquoted service paths detected by this filter." `
            -Evidence "Count = 0" `
            -WhyItMatters "This reduces a common Windows privilege escalation pattern." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }

    Write-Info "Services exported to Services.csv."
} catch {
    Write-Info "Could not collect services."
}

# ==============================
# BROWSER EXTENSIONS
# ==============================

Write-Header "20. BROWSER EXTENSION LOCATIONS"

try {
    $chromeExt = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    $edgeExt = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

    $browserExtResults = @()

    if (Test-Path $chromeExt) {
        $chromeItems = Get-ChildItem $chromeExt -Directory -ErrorAction SilentlyContinue

        foreach ($item in $chromeItems) {
            $browserExtResults += [PSCustomObject]@{
                Browser     = "Chrome"
                ExtensionId = $item.Name
                Path        = $item.FullName
            }
        }
    }

    if (Test-Path $edgeExt) {
        $edgeItems = Get-ChildItem $edgeExt -Directory -ErrorAction SilentlyContinue

        foreach ($item in $edgeItems) {
            $browserExtResults += [PSCustomObject]@{
                Browser     = "Edge"
                ExtensionId = $item.Name
                Path        = $item.FullName
            }
        }
    }

    $browserExtResults | Export-Csv "$ReportDir\Browser_Extension_Folders.csv" -NoTypeInformation

    if ($browserExtResults.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-BROWSER-001" `
            -ControlMapping "Browser Security / Extensions" `
            -Severity "Low" `
            -Status "Review" `
            -Finding "Browser extension folders were found." `
            -Evidence "Extension folder count = $($browserExtResults.Count)" `
            -WhyItMatters "Browser extensions can access sensitive browser activity depending on permissions." `
            -Recommendation "Review Chrome and Edge extensions manually and remove anything unused or unknown." `
            -RemediationCommand "" `
            -ManualSteps "Chrome: chrome://extensions | Edge: edge://extensions" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-BROWSER-001" `
            -ControlMapping "Browser Security / Extensions" `
            -Severity "Low" `
            -Status "Pass" `
            -Finding "No browser extension folders found in default profile locations." `
            -Evidence "Extension folder count = 0" `
            -WhyItMatters "Fewer extensions can reduce browser attack surface." `
            -Recommendation "No action required." `
            -RemediationCommand "" `
            -ManualSteps "" `
            -RestartRequired "No"
    }
} catch {
    Write-Info "Could not collect browser extension folders."
}

# ==============================
# WINDOWS HOTFIXES
# ==============================

Write-Header "21. WINDOWS UPDATE HOTFIXES"

try {
    $hotfixes = Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object HotFixID, Description, InstalledOn

    $hotfixes | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $hotfixes | Export-Csv "$ReportDir\Windows_Hotfixes.csv" -NoTypeInformation

    Add-ControlResult `
        -Id "WIN-UPD-001" `
        -ControlMapping "Patch Management / Windows Updates" `
        -Severity "Medium" `
        -Status "Review" `
        -Finding "Windows hotfix history was exported for review." `
        -Evidence "Hotfix count = $($hotfixes.Count)" `
        -WhyItMatters "Patch status is critical to reducing vulnerability exposure." `
        -Recommendation "Check Windows Update manually and install pending updates." `
        -RemediationCommand "Get-HotFix | Sort-Object InstalledOn -Descending" `
        -ManualSteps "Settings > Update & Security > Windows Update" `
        -RestartRequired "Possibly"
} catch {
    Write-Info "Could not collect Windows hotfixes."
}

# ==============================
# ANTIVIRUS PRODUCTS
# ==============================

Write-Header "22. REGISTERED ANTIVIRUS PRODUCTS"

try {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, productState, pathToSignedProductExe

    $av | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $FullReportFile -Append
    $av | Export-Csv "$ReportDir\Registered_Antivirus.csv" -NoTypeInformation

    if ($av.Count -gt 0) {
        Add-ControlResult `
            -Id "WIN-AV-001" `
            -ControlMapping "Malware Defense / Antivirus Registration" `
            -Severity "High" `
            -Status "Pass" `
            -Finding "Antivirus product is registered in Windows Security Center." `
            -Evidence "AV count = $($av.Count)" `
            -WhyItMatters "Registered antivirus helps ensure Windows recognizes active malware protection." `
            -Recommendation "Confirm antivirus status remains healthy." `
            -RemediationCommand "" `
            -ManualSteps "Windows Security > Virus & threat protection" `
            -RestartRequired "No"
    } else {
        Add-ControlResult `
            -Id "WIN-AV-001" `
            -ControlMapping "Malware Defense / Antivirus Registration" `
            -Severity "High" `
            -Status "Fail" `
            -Finding "No antivirus product was found in Windows Security Center." `
            -Evidence "AV count = 0" `
            -WhyItMatters "Lack of registered antivirus may indicate insufficient malware protection." `
            -Recommendation "Enable Microsoft Defender or install a trusted antivirus." `
            -RemediationCommand "" `
            -ManualSteps "Windows Security > Virus & threat protection" `
            -RestartRequired "No"
    }
} catch {
    Write-Info "Could not collect registered antivirus products."
}

# ==============================
# FINAL REPORTS
# ==============================

Write-Header "23. FINAL RISK SUMMARY"

$SecurityScore = Get-SecurityScore
$SecurityRating = Get-SecurityRating -Score $SecurityScore

$HighCount = ($ControlResults | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "High" }).Count
$MediumCount = ($ControlResults | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Medium" }).Count
$LowCount = ($ControlResults | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Low" }).Count
$PassCount = ($ControlResults | Where-Object { $_.Status -eq "Pass" }).Count
$FailCount = ($ControlResults | Where-Object { $_.Status -eq "Fail" }).Count
$ReviewCount = ($ControlResults | Where-Object { $_.Status -eq "Review" }).Count

Write-Info "Security Score: $SecurityScore / 100"
Write-Info "Security Rating: $SecurityRating"
Write-Info "High Findings: $HighCount"
Write-Info "Medium Findings: $MediumCount"
Write-Info "Low Findings: $LowCount"
Write-Info "Pass Controls: $PassCount"
Write-Info "Fail Controls: $FailCount"
Write-Info "Review Controls: $ReviewCount"

$ControlResults | Export-Csv $ControlCsv -NoTypeInformation
$RiskFindings | Export-Csv $RiskCsv -NoTypeInformation
$ActionsTaken | Export-Csv $ActionsCsv -NoTypeInformation

$summary = @"
WINDOWS SECURITY HARDENING SUMMARY
Generated: $(Get-Date)
Toolkit Version: $ScriptVersion
Computer: $env:COMPUTERNAME
User: $env:USERNAME

REPORT LOCATION:
$ReportDir

SECURITY SCORE:
$SecurityScore / 100

SECURITY RATING:
$SecurityRating

CONTROL COUNTS:
High Findings:   $HighCount
Medium Findings: $MediumCount
Low Findings:    $LowCount
Passed Controls: $PassCount
Failed Controls: $FailCount
Review Controls: $ReviewCount

ACTIONS TAKEN:
$($ActionsTaken.Action -join "`n")

ACTIONS SKIPPED:
$($ActionsSkipped.Action -join "`n")

RECOMMENDED NEXT STEPS:
1. Open Security_Dashboard.html.
2. Review Top Recommended Fixes.
3. Review Control_Results.csv.
4. Review Risk_Findings.csv.
5. Fix failed controls first.
6. Review items marked Review manually.
7. Re-run this script after remediation.
"@

Set-Content -Path $SummaryFile -Value $summary

New-HtmlDashboard `
    -Path $HtmlReportFile `
    -SecurityScore $SecurityScore `
    -SecurityRating $SecurityRating `
    -HighCount $HighCount `
    -MediumCount $MediumCount `
    -LowCount $LowCount `
    -PassCount $PassCount `
    -FailCount $FailCount `
    -ReviewCount $ReviewCount

Write-Header "24. COMPLETE"

Write-Info "Security toolkit completed."
Write-Info "Security Score: $SecurityScore / 100"
Write-Info "Security Rating: $SecurityRating"
Write-Info "Summary report: $SummaryFile"
Write-Info "Full report: $FullReportFile"
Write-Info "HTML dashboard: $HtmlReportFile"
Write-Info "Risk CSV: $RiskCsv"
Write-Info "Control CSV: $ControlCsv"

Write-Host ""
Write-Host "Done. Reports saved here:"
Write-Host $ReportDir
Write-Host ""

Start-Process $HtmlReportFile