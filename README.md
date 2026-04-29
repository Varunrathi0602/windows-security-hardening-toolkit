# Windows Security Hardening Toolkit

> A defensive PowerShell toolkit that audits Windows security settings and turns the results into an actionable HTML dashboard.

The Windows Security Hardening Toolkit is an interactive PowerShell-based security auditing and hardening tool for Windows 10 and Windows 11. It checks common endpoint security controls, identifies misconfigurations, calculates a security score out of 100, maps results to CIS-style control areas, and generates an HTML dashboard with evidence, recommendations, and remediation commands.

The toolkit is designed for defensive security, endpoint hardening, blue-team learning, and IAM/PAM security awareness. It is intentionally conservative: it asks before applying configuration changes and avoids destructive actions such as deleting files, removing users, uninstalling software, disabling random services, or enabling BitLocker automatically.

## Features

- Interactive Windows security audit
- Safe hardening prompts before applying changes
- Security score out of 100
- Overall security rating
- Pass / Fail / Review control status
- CIS-style control mapping
- Evidence-based findings
- Remediation guidance with PowerShell commands
- Auto-generated HTML dashboard
- Automatic dashboard launch after scan completion
- CSV and TXT report exports
- Windows Firewall audit and optional enablement
- Remote Desktop status check and optional disablement
- Microsoft Defender status and configuration checks
- Defender signature update
- Defender PUA protection configuration
- Defender cloud protection configuration
- Optional Defender quick/full scan
- BitLocker and TPM status reporting
- Local administrator review
- Local user review
- SMB configuration review
- Open port reporting
- Installed software inventory
- Startup application review
- Scheduled task export
- Service inventory
- Browser extension folder review

## Current Version

**v1.1**

### v1.1 Highlights

- Added HTML security dashboard
- Added security score out of 100
- Added security rating logic
- Added Pass / Fail / Review statuses
- Added CIS-style control mapping
- Added remediation guidance and commands
- Added exported control results CSV
- Added automatic dashboard launch after script completion

## Reports and Output

The script creates a timestamped report folder on the Desktop:
Windows_Security_Hardening_Report_<timestamp>

**Generated files may include:**
Security_Dashboard.html
Security_Summary.txt
Security_Full_Report.txt
Risk_Findings.csv
Control_Results.csv
Actions_Taken.csv
Firewall_Status.csv
Defender_Status.csv
Defender_Preferences.csv
BitLocker_Status.csv
TPM_Status.csv
Local_Admins.csv
Local_Users.csv
SMB_Config.csv
Shared_Folders.csv
Listening_Ports.csv
Listening_Ports_With_Processes.csv
Installed_Programs.csv
Startup_Apps.csv
Scheduled_Tasks.csv
Services.csv
Browser_Extension_Folders.csv
Windows_Hotfixes.csv
Registered_Antivirus.csv

**The main output is:**
Security_Dashboard.html

## Safety Notes

This toolkit is designed to be safe by default. It does not automatically perform destructive actions.

The script does **not** automatically:
- Delete files
- Remove users
- Uninstall software
- Delete scheduled tasks
- Disable random services
- Enable BitLocker
- Remove browser extensions

Any configuration change is interactive and requires user confirmation.

## Requirements

- Windows 10 or Windows 11
- PowerShell
- Administrator privileges


## How to Run

Follow these steps to run the Windows Security Hardening Toolkit for the first time.

### 1. Download the project

Download or clone this repository to your Windows machine.

Using Git:

```powershell
git clone https://github.com/Varunrathi0602/windows-security-hardening-toolkit.git
```

Then go into the project folder:

```powershell
cd windows-security-hardening-toolkit
```

Alternatively, you can download the repository as a ZIP file from GitHub, extract it, and open PowerShell inside the extracted folder.

---

### 2. Open PowerShell as Administrator

This script checks and optionally updates Windows security settings, so it must be run with Administrator privileges.

To open PowerShell as Administrator:

1. Click the **Start** menu.
2. Search for **PowerShell**.
3. Right-click **Windows PowerShell**.
4. Select **Run as administrator**.

---

### 3. Allow script execution for the current session

Windows may block PowerShell scripts by default. To allow this script to run only for the current PowerShell session, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

When prompted, type:

```text
Y
```

This does not permanently change your system-wide execution policy.

---

### 4. Run the toolkit

From inside the project folder, run:

```powershell
.\Windows_Security_Hardening_Toolkit.ps1
```

---

### 5. Answer the interactive prompts

The toolkit will ask before applying any security changes.

Recommended first-time answers:

| Prompt | Recommended Answer |
|---|---|
| Create a system restore point? | `Y` |
| Enable Windows Firewall if disabled? | `Y` |
| Disable Remote Desktop if enabled? | `Y` if you do not use RDP |
| Update Microsoft Defender signatures? | `Y` |
| Enable Defender protections? | `Y` |
| Enable Potentially Unwanted App protection? | `Y` |
| Enable Microsoft cloud protection? | `Y` |
| Enable Controlled Folder Access? | `N` for first run |
| Start Defender Quick Scan? | `Y` |
| Start Defender Full Scan? | `N` for first run |
| Set account lockout policy? | `Y` |

---

### 6. Review the generated dashboard

After the scan completes, the toolkit automatically opens the HTML dashboard in your default browser.

The dashboard file is saved in a timestamped folder on your Desktop:

```text
Windows_Security_Hardening_Report_<timestamp>
```

The main file to review is:

```text
Security_Dashboard.html
```

The dashboard includes:

- Security score out of 100
- Overall security rating
- High, medium, and low findings
- Pass / Fail / Review control results
- CIS-style control mapping
- Evidence for each finding
- Recommended remediation steps
- PowerShell commands for safe fixes

---

### 7. Review supporting report files

The toolkit also creates supporting TXT and CSV reports, including:

```text
Security_Summary.txt
Security_Full_Report.txt
Risk_Findings.csv
Control_Results.csv
Actions_Taken.csv
Firewall_Status.csv
Defender_Status.csv
BitLocker_Status.csv
TPM_Status.csv
Listening_Ports_With_Processes.csv
Installed_Programs.csv
Startup_Apps.csv
Scheduled_Tasks.csv
Services.csv
Browser_Extension_Folders.csv
```

Start with:

```text
Security_Dashboard.html
Risk_Findings.csv
Control_Results.csv
```

---

### 8. Apply fixes carefully

Review the recommendations in the dashboard before applying any manual fixes.

The script is designed to be safe by default. It does not automatically:

- Delete files
- Remove users
- Uninstall software
- Delete scheduled tasks
- Disable random services
- Enable BitLocker
- Remove browser extensions

---

### 9. Re-run the toolkit after remediation

After fixing issues, run the toolkit again:

```powershell
.\Windows_Security_Hardening_Toolkit.ps1
```

Compare the new dashboard score and findings with the previous report.
