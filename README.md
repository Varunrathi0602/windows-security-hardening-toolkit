\# Windows Security Hardening Toolkit



An interactive PowerShell toolkit for auditing and safely hardening common Windows security settings.



This tool is designed for personal Windows machines and cybersecurity learning. It checks key security controls, generates reports, and asks before applying safe configuration changes.



\## Features



\- Windows Firewall audit and optional enablement

\- Remote Desktop status check and optional disablement

\- Microsoft Defender status check

\- Defender signature update

\- Defender PUA protection configuration

\- Defender cloud protection configuration

\- Optional Defender quick/full scan

\- BitLocker and TPM status reporting

\- Local administrator review

\- Local user review

\- SMB configuration review

\- Open port reporting

\- Installed software inventory

\- Startup application review

\- Scheduled task export

\- Service inventory

\- Browser extension folder review

\- Risk findings CSV output

\- Full text report output



\## Safety Design



This script does \*\*not\*\* automatically:



\- Delete files

\- Remove users

\- Uninstall software

\- Delete scheduled tasks

\- Disable random services

\- Enable BitLocker

\- Remove browser extensions



Any configuration change is interactive and requires user confirmation.



\## Requirements



\- Windows 10 or Windows 11

\- PowerShell

\- Administrator privileges



\## How to Run



Open PowerShell as Administrator.



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\\Windows\_Security\_Hardening\_Toolkit.ps1

