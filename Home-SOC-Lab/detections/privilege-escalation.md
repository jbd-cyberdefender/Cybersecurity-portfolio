# Detection: Privilege Escalation Enumeration

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Discovery / Privilege Escalation |
| **MITRE Technique** | T1069 — Permission Groups Discovery / T1033 — System Owner Discovery |
| **Event ID** | 4672 — Special Privileges Assigned / 4688 — Process Creation |
| **Severity** | Medium |
| **Tool Used** | Windows built-in commands |
| **Source** | W11SOC — local execution |
| **Target** | W11SOC (192.168.250.129) |

---

## What Is This Attack?

After gaining initial access, attackers enumerate their privilege level and look for paths to escalate to Administrator or SYSTEM. They run discovery commands to understand user account structure, group memberships, and available privileges — using this intelligence to identify misconfigured accounts or exploitable privilege assignments.

---

## Attack Commands

```cmd
whoami /priv
whoami /groups
net localgroup administrators
net user
```

---

## Splunk Detection Queries

```spl
index=windows EventCode=4672
| table _time, Account_Name, Privileges
| sort - _time
```

```spl
index=windows EventCode=4688
| search CommandLine="*whoami*" OR CommandLine="*net localgroup*" OR CommandLine="*net user*"
| table _time, Account_Name, CommandLine
| sort - _time
```

**Alert Threshold:** Multiple enumeration commands from same account within 60 seconds.

---

## Evidence

![Privilege Escalation](../screenshots/privilege-escalation.png)

---

## Remediation

- Apply Principle of Least Privilege — users only get minimum required permissions
- Audit local Administrators group membership regularly
- Alert on rapid succession of whoami and net commands from same process
- Implement Privileged Access Workstations (PAWs) for admin tasks
- Use Windows Defender Credential Guard
