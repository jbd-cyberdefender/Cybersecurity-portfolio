# Detection: Security Log Clearing (Anti-Forensics)

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Event ID** | 1102 — Security Audit Log Cleared / 104 — System Log Cleared |
| **Severity** |  Critical |
| **Tool Used** | wevtutil (Windows built-in) |
| **Source** | W11SOC — local execution |
| **Target** | W11SOC (192.168.250.129) |

---

## What Is This Attack?

Log clearing is an anti-forensics technique used after an attack to erase evidence of malicious activity. Attackers clear Windows event logs to remove records of failed logins, executed processes, files accessed, and accounts created. 

**Key insight:** Clearing the Security log generates EventCode 1102 before the log is wiped. Since Splunk forwards logs in real time, this event is already in Splunk before the local log is cleared — making this one of the few attacks where the attacker's cleanup action itself becomes the detection.

---

## Attack Commands

```cmd
wevtutil cl System
wevtutil cl Application
wevtutil cl Security

```

---

## Splunk Detection Query

```spl
index=windows EventCode=1102 OR EventCode=104
| table _time, Account_Name, Message
| sort - _time
```

**Alert:** Any EventCode 1102 is an immediate critical incident — Security log clearing should never happen in a healthy environment.

---

## Evidence

 ![Splunk screenshot here showing EventCode 1102 log clearing detection](../screenshots/log-clearing-splunk.png)

---


## Remediation

- Forward all logs to SIEM in real time — logs cleared locally are preserved in Splunk
- Alert immediately on EventCode 1102 — requires immediate investigation
- Restrict wevtutil clear-log permissions via Group Policy
- Enable log archiving before clearing
- Implement write-once log storage so logs cannot be deleted by any account
