# Detection: Backdoor Account Creation

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | T1136.001 — Create Account: Local Account |
| **Event ID** | 4720 — User Account Created / 4732 — Member Added to Admin Group |
| **Severity** | 🔴 Critical |
| **Tool Used** | Windows net command |
| **Source** | W11SOC — local execution |
| **Target** | W11SOC (192.168.250.129) |

---

## What Is This Attack?

Creating a backdoor administrator account is one of the first persistence techniques attackers use after gaining access. Even if the original vulnerability is patched, they can return via their created account. This is Critical severity because it grants permanent, privileged access that survives reboots and remediation attempts if not detected.

---

## Attack Commands

```cmd
net user hacker Password123! /add
net localgroup administrators hacker /add
```

---

## Splunk Detection Query

```spl
index=windows EventCode=4720 OR EventCode=4732
| table _time, Account_Name, SAMAccountName, Message
| sort - _time
```

**Alert:** Any EventCode 4720 or 4732 should be treated as a critical alert — account creation and admin group changes are rare in healthy environments.

---

## Evidence

![Account Creation](../screenshots/account-creation-cmd.png
)
---

## Cleanup

```cmd
net user hacker /delete
```

---

## Remediation

- Alert immediately on EventCode 4720 and 4732 — these should be rare
- Restrict account creation to designated administrators only via Group Policy
- Quarterly review of all local user accounts
- Consider disabling local Administrator account entirely
- Use domain accounts with MFA for all administrative access
