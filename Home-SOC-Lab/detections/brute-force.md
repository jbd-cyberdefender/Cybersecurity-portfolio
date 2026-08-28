# Detection: Brute Force Login Attack

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1110.001 — Brute Force: Password Guessing |
| **Event ID** | 4625 — An account failed to log on |
| **Severity** | 🔴 High |
| **Tool Used** | xfreerdp3 |
| **Source** | Kali Linux (192.168.250.130) |
| **Target** | Windows 11 (192.168.250.129) |

---

## What Is This Attack?

A brute force attack systematically tries password combinations against an authentication service until it finds the correct one. RDP (port 3389) is one of the most targeted services on the internet because it provides full remote desktop access once authenticated.

---

## Attack Command

```bash
for i in {1..30}; do
  xfreerdp3 /u:administrator /p:wrongpassword$i /v:192.168.250.129 /cert-ignore +auth-only 2>/dev/null
  echo "Attempt $i complete"
  sleep 1
done
```

---

## Splunk Detection Query

```spl
index=windows EventCode=4625
| stats count by Source_Network_Address, Account_Name, Logon_Type
| where count > 5
| sort - count
```

**Alert Threshold:** More than 5 failed logins from the same IP within 5 minutes.

---

## Evidence

> Add your Splunk screenshot here showing EventCode 4625 detections

**Key Fields to Observe:**
- `Source_Network_Address` — attacker IP (192.168.250.130)
- `Account_Name` — targeted account (administrator)
- `Logon_Type` — 3 (network logon)
- `count` — number of failed attempts

---

## Remediation

- Implement account lockout after 5 failed attempts
- Restrict RDP access to trusted IPs only via firewall
- Enable Network Level Authentication (NLA)
- Implement Multi-Factor Authentication on all remote access
- Consider moving RDP to a non-standard port
