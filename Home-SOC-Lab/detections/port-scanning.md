# Detection: Network Port Scanning

## Overview

| Field | Detail |
|---|---|
| **MITRE Tactic** | Discovery |
| **MITRE Technique** | T1046 — Network Service Scanning |
| **Event ID** | Sysmon EventCode 3 — Network Connection |
| **Severity** |  Medium |
| **Tool Used** | Nmap |
| **Source** | Kali Linux (192.168.250.130) |
| **Target** | Windows 11 (192.168.250.129) |

---

## What Is This Attack?

Port scanning is the reconnaissance phase — the first thing attackers do after identifying a target. By scanning all ports, the attacker maps the attack surface: which services are running, what software versions are in use, and what OS the target runs. This intelligence informs which specific exploits to use next.

---

## Attack Command

```bash
nmap -sV -O -A 192.168.250.129

```

## Results of Scan

Four open ports were discovered from the scan. Ports 135, 139, 445 and 3389. These are the vulnerabilties of each port being open.

Port 135 (MSRPC / RPC Endpoint Mapper): Susceptible to unauthenticated RPC interface enumeration.

Port 139 (NetBIOS Session Service): Vulnerable to null session enumeration for harvesting users, groups, and shares without authentication, as well as NetBIOS Name Service (NBNS) spoofing.

Port 445 (SMB over TCP): High-risk vector for unauthenticated SYSTEM-level remote code execution (e.g., MS17-010 EternalBlue, CVE-2020-0796 SMBGhost), NTLM relay attacks when SMB signing is disabled, and administrative lateral movement via C$ and ADMIN$ shares.

Port 3389 (RDP - Remote Desktop Protocol): Exposed to pre-authentication remote code execution  password spraying/brute-force credential attacks, and post-exploitation desktop session hijacking (tscon.exe).

# Evidence
![nmap port scan ran on Kali Linux](/screenshots/port-scan-nmap.png)
---

## Splunk Detection Query

```spl
index=sysmon EventCode=3
| stats count by SourceIp, DestinationPort
| where count > 20
| sort - count
```

**Alert Threshold:** One IP connecting to more than 20 distinct ports within 60 seconds.

---

## Evidence

![Port Scan shown on Splunk](/screenshots/port-scan-splunk.png)

---

## Remediation

- Deploy an IDS/IPS (Snort, Suricata) to detect scan patterns
- Block all inbound traffic except explicitly required ports
- Alert on single IP connecting to 20+ ports in 60 seconds
- Implement network segmentation to limit scan visibility
