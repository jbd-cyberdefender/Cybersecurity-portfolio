# SOC Dashboard — Splunk Queries

All queries used to build the SOC monitoring dashboard in Splunk. Each panel can be added to a dashboard via **Search & Reporting → Save As → Dashboard Panel**.

---

## Panel 1 — Failed Login Attempts Over Time

```spl
index=windows EventCode=4625
| timechart count span=1h
```

**Visualization:** Line chart
**Purpose:** Shows brute force attack spikes over time

---

## Panel 2 — Top Attacking IPs

```spl
index=windows EventCode=4625
| stats count by Source_Network_Address
| sort - count
| head 10
```

**Visualization:** Bar chart
**Purpose:** Identifies most active attack sources

---

## Panel 3 — Suspicious PowerShell Executions

```spl
index=windows EventCode=4688
| search CommandLine="*EncodedCommand*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"
| table _time, Account_Name, CommandLine
| sort - _time
```

**Visualization:** Table
**Purpose:** Catches obfuscated PowerShell in real time

---

## Panel 4 — Account Management Events

```spl
index=windows (EventCode=4720 OR EventCode=4732 OR EventCode=4740 OR EventCode=4726)
| eval EventType=case(
    EventCode=4720, "Account Created",
    EventCode=4732, "Added to Admin Group",
    EventCode=4740, "Account Locked Out",
    EventCode=4726, "Account Deleted"
  )
| table _time, EventType, Account_Name, SAMAccountName
| sort - _time
```

**Visualization:** Table
**Purpose:** Monitors all account lifecycle changes

---

## Panel 5 — Log Clearing Alerts

```spl
index=windows EventCode=1102 OR EventCode=104
| table _time, Account_Name, Message
| sort - _time
```

**Visualization:** Table with red highlighting
**Purpose:** Immediate alert on any log clearing activity

---

## Panel 6 — Privilege Escalation Indicators

```spl
index=windows EventCode=4672
| stats count by Account_Name, Privileges
| sort - count
```

**Visualization:** Table
**Purpose:** Monitors special privilege assignments

---

## Panel 7 — Network Connections by Source (Sysmon)

```spl
index=sysmon EventCode=3
| stats count by SourceIp, DestinationPort
| where count > 5
| sort - count
```

**Visualization:** Bar chart
**Purpose:** Detects port scanning and unusual outbound connections

---

## Panel 8 — Alert Summary (Last 24 Hours)

```spl
index=windows (EventCode=4625 OR EventCode=4720 OR EventCode=1102 OR EventCode=4672 OR EventCode=4688)
| eval Alert=case(
    EventCode=4625, "Failed Login",
    EventCode=4720, "Account Created",
    EventCode=1102, "Log Cleared",
    EventCode=4672, "Privilege Use",
    EventCode=4688, "Process Created"
  )
| stats count by Alert
| sort - count
```

**Visualization:** Pie chart
**Purpose:** High-level overview of all alert types

---

## Creating the Dashboard

1. Go to Splunk UI → **Dashboards** → **Create New Dashboard**
2. Name it: `SOC Lab - Threat Detection`
3. Add each panel by clicking **Add Panel** → **New from Search**
4. Paste each SPL query above
5. Set time range to **Last 24 hours** for real-time monitoring
