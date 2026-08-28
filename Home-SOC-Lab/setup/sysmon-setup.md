# Sysmon Setup Guide

## Overview
Sysmon (System Monitor) is a Windows system service from Microsoft Sysinternals that logs detailed endpoint telemetry far beyond what Windows Event Logs provide natively. It captures process creation with full command lines, network connections, file creation, and registry modifications.

---

## Download

- **Sysmon**: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- **SwiftOnSecurity Config** (recommended): https://github.com/SwiftOnSecurity/sysmon-config

---

## Installation

```cmd
# Install with SwiftOnSecurity config (run as Administrator)
sysmon64 -accepteula -i sysmonconfig.xml
```

---

## Verify Installation

```cmd
# Check service status
sc query sysmon64

# Verify logs in Event Viewer
# Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

## Key Sysmon Event IDs

| Event ID | Description | Use Case |
|---|---|---|
| 1 | Process Create | Detect malicious process execution |
| 2 | File Creation Time Changed | Timestomping detection |
| 3 | Network Connection | Detect C2 communication, port scanning |
| 7 | Image Loaded | DLL injection detection |
| 8 | CreateRemoteThread | Process injection detection |
| 10 | ProcessAccess | LSASS access (Mimikatz) |
| 11 | FileCreate | Malware dropping files |
| 12 | RegistryEvent (Object create/delete) | Persistence detection |
| 13 | RegistryEvent (Value Set) | Registry run key persistence |
| 15 | FileCreateStreamHash | ADS detection |
| 22 | DNSEvent | DNS query logging |

---

## Splunk Detection Queries Using Sysmon

**Detect LSASS Access (Mimikatz):**
```spl
index=sysmon EventCode=10
| where TargetImage like "%lsass%"
| table _time, SourceImage, TargetImage, GrantedAccess
```

**Detect Process Injection:**
```spl
index=sysmon EventCode=8
| table _time, SourceImage, TargetImage, StartAddress
```

**Detect Registry Persistence:**
```spl
index=sysmon EventCode=13
| search TargetObject="*\\CurrentVersion\\Run*"
| table _time, Computer, User, TargetObject, Details
```

**Detect Network Scanning:**
```spl
index=sysmon EventCode=3
| stats count by SourceIp, DestinationPort
| where count > 20
| sort - count
```

---

## Updating Sysmon Config

```cmd
# Update config without reinstalling
sysmon64 -c sysmonconfig.xml

# Uninstall
sysmon64 -u
```
