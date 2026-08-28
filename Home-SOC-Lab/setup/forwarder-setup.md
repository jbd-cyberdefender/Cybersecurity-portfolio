# Splunk Universal Forwarder Setup — Windows 11

## Overview
The Splunk Universal Forwarder is a lightweight agent installed on the Windows 11 endpoint (W11SOC) that collects Windows Event Logs and Sysmon telemetry and ships them to Splunk Enterprise over TCP port 9997.

---

## Installation

### 1. Download the Forwarder
Download the Windows 64-bit `.msi` installer from:
```
https://www.splunk.com/en_us/download/universal-forwarder.html
```

### 2. Install as Administrator
Right-click the `.msi` → **Run as Administrator**

During installation:
- Set username and password (write these down)
- **Deployment Server screen: leave completely blank**
- Receiving Indexer: enter your Splunk server IP and port `9997`

---

## Configuration Files

Both files live at:
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\
```

### outputs.conf
Tells the forwarder where to send logs:
```ini
[tcpout]
defaultGroup = splunk-server

[tcpout:splunk-server]
server = 192.168.250.128:9997
```

### inputs.conf
Tells the forwarder what logs to collect:
```ini
[WinEventLog://Security]
index = windows
disabled = 0
renderXml = false

[WinEventLog://System]
index = windows
disabled = 0
renderXml = false

[WinEventLog://Application]
index = windows
disabled = 0
renderXml = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = windows
disabled = 0
renderXml = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
disabled = 0
renderXml = true
```

---

## Important Configuration Note

**The SplunkForwarder service must run as Local System** to have permission to read Sysmon logs:

1. Press `Win + R` → `services.msc`
2. Find **SplunkForwarder** → Right-click → Properties
3. Log On tab → Select **Local System account**
4. Restart the service

---

## Useful Commands

Run from:
```
C:\Program Files\SplunkUniversalForwarder\bin\
```

```cmd
# Restart forwarder
splunk restart -auth username:password

# Check connection status
splunk list forward-server -auth username:password

# Add a forward server
splunk add forward-server 192.168.250.128:9997 -auth username:password
```

---

## Verification

In Splunk UI → Search & Reporting:
```spl
index=windows | head 20
```
```spl
index=sysmon | head 20
```

Both should return events within 2-3 minutes of forwarder startup.

---

## Common Issues

| Issue | Cause | Fix |
|---|---|---|
| Winsock error 10061 | Splunk not listening on 9997 | Add receiving port in Splunk UI |
| errorCode=5 on Sysmon | Permission denied | Change service to Local System account |
| Inactive forwards | Wrong IP in outputs.conf | Verify Splunk server IP |
| 0 events in Splunk | SplunkForwarder service stopped | `sc start SplunkForwarder` |
