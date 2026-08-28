# Splunk Enterprise Setup Guide

## Overview
Splunk Enterprise 9.2.1 was installed on Ubuntu Server 22.04 to serve as the central SIEM for this lab. All Windows endpoint logs are shipped here via the Splunk Universal Forwarder.

---

## System Requirements

| Resource | Minimum | Used in Lab |
|---|---|---|
| RAM | 4GB | 8GB |
| Disk | 20GB | 50GB |
| CPU | 2 cores | 2 cores |
| OS | Ubuntu 22.04 | Ubuntu 22.04 |

---

## Installation Steps

### 1. Download Splunk Enterprise

```bash
wget -O splunk.deb "https://download.splunk.com/products/splunk/releases/9.2.1/linux/splunk-9.2.1-78803f08aabb-linux-2.6-amd64.deb"
```

### 2. Install the Package

```bash
sudo dpkg -i splunk.deb
```

### 3. Start Splunk and Accept License

```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

Set admin username and password when prompted.

### 4. Enable Auto-Start on Boot

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### 5. Open Required Firewall Ports

```bash
sudo ufw allow 8000/tcp   # Web UI
sudo ufw allow 9997/tcp   # Forwarder receiving port
sudo ufw allow 8089/tcp   # Management port
sudo ufw reload
```

---

## Post-Install Configuration

### Configure Receiving Port (9997)
- Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port → `9997`

### Create Indexes
- Settings → Indexes → New Index → `windows`
- Settings → Indexes → New Index → `sysmon`

### Install Add-ons
- Apps → Find More Apps → `Splunk Add-on for Microsoft Windows`
- Apps → Find More Apps → `Splunk Add-on for Sysmon`

---

## Accessing the UI

```
http://[ubuntu-server-ip]:8000
```

Default credentials set during installation.

---

## Useful Commands

```bash
# Check status
sudo /opt/splunk/bin/splunk status

# Start
sudo /opt/splunk/bin/splunk start

# Restart
sudo /opt/splunk/bin/splunk restart

# Check listening ports
sudo ss -tlnp | grep splunk
```
