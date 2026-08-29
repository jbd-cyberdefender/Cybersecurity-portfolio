# Joshua Bassey-Duke | Cybersecurity Portfolio

Welcome to my cybersecurity portfolio.

I am an Information Technology student at the University of Missouri focused on cybersecurity, detection engineering, SOC operations, Active Directory security, network security, and offensive security.

This repository documents hands-on projects where I build, attack, monitor, investigate, and secure realistic environments.

## Featured Projects

### 01 — Active Directory Password Spray Detection & SOC Response

**Focus:** Active Directory | Splunk | Detection Engineering | SOC Analysis | Incident Response

Built and investigated a simulated Active Directory password-spray attack using a multi-machine lab environment.

The project follows a complete SOC workflow:

**Attack → Telemetry → Detection → Alert → Investigation → Containment → Validation → Documentation**

Key areas demonstrated:

- Active Directory domain administration
- Windows Security Event Log analysis
- Password-spray attack simulation
- Splunk SIEM investigation
- SPL detection engineering
- Authentication event analysis
- Alert creation and severity configuration
- Source IP identification
- Incident containment using Windows Firewall
- Post-containment validation
- Detection improvement opportunities

[View Project →](./01-AD-Splunk-Password-Spray/)

### 02 — Home SOC Lab: Multi-Vector Threat Detection & SIEM Engineering

**Focus:** Splunk Enterprise | Sysmon Telemetry | Threat Simulation | Windows Security Event Logs | MITRE ATT&CK

Built a fully functional virtualized Security Operations Center (SOC) home lab to orchestrate adversarial attack techniques, capture granular telemetry, and engineer custom detection controls within a centralized SIEM environment.

The pipeline spans across a dedicated three-machine architecture: 

**Ubuntu Splunk Server (SIEM) ⟵ Windows 11 Enterprise (Target + Sysmon Forwarder) ⟵ Kali Linux (Adversary)**

Key areas demonstrated:
- **SIEM Infrastructure Deployment:** Provisioned and managed an enterprise-grade Splunk indexing server on Ubuntu Server 22.04 with centralized real-time ingestion via Universal Forwarders.
- **Advanced Endpoint Telemetry:** Deployed Sysmon utilizing highly granular configuration frameworks (SwiftOnSecurity) to capture deep subsystem visibility alongside native Windows Security Logs.
- **Adversarial Attack Simulation:** Executed multi-staged cyber attack chains utilizing offensive security tools including Nmap, Hydra, xfreerdp3, CrackMapExec, and the Impacket protocol library.
- **SPL Detection Engineering:** Authored custom Search Processing Language (SPL) correlation rules to identify critical indicators of compromise (IOCs), specifically tracking Event IDs 4625 (Brute Force), 4720 (Backdoor Account Creation), 1102 (Audit Log Clearing), and Sysmon Process Creation events.
- **MITRE ATT&CK Framework Mapping:** Structured a comprehensive multi-vector incident report mapping tactical simulations back to industry-standard adversary profiles (Credential Access, Persistence, Defense Evasion, and Discovery).

[View Project →](./Home-SOC-Lab/)


### 03 — Automated Phishing Email Header Analyzer & Scoring Tool

**Focus:** Python | Incident Response | Email Security | Threat Analysis | Automation

Developed a lightweight Python security tool to automate the parsing, extraction, and analysis of raw `.eml` email headers for rapid incident triage. 

The tool implements a structured, defense-in-depth pipeline:

**Raw Header Parsing → IOC Extraction → Auth Alignment Verification → Weighted Rubric Scoring → Risk Verdict**

Key areas demonstrated:
- **Header Analysis:** Programmatic inspection of SMTP routing vectors (`From`, `Reply-To`, `Return-Path`, `Received`).
- **Authentication Verification:** Automated parsing and multi-hop extraction of SPF, DKIM, and DMARC alignment validation results using regex.
- **Identity Spoofing Detection:** Algorithmic detection of lookalike domains, typosquatting, and display-name brand impersonation patterns.
- **Defensive Rubric Design:** Engineering a multi-tier, weighted scoring rubric (1–3 point matrix) to eliminate false positives while accurately catching true malicious indicators.
- **Synthesized Regression Testing:** Building a modular architecture (`parser.py`, `analyze_email.py`, `test_parser.py`) to validate clean, ambiguous, and malicious edge-cases.

[View Project →](./03_Phishing_Investigation_script/)


---

## Skills & Technologies

### Security Operations & Detection

- Splunk
- Wazuh
- SIEM
- Detection Engineering
- Security Event Analysis
- Incident Investigation
- Alert Triage
- Incident Response

### Windows & Active Directory

- Active Directory
- Windows Server
- Windows 11
- Security Event Logs
- Event ID 4624
- Event ID 4625
- PowerShell
- Windows Firewall
- Sysmon

### Offensive Security

- Kali Linux
- Hack The Box
- Nmap
- Network Enumeration
- SMB
- Web Security
- Attack Simulation

### Programming & Automation

- Python
- C
- C#
- PowerShell
- SPL

## Portfolio Roadmap

Additional projects will be added as I continue developing my cybersecurity skills.

## Certifications
CompTIA Security+

## Education
University of Missouri

Bachelors of Science in Information Technology

Expected Graduation: May 2027

## Social Links
Linkedin - https://www.linkedin.com/in/joshuabassey-duke/
