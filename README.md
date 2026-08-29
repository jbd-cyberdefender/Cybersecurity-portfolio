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
- **SIEM Platforms:** Splunk Enterprise, Wazuh
- **Log Management:** Centralized Ingestion, Universal Forwarders, Data Indexing
- **Detection Engineering:** SPL (Search Processing Language) Query Optimization, Correlation Rules
- **Security Event Analysis:** Windows Event Logs, Endpoint Telemetry Monitoring
- **Incident Response:** Alert Triage, Cyber Attack Investigation, Incident Containment

### Enterprise Systems & Infrastructure
- **Windows Architecture:** Active Directory Domain Services, Windows Server Administration
- **Linux Administration:** Ubuntu Server (Enterprise Deployments, CLI Configuration)
- **Virtualization:** VMware Workstation Pro, Hypervisor Provisioning & Networking
- **Endpoint Protection:** Sysmon Architecture (SwiftOnSecurity Framework), Windows Firewall
- **Windows Security Event Auditing:** Event ID 4624/4625 (Logons), 4720/4732 (Accounts), 1102 (Log Clearing)

### Email Security & Digital Forensics
- **Header Analysis:** Raw SMTP Routing Vector Analysis (`From`, `Reply-To`, `Return-Path`, `Received` chain)
- **Email Authentication:** SPF, DKIM, DMARC Alignment Verification
- **Threat Indicators:** IOC Extraction, Brand Impersonation Vectors, Typosquatting Detection
- **Mail Formats:** `.eml` Analysis (Gmail, Outlook Metadata Formats)

### Offensive Security & Threat Simulation
- **Network Reconnaissance:** Nmap, Network Mapping, Service Enumeration
- **Attack Simulation:** RDP Brute-Forcing (`xfreerdp3`), SMB Attack Execution (`CrackMapExec`)
- **Credential & Protocol Attacks:** Password Auditing (`Hydra`), Network Protocol Exploitation (`Impacket`)
- **Frameworks:** MITRE ATT&CK Mapping, Kali Linux Operational Frameworks

### Programming, Data Parsing & Automation
- **Languages:** Python, PowerShell, C, C#
- **Text Processing:** Regular Expressions (`re.findall()`), Pattern Matching, Text Parsing
- **Software Engineering:** Modular Code Architecture, Object-Oriented Logic, Automated Regression Testing

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
