# Detection Engineering

This directory contains the Splunk SPL detections developed during
the Active Directory password spray investigation.

## Detection 1 — Password Spray

Detects multiple failed authentication attempts from a single
source IP against multiple distinct Active Directory accounts.

### Telemetry

Windows Security Event ID 4625.

### Detection Logic

- 5+ failed authentications
- 5+ distinct targeted accounts
- Grouped by source IP

### MITRE ATT&CK

T1110.003 — Password Spraying

### Severity

High

---

## Detection 2 — Successful Authentication

**File:** `successful-password-spray.spl`

Identifies successful Windows authentication originating from the
known password-spray source.

### Telemetry

Windows Security Event ID 4624.

### Why It Matters

A successful authentication following password-spray activity may
indicate that the attacker obtained valid credentials.

### Severity

High/Critical depending on the affected account.

---

## Detection Development Process

The detections were developed using the following workflow:

1. Generate controlled attack activity from Kali Linux.
2. Observe Windows Security telemetry.
3. Identify relevant Event IDs and fields.
4. Develop SPL searches.
5. Validate results against known attack activity.
6. Convert validated searches into Splunk alerts.
7. Investigate the resulting alerts.
8. Perform containment.
9. Validate containment.