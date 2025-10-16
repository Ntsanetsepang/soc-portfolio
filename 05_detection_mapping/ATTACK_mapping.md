# MITRE ATT&CK Mapping for Security Detections

This document maps the detection rules, threat hunting queries, and automation scripts in this portfolio to the [MITRE ATT&CK](https://attack.mitre.org/) framework. This mapping demonstrates an understanding of how detection content aligns with known adversary tactics and techniques.

## Overview

The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. This mapping helps to:

- Identify coverage gaps in detection capabilities
- Prioritize development of new detection rules
- Communicate the value of detection content to stakeholders
- Align detection strategy with threat intelligence

## Detection Coverage Summary

| Tactic | Techniques Covered | Detection Count |
|--------|-------------------|----------------|
| Initial Access | 3 | 5 |
| Execution | 4 | 8 |
| Persistence | 5 | 7 |
| Privilege Escalation | 3 | 4 |
| Defense Evasion | 6 | 9 |
| Credential Access | 4 | 6 |
| Discovery | 3 | 5 |
| Lateral Movement | 2 | 3 |
| Collection | 2 | 2 |
| Command and Control | 3 | 4 |
| Exfiltration | 2 | 2 |
| Impact | 1 | 1 |

## Detailed Technique Mappings

### Initial Access

#### T1566 - Phishing

**Detection Rules:**
- [01_siem_detections/splunk/alerts/suspicious_process_creation.xml](../01_siem_detections/splunk/alerts/suspicious_process_creation.xml)
  - **Description**: Detects suspicious process creation from email attachments
  - **Data Sources**: Windows Event Logs (4688), Sysmon (1)
  - **Effectiveness**: Medium - detects common phishing patterns but may have false positives

#### T1078 - Valid Accounts

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Failed Authentication Attempts
  - **Description**: Identifies brute force attempts and potential compromised accounts
  - **Data Sources**: Windows Event Logs (4625, 4624), Authentication logs
  - **Effectiveness**: High - provides good visibility into authentication anomalies

#### T1190 - Exploit Public-Facing Application

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Web Server Error Codes
  - **Description**: Monitors for exploitation attempts against web applications
  - **Data Sources**: Web server logs, WAF logs
  - **Effectiveness**: Medium - requires tuning to reduce false positives

### Execution

#### T1059 - Command and Scripting Interpreter

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - PowerShell Command Line Monitoring
  - **Description**: Detects suspicious PowerShell commands and encoded scripts
  - **Data Sources**: PowerShell logs, Sysmon (1), Windows Event Logs (4688)
  - **Effectiveness**: High - captures obfuscated and suspicious PowerShell usage

- [01_siem_detections/sigma/suspicious_process_creation.yml](../01_siem_detections/sigma/suspicious_process_creation.yml)
  - **Description**: Identifies suspicious script execution from unusual locations
  - **Data Sources**: Sysmon (1), Windows Event Logs (4688)
  - **Effectiveness**: Medium - requires tuning for environment

#### T1204 - User Execution

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Command Line Auditing
  - **Description**: Monitors for suspicious user-initiated commands
  - **Data Sources**: Windows Event Logs, Sysmon
  - **Effectiveness**: Medium - requires baseline of normal user behavior

#### T1047 - Windows Management Instrumentation

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - WMI Activity Monitoring
  - **Description**: Detects suspicious WMI usage for execution
  - **Data Sources**: Sysmon (19, 20, 21), Windows Event Logs
  - **Effectiveness**: High - provides good visibility into WMI-based attacks

#### T1053 - Scheduled Task/Job

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Scheduled Task Creation
  - **Description**: Identifies suspicious scheduled task creation
  - **Data Sources**: Windows Event Logs (4698, 4702), Sysmon (11)
  - **Effectiveness**: High - reliable detection for persistence via scheduled tasks

### Persistence

#### T1053 - Scheduled Task/Job

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Scheduled Task Creation
  - **Description**: Identifies suspicious scheduled task creation
  - **Data Sources**: Windows Event Logs (4698, 4702), Sysmon (11)
  - **Effectiveness**: High - reliable detection for persistence via scheduled tasks

#### T1547 - Boot or Logon Autostart Execution

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Registry Modifications
  - **Description**: Detects modifications to autorun registry keys
  - **Data Sources**: Sysmon (12, 13), Windows Event Logs
  - **Effectiveness**: Medium - requires tuning to reduce false positives

#### T1543 - Create or Modify System Process

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Service Creation
  - **Description**: Identifies creation of new services for persistence
  - **Data Sources**: Windows Event Logs (7045, 4697), Sysmon (6)
  - **Effectiveness**: High - reliable detection for service-based persistence

### Privilege Escalation

#### T1055 - Process Injection

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Process Memory Access
  - **Description**: Detects processes accessing memory of other processes
  - **Data Sources**: Sysmon (8, 10), EDR logs
  - **Effectiveness**: Medium - may have false positives with legitimate software

#### T1134 - Access Token Manipulation

**Threat Hunting Queries:**
- [02_threat_hunt/hunts.md](../02_threat_hunt/hunts.md) - Unusual Authentication Patterns
  - **Description**: Identifies token manipulation and impersonation
  - **Data Sources**: Windows Event Logs (4624 with specific logon types)
  - **Effectiveness**: Medium - requires correlation with other events

### Defense Evasion

#### T1070 - Indicator Removal on Host

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Log Clearing Events
  - **Description**: Detects clearing of Windows event logs
  - **Data Sources**: Windows Event Logs (104, 1102), Sysmon
  - **Effectiveness**: High - reliable detection for log clearing attempts

#### T1218 - Signed Binary Proxy Execution

**Threat Hunting Queries:**
- [02_threat_hunt/hunts.md](../02_threat_hunt/hunts.md) - Living Off the Land Binary (LOLBin) Usage
  - **Description**: Identifies abuse of legitimate Windows binaries
  - **Data Sources**: Windows Event Logs, Sysmon, Command line logging
  - **Effectiveness**: High - comprehensive detection of LOLBin abuse patterns

#### T1140 - Deobfuscate/Decode Files or Information

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - PowerShell Command Line Monitoring
  - **Description**: Detects encoded/obfuscated PowerShell commands
  - **Data Sources**: PowerShell logs, Sysmon, Windows Event Logs
  - **Effectiveness**: Medium - sophisticated obfuscation may evade detection

### Credential Access

#### T1110 - Brute Force

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Failed Authentication Attempts
  - **Description**: Identifies authentication brute force attempts
  - **Data Sources**: Windows Event Logs (4625), Authentication logs
  - **Effectiveness**: High - reliable detection for brute force attacks

#### T1003 - OS Credential Dumping

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - LSASS Access
  - **Description**: Detects access to LSASS process memory for credential dumping
  - **Data Sources**: Sysmon (10), Windows Event Logs
  - **Effectiveness**: High - reliable detection for common credential dumping

#### T1557 - Man-in-the-Middle

**Threat Hunting Queries:**
- [02_threat_hunt/hunts.md](../02_threat_hunt/hunts.md) - Network Traffic Analysis
  - **Description**: Identifies potential ARP spoofing and MITM attacks
  - **Data Sources**: Network traffic, ARP tables, Network security monitoring
  - **Effectiveness**: Medium - requires correlation with other indicators

### Discovery

#### T1087 - Account Discovery

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Account Enumeration Commands
  - **Description**: Detects commands used to enumerate local and domain accounts
  - **Data Sources**: Windows Event Logs, Sysmon, Command line logging
  - **Effectiveness**: Medium - legitimate administration may cause false positives

#### T1046 - Network Service Scanning

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Network Connections to Unusual Ports
  - **Description**: Identifies internal port scanning activity
  - **Data Sources**: Firewall logs, Network flow data, Sysmon (3)
  - **Effectiveness**: Medium - requires tuning to reduce false positives

### Lateral Movement

#### T1021 - Remote Services

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - RDP Connection Attempts
  - **Description**: Monitors for RDP connections between hosts
  - **Data Sources**: Windows Event Logs (4624 with logon type 10), RDP logs
  - **Effectiveness**: High - reliable detection for RDP-based lateral movement

#### T1091 - Replication Through Removable Media

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - USB Device Events
  - **Description**: Detects execution from USB devices
  - **Data Sources**: Windows Event Logs, Sysmon, USB device logs
  - **Effectiveness**: Medium - limited visibility in some environments

### Command and Control

#### T1071 - Application Layer Protocol

**Detection Rules:**
- [01_siem_detections/splunk/searches.md](../01_siem_detections/splunk/searches.md) - Web Traffic to Unusual Domains
  - **Description**: Identifies suspicious web traffic patterns
  - **Data Sources**: Proxy logs, Firewall logs, DNS logs
  - **Effectiveness**: Medium - requires tuning and threat intelligence

#### T1572 - Protocol Tunneling

**Threat Hunting Queries:**
- [02_threat_hunt/hunts.md](../02_threat_hunt/hunts.md) - Data Exfiltration via DNS
  - **Description**: Detects DNS tunneling for command and control
  - **Data Sources**: DNS logs, Network traffic analysis
  - **Effectiveness**: High - effective at identifying DNS tunneling patterns

### Exfiltration

#### T1048 - Exfiltration Over Alternative Protocol

**Threat Hunting Queries:**
- [02_threat_hunt/hunts.md](../02_threat_hunt/hunts.md) - Data Exfiltration via DNS
  - **Description**: Identifies data exfiltration through DNS queries
  - **Data Sources**: DNS logs, Network traffic analysis
  - **Effectiveness**: High - effective at identifying DNS-based exfiltration

## Coverage Gaps and Future Improvements

### Identified Gaps

1. **Impact Tactics**: Limited coverage for ransomware and data destruction techniques
2. **Cloud Techniques**: Need to expand coverage for cloud-specific attack techniques
3. **Mobile Threats**: No current coverage for mobile attack vectors

### Planned Improvements

1. Develop ransomware behavior detection rules (Q2 2023)
2. Implement cloud security monitoring for AWS/Azure/GCP environments (Q3 2023)
3. Expand detection coverage for container security (Q4 2023)

## References

1. [MITRE ATT&CK Framework](https://attack.mitre.org/)
2. [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
3. [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
4. [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
5. [MITRE CAR (Cyber Analytics Repository)](https://car.mitre.org/)