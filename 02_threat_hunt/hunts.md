# Threat Hunting Hypotheses and Documentation

This document outlines various threat hunting hypotheses, the data sources used for analysis, and their mapping to the MITRE ATT&CK framework.

## Hunt 1: PowerShell Command Execution Patterns

### Hypothesis

Adversaries are using PowerShell to execute malicious commands, establish persistence, and perform lateral movement within the environment. These activities may be hidden among legitimate PowerShell usage but can be identified through command pattern analysis and execution context.

### Data Sources

- Windows PowerShell Event Logs (4103, 4104)
- Windows Security Event Logs (4688 - Process Creation)
- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Transcription Logs

### Analysis Approach

1. Collect PowerShell command execution data across the environment
2. Analyze command patterns, focusing on:
   - Encoded commands (Base64)
   - Obfuscation techniques
   - Known malicious cmdlets and parameters
   - Unusual execution contexts (time, user, host)
3. Establish baseline of normal PowerShell usage in the environment
4. Identify deviations from the baseline
5. Investigate suspicious command executions

### MITRE ATT&CK Mapping

- **Execution**
  - T1059.001: Command and Scripting Interpreter: PowerShell
- **Defense Evasion**
  - T1027: Obfuscated Files or Information
  - T1140: Deobfuscate/Decode Files or Information
- **Discovery**
  - T1082: System Information Discovery
  - T1087: Account Discovery
- **Lateral Movement**
  - T1021.006: Remote Services: Windows Remote Management

---

## Hunt 2: Unusual Authentication Patterns

### Hypothesis

Adversaries are using compromised credentials to access systems during non-business hours or from unusual locations, potentially indicating account compromise or insider threat activity.

### Data Sources

- Windows Security Event Logs (4624, 4625, 4634, 4647)
- VPN access logs
- Proxy logs
- Cloud service authentication logs (Azure AD, AWS CloudTrail)

### Analysis Approach

1. Establish authentication baselines for users:
   - Typical working hours
   - Common access locations and IP addresses
   - Usual systems accessed
   - Normal authentication patterns
2. Identify deviations from established baselines:
   - Off-hours authentication
   - Geographically impossible travel
   - Authentication from unusual IP addresses
   - Access to systems not typically used
3. Correlate suspicious authentications with other activities
4. Investigate potential compromised accounts

### MITRE ATT&CK Mapping

- **Initial Access**
  - T1078: Valid Accounts
- **Persistence**
  - T1098: Account Manipulation
- **Defense Evasion**
  - T1550: Use Alternate Authentication Material
- **Lateral Movement**
  - T1550.002: Use Alternate Authentication Material: Pass the Hash

---

## Hunt 3: Data Exfiltration via DNS

### Hypothesis

Adversaries are using DNS tunneling or DNS queries to exfiltrate data from the environment, bypassing traditional network security controls.

### Data Sources

- DNS server logs
- Network flow data
- Packet captures (if available)
- Firewall logs
- DNS security solutions (if deployed)

### Analysis Approach

1. Analyze DNS query patterns:
   - Unusually long domain names
   - High volume of queries to specific domains
   - Entropy analysis of domain names
   - Unusual TXT record queries
2. Identify hosts with anomalous DNS traffic patterns
3. Examine the timing and frequency of DNS queries
4. Reconstruct potential data exfiltration by analyzing query content
5. Correlate suspicious DNS activity with other host-based indicators

### MITRE ATT&CK Mapping

- **Command and Control**
  - T1071.004: Application Layer Protocol: DNS
- **Exfiltration**
  - T1048: Exfiltration Over Alternative Protocol
  - T1048.003: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

---

## Hunt 4: Living Off the Land Binary (LOLBin) Usage

### Hypothesis

Adversaries are using legitimate Windows utilities (LOLBins) to execute malicious code, bypass application whitelisting, and maintain persistence while evading detection.

### Data Sources

- Windows Security Event Logs (4688 - Process Creation)
- Sysmon Event Logs (Event ID 1 - Process Creation)
- Command line logging
- PowerShell logs

### Analysis Approach

1. Identify execution of commonly abused LOLBins:
   - certutil.exe
   - regsvr32.exe
   - mshta.exe
   - rundll32.exe
   - bitsadmin.exe
   - wmic.exe
2. Analyze command line parameters for suspicious patterns
3. Examine parent-child process relationships
4. Identify unusual execution contexts (user, time, location)
5. Correlate LOLBin execution with other suspicious activities

### MITRE ATT&CK Mapping

- **Defense Evasion**
  - T1218: Signed Binary Proxy Execution
  - T1218.001: Signed Binary Proxy Execution: Regsvr32
  - T1218.005: Signed Binary Proxy Execution: Mshta
  - T1218.011: Signed Binary Proxy Execution: Rundll32
- **Execution**
  - T1059.003: Command and Scripting Interpreter: Windows Command Shell

---

## Hunt 5: Suspicious Registry Modifications

### Hypothesis

Adversaries are modifying Windows Registry keys to establish persistence, hide malicious activities, or disable security controls.

### Data Sources

- Windows Security Event Logs (4657 - Registry value modified)
- Sysmon Event Logs (Event ID 12, 13, 14 - Registry events)
- Registry snapshots or baselines

### Analysis Approach

1. Monitor changes to commonly abused registry locations:
   - Run keys (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
   - Service configurations
   - Startup items
   - Shell extensions
   - WinLogon helper DLLs
2. Identify modifications made by unusual processes
3. Detect changes made outside normal administrative activities
4. Correlate registry changes with other suspicious activities
5. Analyze the content of registry modifications

### MITRE ATT&CK Mapping

- **Persistence**
  - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
  - T1546.012: Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **Defense Evasion**
  - T1112: Modify Registry
- **Privilege Escalation**
  - T1548: Abuse Elevation Control Mechanism