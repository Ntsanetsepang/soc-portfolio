# Splunk Searches for Security Monitoring

This document contains Splunk search queries for detecting various security threats, along with explanations of what each search is looking for and why it's important.

## Suspicious Process Creation

```
index=windows sourcetype=WinEventLog:Security EventCode=4688 
| where NOT match(NewProcessName, "(?i)C:\\\\Windows\\\\System32\\\\.*") 
| where NOT match(NewProcessName, "(?i)C:\\\\Program Files\\\\.*") 
| where NOT match(NewProcessName, "(?i)C:\\\\Program Files \(x86\)\\\\.*") 
| stats count by NewProcessName, Creator_Process_ID, ParentProcessName, Account_Name, Computer
| sort - count
```

**Explanation:** This search identifies process creation events (EventCode 4688) where the process is not being launched from standard Windows directories. This could indicate malicious activity as attackers often use non-standard paths to execute malware. The search excludes common legitimate paths and counts occurrences to help identify unusual patterns.

## PowerShell Command Line Monitoring

```
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 
| regex ScriptBlockText="(?i)net\\s+user|mimikatz|Invoke-Mimikatz|SecretsDump|Invoke-WMIExec|Get-Credential|PasswordVault|ConvertTo-SecureString"
| table _time, Computer, ScriptBlockText, UserID
```

**Explanation:** This search looks for PowerShell script blocks containing suspicious commands or tools commonly used in attacks. It monitors for credential access attempts, use of offensive security tools like Mimikatz, and other potentially malicious PowerShell activities.

## Failed Authentication Attempts

```
index=windows sourcetype=WinEventLog:Security EventCode=4625 
| stats count as failure_count by dest, user, src_ip 
| where failure_count > 5
| sort - failure_count
```

**Explanation:** This search identifies hosts with multiple failed login attempts, which could indicate brute force attacks. By setting a threshold of more than 5 failures, it helps reduce false positives while still catching potential attacks.

## Unusual Service Creation

```
index=windows sourcetype=WinEventLog:System EventCode=7045 
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| search Service_Account="LocalSystem" OR Service_Account="NT AUTHORITY\\\\SYSTEM"
```

**Explanation:** This search detects the creation of new Windows services, focusing on those configured to run with SYSTEM privileges. Attackers often create services for persistence and privilege escalation, making this an important activity to monitor.

## Scheduled Task Creation

```
index=windows sourcetype=WinEventLog:Security EventCode=4698 OR (sourcetype=WinEventLog:Microsoft-Windows-TaskScheduler/Operational EventCode=106) 
| table _time, host, user, Task_Name, Task_Content
```

**Explanation:** This search monitors for the creation of scheduled tasks, which is a common persistence mechanism used by attackers. It captures both the task name and content to help analysts determine if the scheduled task is legitimate or malicious.

## Suspicious Registry Modifications

```
index=windows sourcetype=WinEventLog:Security EventCode=4657 
| search ObjectName="*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*" OR ObjectName="*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce*"
| table _time, host, ObjectName, ProcessName, SubjectUserName
```

**Explanation:** This search detects modifications to Windows registry Run and RunOnce keys, which are common locations for persistence mechanisms. Attackers often add entries to these registry locations to ensure their malware runs when a system boots.

## Network Connections to Unusual Ports

```
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
| stats count by DestinationIp, DestinationPort, Image 
| where NOT match(DestinationPort, "^(80|443|53|123|389|88|636|3268|3269|445|135|137|138|139|21|22|25|110|143|993|995|20)$") 
| sort - count
```

**Explanation:** This search identifies network connections to unusual ports using Sysmon data. It excludes common legitimate ports and helps identify potential command and control (C2) communications or data exfiltration attempts.

## DLL Sideloading Detection

```
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 
| where NOT match(ImageLoaded, "(?i)C:\\\\Windows\\\\System32\\\\.*") AND NOT match(ImageLoaded, "(?i)C:\\\\Windows\\\\SysWOW64\\\\.*") 
| stats count by Image, ImageLoaded, Computer
| sort - count
```

**Explanation:** This search detects potential DLL sideloading, where a process loads a DLL from a non-standard location. This technique is commonly used by attackers to execute malicious code through legitimate processes.

## Detecting Pass-the-Hash Attacks

```
index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM 
| where NOT match(SubjectUserName, "(?i)ANONYMOUS LOGON") 
| stats count by SourceNetworkAddress, TargetUserName, TargetDomainName, TargetServerName
| sort - count
```

**Explanation:** This search identifies potential Pass-the-Hash attacks by looking for NTLM authentication in network logons. It excludes anonymous logons and helps identify lateral movement within the network.

## Command Line Auditing for Suspicious Commands

```
index=windows sourcetype=WinEventLog:Security EventCode=4688 
| regex CommandLine="(?i)whoami|net\\s+user|net\\s+group|net\\s+localgroup|ipconfig|systeminfo|tasklist|netstat|reg\\s+query|findstr|dir\\s+/s|copy\\s+.*\\\\.\\\\|certutil.*-urlcache"
| table _time, Computer, SubjectUserName, CommandLine
```

**Explanation:** This search monitors for command-line activities commonly associated with reconnaissance and discovery phases of an attack. It looks for commands that attackers use to gather information about systems and networks.