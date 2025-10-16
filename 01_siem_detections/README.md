# SIEM Detections

This directory contains custom detection rules, searches, and alerts for various Security Information and Event Management (SIEM) platforms.

## Contents

- [Splunk](./splunk/): Splunk searches and alerts for detecting suspicious activities
- [Sigma](./sigma/): SIEM-agnostic Sigma rules that can be converted to various SIEM query languages
- [Test Data](./test_data/): Sample log data and synthetic events for testing detection rules

## Implementation Guide

### Splunk

The Splunk directory contains:
- Search queries with detailed explanations
- Alert configurations in XML format

To implement these in your Splunk environment:
1. Navigate to the Searches & Reports section in Splunk
2. Create a new search
3. Copy and paste the search query
4. Configure the alert settings as specified in the corresponding XML file

### Sigma Rules

Sigma rules are platform-agnostic detection rules that can be converted to various SIEM query languages.

To use these rules:
1. Install the sigmac converter tool
2. Convert the rules to your SIEM's query language
3. Implement the converted queries in your SIEM

## Detection Strategy

These detections focus on identifying:
- Unusual process creation patterns
- Suspicious network connections
- Potential credential theft
- Privilege escalation attempts
- Data exfiltration indicators

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)