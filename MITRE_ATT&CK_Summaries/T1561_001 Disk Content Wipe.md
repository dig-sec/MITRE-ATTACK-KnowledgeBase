# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by performing a disk content wipe on target systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1561.001 - Disk Content Wipe
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1561/001)

## Strategy Abstract
The detection strategy focuses on monitoring for signs of disk content wipes across various platforms. This involves analyzing data from several sources including:
- System logs (e.g., Windows Event Logs, Linux syslog)
- File integrity monitoring tools
- Endpoint Detection and Response (EDR) solutions

Patterns analyzed include sudden deletion of large volumes of files, use of specific wiping commands or tools, and unauthorized access to disk management functionalities. 

## Technical Context
Adversaries may execute a disk content wipe using various methods such as:
- Command-line utilities like `shred` on Linux, `sdelete` from Sysinternals Suite on Windows.
- Scripts that automate the deletion of files across directories.
- Malware specifically designed to erase data before an adversary's tracks are covered.

Adversaries typically perform this technique when they need to remove evidence or prepare a system for malicious activities without detection. It is often observed during the final stages of an intrusion, under the "Impact" phase in the kill chain.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Encrypted volumes may not show detectable changes pre-wipe.
  - Wipes performed on external or removable drives might evade local monitoring.
  
- **Assumptions:**
  - Disk content wipe tools leave some traces that can be detected by logs and file integrity checks.
  - Monitoring solutions have appropriate access to all potential data sources.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate use of disk wiping utilities for secure data deletion (e.g., IT administrators clearing sensitive information).
- Bulk file deletions during system maintenance or decommissioning processes.

## Priority
**Severity: High**

Justification: Disk content wipes can significantly impact an organization by erasing critical evidence needed for forensic analysis and recovery. The potential loss of important data makes it imperative to detect such activities promptly.

## Validation (Adversary Emulation)
Currently, no step-by-step instructions are available in the test environment. Future efforts should focus on creating controlled scenarios that safely emulate disk wipe techniques across supported platforms.

## Response
When an alert fires indicating a possible disk content wipe:
1. Immediately isolate the affected systems from the network to prevent further potential data loss or lateral movement.
2. Preserve volatile memory (RAM) for forensic analysis, as it may contain artifacts related to the wiping activity.
3. Review logs and alerts leading up to the event to identify initial compromise vectors.
4. Conduct a thorough investigation of all endpoints to detect any other indicators of compromise.
5. Notify relevant stakeholders about the incident according to the organization's incident response protocol.

## Additional Resources
No additional resources currently available.

---

This report provides an overview of strategies and considerations for detecting disk content wipes as part of Palantir's ADS framework, highlighting key areas for monitoring and response.