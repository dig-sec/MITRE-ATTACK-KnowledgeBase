# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by modifying the authentication process on various platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1556 - Modify Authentication Process
- **Tactic / Kill Chain Phases:** Credential Access, Defense Evasion, Persistence
- **Platforms:** Windows, Linux, macOS, Network

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1556)

## Strategy Abstract
The detection strategy involves monitoring and analyzing authentication-related logs across various platforms. Key data sources include system event logs (e.g., Windows Event Logs), application logs, network traffic logs, and security information and event management (SIEM) systems. The focus is on identifying anomalous patterns in authentication events that deviate from established baselines.

Patterns analyzed include:
- Unusual changes to authentication configurations or policies.
- Unexpected modifications to authentication-related files or registry entries.
- Anomalous access patterns indicating unauthorized modification attempts.

## Technical Context
Adversaries may execute T1556 by altering system authentication mechanisms, such as modifying security policies, changing authentication protocols, or exploiting misconfigurations. Common methods include:
- Altering password policies to weaken security.
- Modifying local security authority (LSA) configurations.
- Implementing unauthorized third-party authentication services.

Sample commands might involve editing registry keys on Windows using `regedit` or altering configuration files on Linux systems via `sudo`.

## Blind Spots and Assumptions
- Detection may not cover zero-day exploits that bypass known monitoring capabilities.
- Assumes a baseline of normal behavior is established, which may not account for evolving user activities.
- Limited visibility into encrypted traffic or obfuscated command executions.

## False Positives
Potential benign activities triggering false alerts include:
- Authorized changes to authentication settings by IT administrators.
- Scheduled updates or patches that modify security policies.
- Legitimate use of administrative tools for system maintenance.

## Priority
**Priority: High**

Justification: Modifying the authentication process can significantly undermine security controls, allowing adversaries persistent access and potential escalation of privileges. The high priority reflects the critical impact on organizational security posture if left undetected.

## Validation (Adversary Emulation)
None available

## Response
When an alert is triggered:
1. **Immediate Verification:** Confirm whether the change was authorized by verifying with IT or network administration.
2. **Containment:** If unauthorized, isolate affected systems to prevent further compromise.
3. **Investigation:** Analyze logs and system configurations to understand the scope of changes made.
4. **Remediation:** Revert any unauthorized modifications and restore original settings.
5. **Post-Incident Review:** Update security policies and incident response plans based on findings.

## Additional Resources
None available

---

This report outlines a comprehensive strategy for detecting attempts to modify authentication processes, emphasizing the importance of monitoring and responding to such activities to maintain robust security defenses.