# Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by using email hiding techniques within Microsoft 365 (M365). Specifically, it focuses on identifying when adversaries create inbox rules designed to conceal emails and evade detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1564.008 - Email Hiding Rules
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, Office 365, Linux, macOS  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1564/008)

## Strategy Abstract
The detection strategy involves monitoring for specific patterns indicative of email hiding within M365. It leverages mailbox auditing logs and user activity tracking data to identify when new inbox rules are created that could potentially hide emails. Patterns analyzed include rule creation events targeting specific types of messages or criteria designed to remove visibility from monitored users.

## Technical Context
Adversaries utilize email hiding techniques by creating inbox rules that automatically move, archive, or delete incoming messages based on specified conditions, such as sender address or subject keywords. This allows them to evade detection by security tools that monitor for suspicious activities through email channels.

### Adversary Emulation Details:
- **Sample Command:** Creating an inbox rule in M365 using PowerShell:

  ```powershell
  New-InboxRule -Name "Hide Specific Emails" -SentOnly $false `
                -SubjectContainsWords "confidential" -MoveToFolder "Archive"
  ```

- **Test Scenario:**
  - Log into a test Office 365 tenant.
  - Use PowerShell to create an inbox rule that moves emails with the subject containing "confidential" to an archive folder.

## Blind Spots and Assumptions
- **Limitations:** The strategy assumes that all significant email hiding activities are conducted through M365. It may not detect similar behaviors outside of this platform.
- **Assumptions:** Detection relies on thorough logging and auditing being enabled in the tenant, which might not always be the case.

## False Positives
Potential benign activities include:
- Users creating rules for personal organization, such as moving emails related to specific projects or personal tasks into designated folders.
- Automated system-generated rules that may perform similar actions without malicious intent.

## Priority
**High:** Email hiding represents a significant threat vector in bypassing security monitoring. The ability to conceal communications can facilitate further exploitation and data exfiltration activities undetected by traditional means.

## Validation (Adversary Emulation)
To emulate this technique, follow these steps in a controlled test environment:

1. **Setup:**
   - Access a test Office 365 tenant with administrative privileges.
   - Ensure mailbox auditing is enabled to capture rule creation events.

2. **Create an Inbox Rule:**
   - Open the Exchange Online PowerShell module.
   - Execute the following command to create a new inbox rule:
     ```powershell
     New-InboxRule -Name "Hide Test Emails" -SentOnly $false `
                   -SubjectContainsWords "test" -MoveToFolder "Archive"
     ```

3. **Verify Rule Creation:**
   - Check the mailbox audit logs for an entry indicating the creation of a new inbox rule.
   - Ensure that emails with subjects containing "test" are moved to the archive folder.

## Response
When an alert is triggered, analysts should:
1. Review the specific inbox rules created and assess their criteria.
2. Determine whether these rules align with typical user behavior or indicate potential evasion tactics.
3. Investigate any associated activities for signs of malicious intent.
4. Communicate findings to relevant stakeholders and consider adjusting monitoring parameters if necessary.

## Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- Microsoft Documentation on [Inbox Rules in Exchange Online](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/mail-flow-rules-also-known-as-transport-rules?view=o365-worldwide)

This report provides a structured approach to detecting and responding to email hiding techniques within Microsoft 365, aligned with Palantir's ADS framework.