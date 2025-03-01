# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring by collecting emails remotely using Microsoft Office 365, Windows, and Google Workspace platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1114.002 - Remote Email Collection
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Office 365, Windows, Google Workspace  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1114/002)

## Strategy Abstract
This detection strategy focuses on identifying unauthorized email collection activities that indicate an adversary's attempt to bypass security controls. The primary data sources include Office 365 audit logs, Windows event logs, and Google Workspace administrative reports. Patterns analyzed involve unusual login attempts, configuration changes in mail forwarding settings, and suspicious PowerShell or script-based activity indicating remote access.

## Technical Context
Adversaries often execute Remote Email Collection by leveraging compromised credentials to configure email forwarding rules. This allows them to intercept sensitive emails from a target's account without being detected as they receive the emails on an external server under their control.

### Adversary Emulation Details:
- **Sample Commands:** 
  - PowerShell script for modifying mail forwarding settings.
  - Command-line tools for extracting credentials and configuring email clients to redirect mails.
- **Test Scenarios:**
  - Create a compromised account in Office 365 or Google Workspace.
  - Alter mail forwarding rules to send copies of emails to an external address.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may not cover all third-party tools used for email redirection.
  - Potential undetected use of legitimate remote administration methods misused by adversaries.
  
- **Assumptions:**
  - Assumes that monitoring systems are fully integrated with mail server logs and event data.

## False Positives
Potential false positives include:
- Legitimate administrative changes to forwarding rules by authorized personnel.
- Remote desktop sessions for IT support conducted through legitimate channels.
- Automated backup solutions configured to archive emails externally.

## Priority
**Priority: High**

Justification: The capability of adversaries to collect sensitive information remotely without detection poses a significant threat. It allows attackers to access confidential data and evade traditional security measures, increasing the risk of data breaches.

## Validation (Adversary Emulation)
### Office 365 - Remote Mail Collected

1. **Setup Environment:** 
   - Create an Office 365 test tenant with necessary permissions.
   
2. **Simulate Adversarial Action:**
   - Use PowerShell to modify mail forwarding settings:
     ```powershell
     Set-Mailbox <MailboxName> -ForwardingAddress <ExternalEmail>
     ```
   
3. **Verify Detection:**
   - Check audit logs for changes in email forwarding rules.
   - Monitor security alerts triggered by unexpected configuration modifications.

## Response
When an alert is fired indicating potential remote email collection:
- Immediately review the affected mailbox’s recent activity and forwarding settings.
- Revoke any unauthorized forwarding configurations.
- Investigate the source of compromised credentials if applicable.
- Notify relevant stakeholders, including IT and legal teams, for further action.
- Initiate incident response procedures to contain and remediate the breach.

## Additional Resources
Currently, no additional references or context are available beyond the MITRE ATT&CK framework and internal security documentation. Further research into third-party tools used in email collection techniques is recommended for enhanced detection capabilities.