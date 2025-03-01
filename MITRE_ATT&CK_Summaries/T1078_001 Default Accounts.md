# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to exploit default accounts for gaining unauthorized access and evading security measures across various platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1078.001 - Default Accounts
- **Tactic / Kill Chain Phases:** Defense Evasion, Persistence, Privilege Escalation, Initial Access
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1078/001)

## Strategy Abstract
The detection strategy leverages data from multiple sources including Active Directory logs, Windows Event Logs, Azure AD activity logs, Office 365 audit logs, and other relevant security event streams. The patterns analyzed focus on abnormal activities such as:
- Activation of default accounts (e.g., Guest or Administrator accounts)
- Modifications to account privileges
- Unusual login attempts from known default accounts
- Changes in group memberships involving default accounts

## Technical Context
Adversaries may exploit default accounts due to their common presence and typical lack of stringent security controls. This technique is often executed by:
- Activating dormant default accounts
- Elevating privileges of these accounts for further access or lateral movement within the network
- Using compromised credentials, weak passwords, or known default credentials

### Adversary Emulation Details
- **Windows:** Enable Guest account via `net user guest /active:yes` and set a password.
- **macOS:** Use `dscl . -create /Users/guest UserShell /usr/bin/false` to create a guest account without login capabilities, then enable it.

## Blind Spots and Assumptions
- Detection relies on the assumption that default accounts are not routinely monitored or updated with strong credentials across all environments.
- Potential blind spots include scenarios where adversaries use non-standard methods to exploit default accounts, such as modifying system configurations at a low level.

## False Positives
Potential benign activities triggering false alerts may involve:
- Legitimate administrative tasks involving default account modifications for maintenance or deployment purposes
- Automated scripts or tools that temporarily enable default accounts during specific operations

## Priority
**Severity: High**

Justification: The exploitation of default accounts can provide adversaries with significant unauthorized access to critical systems and data, bypassing security controls.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:
1. **Windows:**
   - Open Command Prompt as an administrator.
   - Run `net user guest /active:yes` to activate the Guest account.
   - Set a password with `net user guest [password]`.

2. **macOS:**
   - Open Terminal.
   - Create and enable a guest account using:
     ```bash
     sudo dscl . -create /Users/guest UserShell /usr/bin/false
     sudo dscl . -create /Users/guest RealName "Guest Account"
     sudo dscl . -create /Users/guest UniqueID "500"
     sudo dscl . -create /Users/guest PrimaryGroupID 20
     sudo dseditgroup -o edit -a guest -t user admin
     ```
   - Note: Ensure you have proper permissions to create and modify accounts.

## Response
When an alert is triggered:
- Immediately investigate the context of the default account activity.
- Verify if there are legitimate reasons for the changes or usage.
- If malicious, isolate affected systems, reset passwords, and disable compromised accounts.
- Review logs for additional suspicious activities.
- Update security policies to enforce stricter controls on default accounts.

## Additional Resources
- **Suspicious Manipulation Of Default Accounts Via Net.EXE:** Explore how adversaries may manipulate account settings via command-line tools.
- **User Added to Local Administrators Group:** Monitor for unauthorized group modifications that can grant elevated privileges.
- **User Added to Remote Desktop Users Group:** Track changes in user groups related to remote access capabilities.
- **Weak or Abused Passwords In CLI:** Implement monitoring for weak passwords commonly used with default accounts. 

This report provides a structured approach to detecting and responding to the exploitation of default accounts, ensuring robust security posture across diverse environments.