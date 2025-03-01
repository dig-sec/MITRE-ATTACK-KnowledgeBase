# Alerting & Detection Strategy: Domain Accounts (T1078.002)

## Goal
The goal of this detection strategy is to identify adversarial attempts to create, use, and manage domain accounts as a means to bypass security monitoring, gain persistence, escalate privileges, and establish initial access within an environment.

## Categorization

- **MITRE ATT&CK Mapping:** T1078.002 - Domain Accounts
- **Tactic / Kill Chain Phases:** Defense Evasion, Persistence, Privilege Escalation, Initial Access
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1078/002)

## Strategy Abstract
This detection strategy focuses on monitoring for suspicious activities related to the creation and management of domain accounts across various platforms. Data sources such as Active Directory logs, network traffic analysis, file system changes, and process execution events are analyzed. Patterns include anomalous account creation, unexpected privilege escalations, unusual login attempts from different geographic locations or IP addresses, and usage patterns inconsistent with typical user behavior.

## Technical Context
Adversaries often use domain accounts to blend in as legitimate users while conducting malicious activities. These accounts can be leveraged for lateral movement across a network, accessing sensitive resources, or installing backdoors. Common tactics include creating accounts with elevated privileges without authorization, modifying group policies, or utilizing built-in administrative tools.

### Adversary Emulation Details
- **Command Examples:** 
  - PowerShell: `New-ADUser -Name "MaliciousAccount" -GivenName "John" -Surname "Doe" -Enabled $true`
  - Windows Command Prompt: `net user MaliciousAccount P@ssw0rd! /add`
- **Test Scenarios:** Simulate unauthorized domain account creation and monitor corresponding logs to validate detection.

## Blind Spots and Assumptions
- Assumes access to comprehensive logging from Active Directory and network devices.
- May not detect activities from highly skilled adversaries who use legitimate administrative tools with caution.
- Relies on baseline behavior models that may not be fully established in all environments.

## False Positives
- Legitimate IT operations involving bulk account creation for new employees or system updates.
- Scheduled tasks that involve domain accounts for maintenance purposes.
- Remote access by authorized users from unusual locations (e.g., traveling employees).

## Priority
**High**: Domain accounts are a critical vector for persistence and privilege escalation. Unauthorized use can lead to significant security breaches, including data exfiltration and system compromise.

## Validation (Adversary Emulation)
- **Step 1:** Set up a controlled environment with an Active Directory domain.
- **Step 2:** Execute the command examples above to create new accounts.
- **Step 3:** Monitor logs for account creation events and validate if they trigger alerts based on defined patterns.

## Response
When an alert indicating suspicious domain account activity is triggered:
1. Verify the legitimacy of the account creation or usage by cross-referencing with authorized IT changes.
2. Investigate any related anomalies such as unusual login times, IP addresses, or network traffic.
3. If unauthorized, disable the account immediately and conduct a thorough investigation to determine if other accounts were compromised.
4. Update security policies and user access controls to prevent similar incidents.

## Additional Resources
- **Active Directory Best Practices:** [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-best-practices)
- **MITRE ATT&CK Framework Documentation:** [MITRE ATT&CK](https://attack.mitre.org/)