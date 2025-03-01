# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to compromise email accounts for malicious purposes.

## Categorization
- **MITRE ATT&CK Mapping:** T1586.002 - Email Accounts
- **Tactic / Kill Chain Phases:** Resource Development
- **Platforms:** PRE (Persistent, Resilient Environment)
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1586/002)

## Strategy Abstract
The detection strategy focuses on monitoring anomalies in email account usage that may indicate compromise. Data sources include:
- Email server logs
- Authentication logs
- Network traffic analysis

Patterns analyzed involve unusual login times, IP addresses from unexpected locations, and abnormal volume or frequency of sent emails.

## Technical Context
Adversaries often gain access to legitimate email accounts through phishing attacks, exploiting weak credentials, or leveraging social engineering techniques. Once compromised, these accounts can be used for spear-phishing campaigns, spreading malware, or exfiltrating sensitive information.

### Adversary Emulation Details
In a test environment, this technique could be emulated by:
- Using a simulated phishing attack to gain unauthorized access.
- Executing commands that mimic abnormal account activities (e.g., sending emails from unusual locations).

## Blind Spots and Assumptions
- Detection might miss sophisticated attacks using anonymization techniques like VPNs or Tor.
- Assumes all email accounts have baseline behavior established for anomaly detection.

## False Positives
Potential benign activities include:
- Legitimate users traveling abroad.
- Changes in user behavior patterns (e.g., working from home).
- Scheduled automated emails.

## Priority
**Severity: High**
Justification: Compromised email accounts can lead to significant security breaches, including data exfiltration and further network infiltration.

## Response
When the alert fires:
1. Immediately isolate the affected account.
2. Conduct a thorough investigation of recent activities associated with the account.
3. Verify if there are any ongoing malicious campaigns using the compromised account.
4. Initiate password resets for all related accounts and enforce multi-factor authentication (MFA).
5. Notify relevant stakeholders and update incident response protocols.

## Additional Resources
Currently, no additional resources are available beyond standard cybersecurity frameworks and guidelines provided by organizations such as MITRE ATT&CK.