# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## Goal
The goal of this technique is to detect adversarial attempts to compromise email accounts within enterprise environments using phishing attacks and credential theft. This detection aims to identify unauthorized access and manipulation attempts on email services, primarily targeting platforms like Windows, Office 365, and Google Workspace.

## Categorization
- **MITRE ATT&CK Mapping:** T1087.003 - Email Account
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Office 365, Google Workspace  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1087/003)

## Strategy Abstract
This detection strategy leverages data from email logs, access records, and user behavior analytics to identify anomalies indicative of compromised email accounts. Key patterns include unusual login locations, unexpected attachment accesses or downloads, and sudden changes in sending behaviors that deviate from the norm for a given account.

Data sources utilized in this strategy encompass:
- Email server logs
- Authentication logs (e.g., sign-in events)
- User activity reports

Patterns analyzed involve abnormal access times, IP address discrepancies, and deviations in typical email patterns such as sending volume or attachment types. These are cross-referenced with threat intelligence feeds to enhance detection accuracy.

## Technical Context
Adversaries often execute this technique using spear-phishing emails containing malicious links or attachments designed to steal credentials or deliver malware. Upon successful compromise of an account, adversaries gain access to sensitive information and can further exploit the network by sending phishing emails from within the compromised account.

### Adversary Emulation Details
- **Sample Commands:** Attackers might use tools like Mimikatz for credential harvesting or PowerShell scripts for lateral movement.
- **Test Scenarios:** Simulate a spear-phishing attack with benign payloads to test detection mechanisms, ensuring alert generation on unauthorized access patterns without actual harm.

## Blind Spots and Assumptions
- Assumes baseline user behavior is well-established; new legitimate behaviors may initially trigger false positives.
- Detection effectiveness depends heavily on the completeness and quality of data sources.
- May not fully detect advanced persistent threats (APTs) that use slow, methodical approaches to evade detection.

## False Positives
Potential benign activities leading to false alerts include:
- Legitimate but unusual travel or work-from-home scenarios causing unexpected login locations.
- Employees sharing accounts for tasks like email management, resulting in atypical access patterns.
- Scheduled automated processes mimicking abnormal behaviors.

## Priority
**Priority: High**

Justification: Email account compromise can lead to significant data breaches and further network infiltration. Given the critical role of emails in business operations and communication, protecting against such threats is paramount to organizational security.

## Validation (Adversary Emulation)
Currently, specific step-by-step instructions for emulating this technique are not available due to the sensitive nature of potential testing environments. Organizations should work closely with cybersecurity teams to design safe and controlled simulations that mimic adversary tactics without risking actual data or systems.

## Response
When an alert is triggered:
1. Immediately isolate the affected email account by changing passwords and revoking session tokens.
2. Notify relevant stakeholders, including IT security teams and potentially impacted business units.
3. Conduct a forensic analysis to determine the extent of compromise and identify any malicious activities conducted through the account.
4. Review recent emails sent from the compromised account for signs of data exfiltration or further phishing attempts.
5. Implement additional monitoring on related accounts and systems to detect lateral movement or secondary attacks.

## Additional Resources
Currently, no specific additional references are available beyond the MITRE ATT&CK framework provided above. Organizations should consider leveraging threat intelligence platforms and industry reports to stay informed about emerging techniques and trends in email compromise tactics.