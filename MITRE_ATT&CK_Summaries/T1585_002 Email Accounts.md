# Alerting & Detection Strategy (ADS) Report: Email Account Compromise - T1585.002

## Goal
The aim of this technique is to detect adversarial attempts to compromise email accounts and use them for malicious purposes. This includes identifying unauthorized access, account hijacking, or misuse of legitimate credentials by threat actors.

## Categorization
- **MITRE ATT&CK Mapping:** [T1585.002 - Email Accounts](https://attack.mitre.org/techniques/T1585/002)
- **Tactic / Kill Chain Phases:** Resource Development
- **Platforms:** PRE (Preparation)

## Strategy Abstract
The detection strategy involves monitoring for suspicious activities related to email accounts, focusing on anomalies that indicate compromise. Data sources include email server logs, authentication events, and user behavior analytics.

Key patterns analyzed:
- Unusual login locations or times.
- Sudden spikes in outgoing emails.
- Access from unrecognized devices or IP addresses.
- Changes in email forwarding settings without user authorization.

## Technical Context
Adversaries typically execute this technique by exploiting weak passwords, using phishing attacks, or employing malware to steal credentials. They may use compromised accounts to send phishing emails, spread malware, or exfiltrate sensitive data.

### Adversary Emulation Details
- **Phishing Campaigns:** Simulate spear-phishing emails containing malicious links or attachments.
- **Credential Harvesting Tools:** Use tools like Mimikatz or Cobalt Strike for credential dumping.
- **Test Scenarios:**
  - Attempt to login from an unrecognized IP address.
  - Modify email forwarding rules without user consent.

## Blind Spots and Assumptions
- Limited visibility into encrypted traffic may hide certain indicators of compromise.
- Assumes that baseline behavior patterns are well-established and monitored.
- Relies on the availability of comprehensive logging across all relevant systems.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate access from new devices or locations (e.g., travel).
- Scheduled email campaigns by marketing teams.
- Authorized changes to account settings for IT maintenance.

## Priority
**Severity: High**

Justification: Email accounts are critical assets, and their compromise can lead to significant data breaches, financial loss, and reputational damage. The ability of adversaries to use compromised accounts for further attacks amplifies the risk.

## Response
When an alert indicating potential email account compromise fires:
1. **Immediate Isolation:** Temporarily disable the affected account to prevent further misuse.
2. **Verification:** Confirm if the activity is legitimate by contacting the user and reviewing access logs.
3. **Investigation:**
   - Analyze login patterns, IP addresses, and device fingerprints.
   - Review recent email activities for unauthorized actions.
4. **Remediation:**
   - Reset compromised credentials.
   - Update security policies to prevent similar incidents (e.g., enforcing multi-factor authentication).
5. **Communication:** Inform relevant stakeholders about the incident and any data breach implications.

## Additional Resources
- None available

---

This report provides a comprehensive overview of detecting email account compromises using Palantir's ADS framework, ensuring that organizations can effectively monitor and respond to such threats.