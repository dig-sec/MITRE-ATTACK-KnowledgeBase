# Alerting & Detection Strategy: Employee Name Reconnaissance

## Goal
The primary goal of this detection technique is to identify adversarial attempts to gather employee information as part of reconnaissance activities. This involves detecting methods used by adversaries to acquire lists of employee names, which could be leveraged for targeted phishing attacks or social engineering.

## Categorization
- **MITRE ATT&CK Mapping:** T1589.003 - Employee Names
- **Tactic / Kill Chain Phases:** Reconnaissance
- **Platforms:** PRE (Pre-Reconnaissance)
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1589/003)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing data sources such as network traffic, web traffic logs, social media interactions, public directories, and corporate intranet communications. Key patterns analyzed include unusual access requests to employee directories, spikes in traffic to HR-related pages or repositories, and anomalous queries targeting employee-specific information.

## Technical Context
Adversaries often seek out employee names through various channels including:
- Querying internal databases without authorization.
- Scraping publicly available corporate websites.
- Interacting with social media platforms using company hashtags or mentions.
- Using phishing emails to trick employees into revealing colleague information.

In a real-world context, adversaries might use tools like web scrapers or automated scripts to gather this data. Sample commands for such activities could include SQL injection attempts on employee databases (`SELECT * FROM Employees`) or web scraping scripts targeting corporate HR pages.

## Blind Spots and Assumptions
- **Blind Spots:** Detection may miss stealthy reconnaissance techniques that use encrypted traffic channels or low-and-slow approaches to avoid triggering alerts.
- **Assumptions:** It assumes the presence of logging mechanisms for employee directories and access logs, which might not be uniformly implemented across all organizational systems.

## False Positives
Potential false positives include:
- Legitimate HR or IT department activities accessing employee information for administrative purposes.
- Employees searching company intranet pages for contact details during routine communication tasks.
- Marketing teams using social media analytics tools to gather publicly available employee engagement metrics.

## Priority
**Priority: High**

Justification: The acquisition of employee names can lead directly to targeted phishing campaigns and other sophisticated attacks. Preventing the initial reconnaissance phase is crucial to thwart more damaging subsequent actions by adversaries.

## Validation (Adversary Emulation)
Currently, no specific adversary emulation scenarios are available for this technique. However, validation could be achieved through controlled exercises that simulate unauthorized queries to employee databases or test web scraping tools on internal HR websites in a sandbox environment.

## Response
When an alert is triggered:
1. **Immediate Investigation:** Confirm if the activity aligns with known legitimate operations.
2. **Incident Analysis:** Determine the source and method of access, examining IP addresses, user agents, and access patterns.
3. **Containment:** If malicious intent is confirmed, restrict access to sensitive directories or systems from suspicious sources.
4. **Notification:** Inform relevant stakeholders including IT security, HR, and potentially affected employees.
5. **Documentation:** Record findings and response actions for future reference and improvement of detection strategies.

## Additional Resources
Currently, there are no additional resources specified for this technique. However, organizations can refer to MITRE ATT&CK framework documentation and cybersecurity forums for emerging threats and updated adversary tactics related to employee reconnaissance activities.