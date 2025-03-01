# Alerting & Detection Strategy (ADS) Report

## Goal
The primary aim of this technique is to detect adversarial attempts to bypass security monitoring by exploiting Kerberos Ticket Granting Tickets (TGTs) using tools like Mimikatz and Rubeus for "Pass the Ticket" attacks. This detection method focuses on identifying unauthorized use or manipulation of TGTs, which adversaries leverage to gain elevated privileges without authenticating as themselves.

## Categorization
- **MITRE ATT&CK Mapping:** [T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)
- **Tactic / Kill Chain Phases:** Defense Evasion, Lateral Movement
- **Platforms:** Windows

## Strategy Abstract
The detection strategy involves monitoring for anomalies related to Kerberos authentication processes across networked systems. Key data sources include security event logs (e.g., Sysmon events), Active Directory logs, and network traffic analytics. Patterns analyzed involve:
- Unusual ticket usage or modifications.
- Sudden changes in user privileges without legitimate authorization.
- Anomalous logon patterns that correlate with known "Pass the Ticket" tactics.

## Technical Context
Adversaries execute "Pass the Ticket" attacks by extracting TGTs using tools like Mimikatz and then manually applying them to gain access as other users. The attack vector exploits Kerberos' inherent trust in authenticated tickets, allowing adversaries to move laterally within a network without direct authentication.

### Adversary Emulation Details
- **Mimikatz Commands:**
  - `lsadump::secrets /export:kerberos.tgs`
  - Use the extracted ticket with `mimidump::pth /user:<username> <ticket_file>`
  
- **Rubeus Commands:**
  - `Rubeus.exe dump /domain:TARGET_DOMAIN /dc:DOMAIN_CONTROLLER`
  - Apply a ticket using `Rubeus.exe pth /ticket:<ticket_data>`

## Blind Spots and Assumptions
- Assumes that TGT manipulations are detectable through log analysis, which may not capture all sophisticated evasion techniques.
- Relies on comprehensive logging of Kerberos events; lack of logs can create blind spots.
- Assumes consistent network behavior baselines to identify anomalies.

## False Positives
Potential benign activities triggering false alerts include:
- Legitimate use of third-party tools for administrative purposes.
- Scheduled tasks or scripts using tickets legitimately within their operational scope.
- Misconfigurations leading to unusual but legitimate ticket usage patterns.

## Priority
**Priority: High**

Justification: The ability to bypass authentication mechanisms poses a significant threat to enterprise security, allowing adversaries to escalate privileges and move laterally undetected. Early detection is crucial for preventing extensive damage or data breaches.

## Validation (Adversary Emulation)
To emulate "Pass the Ticket" in a controlled test environment:

1. **Mimikatz Kerberos Ticket Attack:**
   - Install Mimikatz on a Windows system.
   - Execute `lsadump::secrets /export:kerberos.tgs` to extract TGTs.
   - Use `mimidump::pth /user:<username> <ticket_file>` to apply tickets.

2. **Rubeus Kerberos Pass The Ticket:**
   - Install Rubeus on a Windows system.
   - Run `Rubeus.exe dump /domain:TARGET_DOMAIN /dc:DOMAIN_CONTROLLER` to extract TGTs.
   - Apply the ticket using `Rubeus.exe pth /ticket:<ticket_data>`.

Ensure all activities are monitored and logged for analysis.

## Response
When an alert fires:
1. Verify the legitimacy of the activity by cross-referencing with known administrative tasks or scheduled operations.
2. Isolate affected systems to prevent further potential misuse of compromised tickets.
3. Conduct a thorough investigation, examining logs for unusual patterns or behaviors preceding the alert.
4. Update detection rules to minimize future false positives and refine anomaly baselines.

## Additional Resources
- [Mimikatz - A Pentesting Framework](https://github.com/gentilkiwi/mimikatz)
- [Rubeus - A Kerberos Attack Tool](https://github.com/GhostPack/Rubeus)

This report aims to provide a comprehensive understanding of the detection strategy for "Pass the Ticket" attacks, ensuring that security teams are equipped with the necessary tools and knowledge to protect against this advanced threat vector.