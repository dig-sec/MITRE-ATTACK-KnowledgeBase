# Alerting & Detection Strategy (ADS): Detect RDP Hijacking

## Goal
The aim of this detection strategy is to identify adversarial attempts to hijack Remote Desktop Protocol (RDP) sessions as part of lateral movement activities within a network, specifically targeting Windows platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1563.002 - RDP Hijacking
- **Tactic / Kill Chain Phases:** Lateral Movement
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1563/002)

## Strategy Abstract
This detection strategy focuses on monitoring network traffic and system logs to identify patterns indicative of RDP hijacking attempts. Key data sources include:

- Network traffic captures (e.g., NetFlow, sFlow)
- Security Information and Event Management (SIEM) logs
- System event logs from Windows hosts

The patterns analyzed involve anomalous login times, multiple failed login attempts followed by a successful login from unusual geographic locations or IP addresses, as well as unexpected changes in session duration or user activity.

## Technical Context
RDP hijacking involves compromising RDP sessions to gain unauthorized access to systems. Adversaries typically exploit weak credentials, unpatched vulnerabilities, or misconfigurations in the RDP protocol. Common methods include brute force attacks on RDP ports and leveraging stolen credentials from other compromised systems within the network.

### Adversary Emulation
To emulate RDP hijacking:

1. **Initial Access:**
   - Gain access to a machine with an active RDP session.
   
2. **Execution:**
   - Use tools such as Mimikatz to extract valid credentials (e.g., `mimikatz.exe "sekurlsa::logonpasswords"`) from the compromised system.

3. **Persistence and Lateral Movement:**
   - Authenticate using extracted credentials on other systems via RDP.
   - Execute commands remotely, for example, accessing sensitive directories or escalating privileges.

## Blind Spots and Assumptions
- Detection relies heavily on accurate log collection and timely analysis; any delay may result in missed detections.
- Assumes that network monitoring tools are correctly configured to capture relevant traffic and logs.
- Relies on the assumption that anomalies such as login patterns will be sufficiently distinct from normal user behavior.

## False Positives
Potential benign activities that might trigger false alerts include:

- Legitimate users accessing systems remotely from different locations (e.g., traveling employees).
- Scheduled tasks or automated processes initiating RDP sessions at unusual times.
- Misconfigurations leading to repeated logins without malicious intent.

## Priority
**Severity: High**

Justification: RDP hijacking enables attackers to move laterally within a network, potentially accessing sensitive data and escalating privileges. Its impact can be substantial if not detected promptly due to the attacker's ability to pivot across systems undetected.

## Validation (Adversary Emulation)
To validate this detection strategy in a controlled test environment:

1. **Setup:**
   - Configure a Windows machine with RDP enabled.
   - Ensure logging for failed and successful login attempts is enabled.

2. **Emulate Attack:**
   - Use a tool like Hydra or Metasploit to perform brute force on the RDP port.
   - Log in successfully using compromised credentials from another machine.

3. **Observe Indicators:**
   - Monitor network traffic for unusual RDP activity.
   - Check system logs for login anomalies and session changes.

## Response
When an alert for potential RDP hijacking fires:

1. **Initial Analysis:**
   - Verify the legitimacy of the RDP session by checking against known user access patterns.
   
2. **Containment:**
   - Isolate affected systems to prevent further lateral movement.

3. **Investigation:**
   - Collect and analyze logs from SIEM, network devices, and Windows event logs for additional indicators of compromise (IoCs).

4. **Remediation:**
   - Reset compromised credentials and patch vulnerabilities in RDP configurations.
   - Review and enhance security controls around RDP access.

5. **Communication:**
   - Inform relevant stakeholders about the breach and steps taken to mitigate risk.

## Additional Resources
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/mat/)
- Guides on securing RDP implementations and best practices.
  
This strategy provides a comprehensive approach to detecting RDP hijacking, emphasizing timely detection and response to minimize potential damage.