# Alerting & Detection Strategy (ADS) Report: SID-History Injection Using Mimikatz

## Goal
This strategy aims to detect adversarial attempts to manipulate security monitoring systems by injecting SIDs into user accounts on Windows platforms using tools like Mimikatz. This technique is primarily used for privilege escalation and defense evasion.

## Categorization
- **MITRE ATT&CK Mapping:** T1134.005 - SID-History Injection
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1134/005)

## Strategy Abstract
The detection strategy involves monitoring for changes in the Security Identifier (SID) history of user accounts. This is achieved by analyzing data from security logs, specifically focusing on Event ID 4728 ("A member was added to a security-enabled global group") and Event ID 4769 ("An attempt was made to modify an object's SID"). The strategy looks for patterns indicating unauthorized modifications or additions to the SID-History attribute of user accounts.

## Technical Context
Adversaries often use Mimikatz, a powerful tool capable of extracting passwords, tokens, and manipulating Windows security structures, including SID-History injection. This technique allows attackers to add their own SIDs into other users' profiles, granting them elevated privileges without detection.

### Adversary Emulation Details:
- **Sample Commands:**
  - `privilege::debug`
  - `sekurlsa::logonpasswords`
  - `misc::sidhistory <TargetUsername>`

These commands can be used to escalate privileges and manipulate the SID-History attribute, allowing attackers to persistently access systems with elevated permissions.

## Blind Spots and Assumptions
- **Assumptions:**
  - Detection assumes that security logging is enabled and properly configured on Windows servers.
  - The strategy relies on timely log collection and analysis.

- **Blind Spots:**
  - If the attacker gains administrator access, they can disable or alter logs to evade detection.
  - Sophisticated adversaries might use alternate methods of privilege escalation, bypassing SID-History modifications entirely.

## False Positives
Potential false positives include legitimate administrative actions that modify user SIDs. These could occur during:
- Routine IT maintenance where administrators are authorized to add users to privileged groups.
- Misconfigurations or errors in automated systems managing user accounts.

## Priority
**High**: The ability for an attacker to bypass security controls and gain elevated privileges presents a significant threat, potentially leading to full system compromise if undetected.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Setup Environment:**
   - Use a controlled test environment with Windows OS.
   - Ensure that logging is enabled for Event IDs 4728 and 4769.

2. **Execute Mimikatz Command:**
   - Open a command prompt with administrative privileges.
   - Run `mimikatz.exe` to initiate the tool.
   - Enter the following commands:
     ```plaintext
     privilege::debug
     sekurlsa::logonpasswords
     misc::sidhistory <TargetUsername>
     ```

3. **Verify Injection:**
   - Check the Event Viewer for corresponding log entries (Event IDs 4728 and 4769) indicating SID-History modification.

## Response
When an alert is triggered:
1. **Immediate Investigation:**
   - Verify the legitimacy of the activity by cross-referencing with recent IT activities or authorized changes.
   - Isolate affected systems to prevent further unauthorized access.

2. **Forensic Analysis:**
   - Collect and analyze logs for additional context on the SID-History modifications.
   - Determine if any malicious tools like Mimikatz are present on the system.

3. **Remediation:**
   - Revoke unauthorized SIDs from affected accounts.
   - Update security policies to prevent future unauthorized SID modifications.
   - Consider implementing stricter access controls and auditing mechanisms.

## Additional Resources
- [HackTool - Mimikatz Execution](https://attack.mitre.org/software/S0053/)
- Windows Event Logs documentation for understanding Event IDs 4728 and 4769.

This strategy aims to provide a comprehensive approach to detecting SID-History injections, balancing thorough detection with minimizing false positives.