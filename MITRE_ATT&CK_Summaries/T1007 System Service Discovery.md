# Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by leveraging system service discovery techniques on Windows and macOS platforms. The focus is identifying unauthorized access or enumeration of running services that could lead to further exploitation.

## Categorization
- **MITRE ATT&CK Mapping:** T1007 - System Service Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1007)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing system service discovery activities across various data sources including process execution logs, command-line interface (CLI) activity, network traffic, and host-based security events. The primary patterns analyzed include:
- Execution of commands such as `net.exe`, `systemctl`, or PowerShell cmdlets like `Get-Service`.
- Unusual access patterns to service management tools indicating reconnaissance.
- Network traffic anomalies associated with remote queries for services.

## Technical Context
Adversaries often use system service discovery techniques to gain insights into the configuration and running state of a target environment. This information can be used to identify critical services that may be targeted for further exploitation, such as privileged access or lateral movement. Real-world execution involves:
- Using `net.exe` on Windows to list services.
- Employing `systemctl` commands on Linux/macOS systems.
- PowerShell cmdlets like `Get-Service` on Windows.

## Blind Spots and Assumptions
- The strategy assumes that adversaries will execute service discovery in a detectable manner. Stealthy or obfuscated execution may bypass detection.
- It does not account for encrypted traffic without proper decryption mechanisms in place, potentially missing network-based reconnaissance.
- Limited coverage of custom scripts or binaries that perform similar functions but are not directly recognizable by the system.

## False Positives
Potential false positives include:
- Legitimate IT administrators performing routine service audits and maintenance using the same tools and commands.
- Automated backup processes accessing services for status checks.
- Scheduled tasks on systems configured to query service states as part of monitoring routines.

## Priority
**High**: System service discovery is a common initial step in adversarial reconnaissance, providing critical information that could facilitate further attacks. Early detection can prevent deeper infiltration and mitigate potential damage.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **System Service Discovery**
   - On Windows: Execute `net start` to list running services.
   - On macOS/Linux: Use `systemctl list-units --type=service`.

2. **System Service Discovery - net.exe**
   - Command: Run `net.exe start` on a Windows machine and observe the output.

3. **System Service Discovery - systemctl/service**
   - Command: Execute `sudo systemctl list-running` on Linux/macOS to check active services.

4. **Get-Service Execution**
   - Command: On Windows, run PowerShell as an administrator and execute `Get-Service`.

## Response
When an alert for system service discovery fires:
1. Investigate the context of the command execution, including user identity and time of activity.
2. Check if the activity correlates with legitimate administrative tasks or scheduled jobs.
3. Assess network traffic to identify any unusual remote access patterns.
4. If malicious intent is suspected, escalate the incident following organizational procedures and engage incident response teams.

## Additional Resources
- **Potentially Suspicious CMD Shell Output Redirect**: Monitor for redirections in command outputs that could indicate attempts to hide results.
- **Suspicious Tasklist Discovery Command**: Be wary of tasklist commands with unusual flags or filters that may be used to gather detailed service information stealthily.

By implementing this ADS framework, organizations can enhance their ability to detect and respond to potential reconnaissance activities by adversaries.