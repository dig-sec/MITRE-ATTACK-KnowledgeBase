# Alerting & Detection Strategy: Internet Connection Discovery (T1016.001)

## Goal
The aim of this detection strategy is to identify adversarial attempts to bypass security monitoring by discovering internet connectivity on targeted systems. This technique allows adversaries to determine if they can communicate with external command and control (C2) servers or exfiltrate data.

## Categorization

- **MITRE ATT&CK Mapping:** T1016.001 - Internet Connection Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Linux, macOS  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1016/001)

## Strategy Abstract
The detection strategy leverages a variety of data sources to identify patterns indicative of internet connection discovery activities. The primary focus is on system logs and network telemetry that capture command execution related to connectivity checks.

- **Data Sources:**
  - System logs (e.g., Windows Event Logs, Syslog)
  - Network traffic logs
  - PowerShell script execution logs

- **Patterns Analyzed:**
  - Execution of commands that test internet connectivity (e.g., `ping`, `Test-NetConnection` in PowerShell).
  - Abnormal spikes in network traffic patterns related to common ports used for connection checks.
  - Use of automation scripts or scheduled tasks to periodically verify internet access.

## Technical Context
Adversaries often execute this technique using built-in tools available across operating systems. By establishing an active internet connection, adversaries can facilitate further stages of their attack lifecycle such as data exfiltration or remote command execution. 

### Execution Methods:
- **Windows:** Utilizing `ping` commands or PowerShell’s `Test-NetConnection`.
- **Linux/macOS:** Using the `ping` command and other network utilities.
  
Example Commands:
- Windows: `ping 8.8.8.8`, `Test-NetConnection google.com -Port 80`
- Linux/macOS: `ping -c 4 8.8.8.8`

## Blind Spots and Assumptions
- **Blind Spots:** Detection might miss covert methods of internet discovery that do not utilize standard commands or logs.
- **Assumptions:** The strategy assumes adversaries will use common tools for connectivity checks, which might not always be the case.

## False Positives
Potential benign activities triggering false alerts include:
- Regular IT maintenance scripts checking network connectivity.
- Legitimate software updates verifying internet access before downloading.
- Routine user activity involving standard connectivity tests (e.g., troubleshooting).

## Priority
**Severity:** High  
**Justification:** Discovering internet connectivity is a critical step for adversaries to progress in their attack, facilitating further malicious activities such as data exfiltration or establishing remote access.

## Validation (Adversary Emulation)

To validate the detection strategy, follow these steps in a controlled test environment:

1. **Windows:**
   - Open Command Prompt and execute `ping 8.8.8.8`.
   - In PowerShell, run `Test-NetConnection google.com -Port 80` (HTTP) and `Test-NetConnection google.com -Port 445` (SMB).

2. **FreeBSD/Linux/macOS:**
   - Open Terminal and execute `ping -c 4 8.8.8.8`.

3. **Observation:** Monitor system logs, network traffic, and PowerShell execution logs for entries related to these commands.

## Response
When an alert is triggered:
- Verify the context of the activity (e.g., user identity, time, location).
- Investigate if the command was executed by authorized personnel or scripts.
- Correlate with other indicators of compromise (IoCs) to determine if this is part of a broader attack.

## Additional Resources
Currently, no additional resources are available. Future enhancements could include integration with threat intelligence feeds to improve context and response actions.

---

This report provides a comprehensive overview of the detection strategy for Internet Connection Discovery using Palantir's ADS framework. It balances technical rigor with practical considerations to support effective security monitoring and incident response.