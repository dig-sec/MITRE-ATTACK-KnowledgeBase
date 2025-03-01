# Alerting & Detection Strategy (ADS) Report: System Network Connections Discovery

## Goal
This technique aims to detect adversarial attempts to discover system network connections. These activities are often precursors to lateral movement within a network and may indicate an adversary’s efforts to map the network for vulnerabilities or high-value targets.

## Categorization
- **MITRE ATT&CK Mapping:** T1049 - System Network Connections Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, IaaS, Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1049)

## Strategy Abstract
The detection strategy leverages a combination of data sources including network traffic logs, system event logs (e.g., Sysmon for Windows), and process monitoring. Key patterns analyzed include unusual or unauthorized attempts to use built-in utilities such as `netstat`, `nmap`, or PowerShell cmdlets like `Get-NetTCPConnection` that could be used by adversaries to map active network connections.

## Technical Context
Adversaries often execute this technique by leveraging native tools available on the host operating system to gather information about active network connections. They may use commands such as:

- Windows: `netstat -ano`, `Get-NetTCPConnection`
- Linux/macOS: `netstat`, `ss`, or custom scripts utilizing `/proc/net/tcp` and `/proc/net/tcp6`.
- FreeBSD: Commands like `sockstat`

### Adversary Emulation Details
Test scenarios may include:
- Running `netstat -ano` on a Windows system to capture active connections.
- Using PowerShell in Linux with WSL (Windows Subsystem for Linux) to execute `Get-NetTCPConnection`.
- On macOS, using terminal commands such as `lsof -i` or `ss`.

## Blind Spots and Assumptions
### Known Limitations:
- Limited visibility on encrypted connections unless decrypted at a controlled layer.
- May not capture ephemeral connections that are established and terminated rapidly.

### Assumptions:
- Baseline of normal network activity is well-established to distinguish between legitimate and malicious behavior.
- Systems have logging enabled for relevant data sources like Sysmon or audit logs.

## False Positives
Potential benign activities that might trigger false alerts include:

- Routine IT maintenance tasks where network administrators use these tools for troubleshooting.
- Legitimate security assessments conducted by internal teams using similar command-line utilities.
- Network scanning by automated scripts run as part of regular software updates or integrations.

## Priority
The priority is assessed as **High** due to the critical nature of this technique in understanding an adversary’s intent and potential access within a network. Detecting such activity early can prevent lateral movement and further compromise.

## Validation (Adversary Emulation)
### Steps to Emulate System Network Connections Discovery:

1. **System Network Connections Discovery:**
   - On Windows, open Command Prompt and execute `netstat -ano`.
   - Record the output and any unexpected results.

2. **System Network Connections Discovery with PowerShell:**
   - Execute `Get-NetTCPConnection` on a system where PowerShell is available.
   - Note the connections listed by this command.

3. **Linux & macOS System Network Connections Discovery:**
   - Use terminal commands like `netstat`, `ss`, or `lsof -i`.
   - Observe and document active network connections.

4. **System Discovery using SharpView (on Windows):**
   - Execute the SharpView tool to enumerate network-related information.
   - Capture its output for analysis.

## Response
When an alert indicating System Network Connections Discovery is triggered, analysts should:

- Immediately review the context of the alert, including which user account initiated the command and from what location/network segment.
- Cross-reference with known IT maintenance schedules or authorized security scans to rule out false positives.
- Investigate any anomalies such as connections to unusual IP addresses or excessive enumeration activities.
- Consider escalating for further incident response if malicious activity is confirmed.

## Additional Resources
No additional resources are available at this time. Analysts should refer to the MITRE ATT&CK framework and other internal threat intelligence feeds for more context on potential adversary TTPs related to T1049.