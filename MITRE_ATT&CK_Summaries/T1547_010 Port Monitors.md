# Palantir's Alerting & Detection Strategy (ADS) Report: Detecting Port Monitors on Windows

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring using port monitors in Windows environments.

## Categorization
- **MITRE ATT&CK Mapping:** T1547.010 - Port Monitors
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/010)

## Strategy Abstract
The detection strategy focuses on identifying port monitor applications configured by adversaries to monitor and potentially manipulate network traffic. The key data sources include system registry entries, process monitoring, and network traffic analysis. Patterns analyzed involve unexpected or unauthorized configurations in the Windows Registry that indicate the presence of a port monitor.

- **Data Sources:**
  - Windows Event Logs
  - System Registry (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services)
  - Network Traffic Analysis

- **Patterns Analyzed:**
  - Unusual registry modifications under `Services` indicating port monitors.
  - Processes with unexpected network access permissions.

## Technical Context
Adversaries may use port monitors to evade detection by monitoring and manipulating network traffic, allowing them to hide malicious activities or exfiltrate data without raising alarms. Typically, this involves creating a service in the Windows Registry that hooks into network API calls.

- **Execution Method:**
  - Adversaries modify registry keys such as `ImagePath` under services like "Tcpip" to point to a port monitor executable.
  - Example command for setting up a port monitor:
    ```shell
    reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableTaskOffload /t REG_DWORD /d 1
    ```

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection may miss port monitors that use sophisticated obfuscation techniques.
  - New or unknown variants of port monitor software might not be detected.

- **Assumptions:**
  - The system registry is accessible for monitoring.
  - Network traffic patterns are consistent and analyzable.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate network management tools configured by IT staff.
- Updates or patches that modify service configurations without malicious intent.

## Priority
**Severity: High**

Justification:
- Port monitors can significantly hinder the effectiveness of security monitoring and incident response, making them a critical threat vector to detect and mitigate promptly.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **Prepare the Environment:**
   - Ensure you have administrative access to a Windows machine.
   - Back up current registry settings before proceeding.

2. **Add Port Monitor Persistence in Registry:**
   - Open Command Prompt as Administrator.
   - Execute the following command:
     ```shell
     reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableTaskOffload /t REG_DWORD /d 1
     ```
   - This modifies the registry to indicate a port monitor configuration.

3. **Verify Configuration:**
   - Use `reg query` to verify changes:
     ```shell
     reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableTaskOffload
     ```

4. **Monitor for Alerts:**
   - Ensure your detection system is configured to alert on such registry modifications.

## Response
When an alert fires indicating the presence of a port monitor:

1. **Immediate Containment:**
   - Isolate the affected machine from the network to prevent potential data exfiltration or further compromise.

2. **Investigation:**
   - Analyze registry changes and associated processes.
   - Determine if the configuration is authorized by IT staff.

3. **Remediation:**
   - Revert unauthorized registry modifications.
   - Ensure all network management tools are configured securely.

4. **Reporting:**
   - Document findings and actions taken for further analysis and improvement of detection strategies.

## Additional Resources
- None available

This report provides a comprehensive approach to detecting port monitors using Palantir's ADS framework, ensuring robust security monitoring and response capabilities in Windows environments.