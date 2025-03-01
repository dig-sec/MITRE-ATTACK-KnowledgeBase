# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring via Event Logging Disruption on Windows Platforms

## Goal
The primary objective of this technique is to detect adversarial attempts aimed at disabling or bypassing security monitoring systems by manipulating Windows event logging mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1562.002 - Disable Windows Event Logging
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/002)

## Strategy Abstract
This detection strategy focuses on identifying activities that aim to disrupt or disable Windows event logging. Key data sources include security logs, Windows Event Viewer, and system audit trails. The analysis involves monitoring for irregularities in event log configurations, unexpected service terminations, and unauthorized registry modifications. Patterns indicative of tampering with event logs are scrutinized to detect potential adversarial behavior.

## Technical Context
Adversaries may execute this technique by employing a variety of methods:
- **Disabling IIS HTTP Logging:** Through GUI or PowerShell commands.
- **Killing Event Log Service Threads:** Direct manipulation of system processes.
- **Modifying Audit Policies and Registry Settings:** Adjusting permissions to restrict logging capabilities.

Common tools used in adversary emulation include `wevtutil` for managing event logs, PowerShell scripts for registry modifications, and specialized malware like Phant0m that target log integrity. These actions often result in reduced visibility into system activities, allowing adversaries to operate undetected.

## Blind Spots and Assumptions
- **Blind Spots:** This strategy may not detect sophisticated methods involving encryption of logs or external storage manipulation.
- **Assumptions:** It assumes the presence of baseline configurations for event logging and audit policies. Additionally, it presumes that security monitoring systems are in place to capture log changes.

## False Positives
Potential benign activities that might trigger false alerts include:
- Authorized administrative tasks modifying event logging settings.
- Routine software updates or patches altering system configurations.
- Misconfigurations by non-malicious users leading to unintended log disruptions.

## Priority
**Severity: High**
The ability of adversaries to disable Windows event logging poses a significant threat as it can conceal malicious activities, making detection and response more challenging. Ensuring robust monitoring of event logs is crucial for maintaining system security integrity.

## Validation (Adversary Emulation)
To validate this detection strategy in a controlled environment, follow these steps:

1. **Disable Windows IIS HTTP Logging**
   - Use IIS Manager or PowerShell to turn off logging features.

2. **Disable Windows IIS HTTP Logging via PowerShell**
   ```powershell
   Set-WebConfigurationProperty -filter /system.applicationHost/sites/siteDefaults/logFile -name "enabled" -value "False"
   ```

3. **Kill Event Log Service Threads**
   - Terminate the `EventLog` service using Task Manager or command line: 
     ```cmd
     taskkill /F /IM eventlog.exe
     ```

4. **Impair Windows Audit Log Policy**
   - Modify Group Policy settings to disable auditing.

5. **Clear Windows Audit Policy Config**
   - Use `auditpol.exe` to clear audit policies:
     ```cmd
     auditpol /clear
     ```

6. **Disable Event Logging with wevtutil**
   ```cmd
   wevtutil cl Application
   wevtutil cl Security
   wevtutil cl System
   ```

7. **Makes Eventlog blind with Phant0m**
   - Deploy Phant0m in a test environment to simulate log tampering.

8. **Modify Event Log Channel Access Permissions via Registry - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "RestrictAccess" -Value 1
   ```

9. **Modify Event Log Channel Access Permissions via Registry 2 - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "RestrictAccess" -Value 1
   ```

10. **Modify Event Log Access Permissions via Registry - PowerShell**
    ```powershell
    Wevtutil.exe gl Application | ForEach-Object {Set-ItemProperty -Path $_ -Name 'RestrictANR' -Value 0x00000001}
    ```

## Response
When an alert is triggered:
1. **Immediate Investigation:** Verify the source and intent of changes to event logging configurations.
2. **Containment Measures:** Re-enable any disabled logs or services promptly to restore monitoring capabilities.
3. **Root Cause Analysis:** Determine if the activity was adversarial or benign, documenting all findings.
4. **Remediation Steps:** Apply corrective actions such as restoring original settings and enhancing policy controls to prevent recurrence.

## Additional Resources
Currently, there are no additional references available for this strategy.

---

This report provides a comprehensive overview of detecting event logging disruptions on Windows platforms, aligning with Palantir's Alerting & Detection Strategy framework. It outlines the approach, validation process, and necessary responses to ensure robust security monitoring against adversarial attempts.