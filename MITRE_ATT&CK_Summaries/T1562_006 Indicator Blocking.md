# Alerting & Detection Strategy (ADS) Report: Indicator Blocking via Event Tracing

## Goal
The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring by manipulating event tracing mechanisms across Windows, macOS, and Linux platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1562.006 - Indicator Blocking
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, macOS, Linux

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/006)

## Strategy Abstract
This detection strategy leverages logs and system configurations to detect attempts by adversaries to disable or manipulate event tracing mechanisms. Data sources include:
- System and application logs on Windows (ETW), macOS, and Linux.
- Registry changes on Windows related to .NET Event Tracing for Windows (ETW).
- Environment variables indicating configuration adjustments in registry settings.

The strategy focuses on identifying patterns that signify disabling of ETW providers or manipulation of logging capabilities. Specific indicators include:
- Attempts to modify the registry keys associated with event tracing.
- Changes in environment variables influencing ETW.
- Configuration changes on Linux and FreeBSD hosts related to audit and logging services.

## Technical Context
Adversaries may execute this technique by using system-level commands to alter logging mechanisms, thus evading detection. Common adversary tactics include:
- Disabling the Windows Defender ETW provider via registry edits or command line tools.
- Adjusting environment variables that affect .NET ETW settings on Windows.
- Modifying audit configurations on Linux and FreeBSD systems.

Adversaries may employ scripts or manual commands to effect these changes, leveraging built-in tools like PowerShell, Command Prompt (`cmd`), or native scripting languages on macOS/Linux.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may be hindered if adversaries use sophisticated methods to revert logging mechanisms after executing malicious activities.
  - Some legitimate system maintenance tasks might temporarily alter logging configurations, mimicking adversary behavior.

- **Assumptions:**
  - Systems are configured with baseline logging and auditing enabled by default.
  - Network infrastructure supports centralized logging collection for effective monitoring.

## False Positives
Potential benign activities that may trigger false positives include:
- System administrators performing maintenance or updates that involve changes to logging configurations.
- Legitimate software installations that modify ETW settings as part of their setup process.
- Misconfigurations during system deployment that inadvertently alter audit and tracing capabilities.

## Priority
**Severity: High**

Justification: This technique directly impacts the ability to monitor system activities, which is crucial for detecting and responding to malicious actions. Successful indicator blocking can lead to significant security breaches if undetected.

## Validation (Adversary Emulation)
To validate this detection strategy, emulate adversary techniques in a controlled environment:

### Windows
- **Disable Powershell ETW Provider**
  - Use PowerShell commands to disable event tracing.
- **Registry Modifications for .NET ETW**
  - `cmd`: `reg add "HKLM\...\EventTrace" /v "Enable" /t REG_DWORD /d 0`
  - `powershell`: `Set-ItemProperty -Path "HKLM:\..." -Name "Enable" -Value 0`

### Linux and FreeBSD
- **Auditing Configuration Changes**
  - Verify audit settings using tools like `auditctl`.
- **Logging Configuration Adjustments**
  - Check syslog configurations to ensure logging services are active.

### BlackOps Simulation (Windows)
- **Disable Windows Defender ETW Provider**
  - Using cmd: `wevtutil im /path/to/ProviderManifest.xml`
  - Using PowerShell: `[System.Diagnostics.Eventing.Reader.ProviderConfiguration]::GetEnabled()`

### Environment Variables
- Adjust .NET ETW settings via environment variables:
  - For HKCU and HKLM, use `cmd` or `powershell` to set the appropriate environment variable values.

## Response
When an alert is triggered, analysts should:

1. **Verify Alert Legitimacy:** Determine if changes were made by authorized personnel.
2. **Conduct Forensic Analysis:**
   - Review logs for unauthorized access attempts or suspicious commands executed around the time of detection.
3. **Revert Changes:** Restore original logging configurations to ensure monitoring capabilities are intact.
4. **Update Security Controls:** Enhance system hardening measures to prevent similar incidents.

## Additional Resources
Currently, no additional resources are available beyond the referenced MITRE ATT&CK documentation. Analysts should maintain awareness of emerging threat intelligence and update detection strategies accordingly.