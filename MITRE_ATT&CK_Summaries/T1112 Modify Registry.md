# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Registry Modifications

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring mechanisms by modifying Windows registry settings. These modifications can be used for various malicious purposes, including disabling security features, enabling persistence, and evading detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1112 - Modify Registry
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1112)

## Strategy Abstract
The detection strategy involves monitoring changes to the Windows registry that are indicative of adversarial activities. Key data sources include event logs, process monitoring tools, and system audit logs. Patterns analyzed include unauthorized modifications to critical registry keys related to security settings, RDP configurations, and persistence mechanisms.

### Data Sources:
- **Event Logs:** Monitor for specific events indicating registry changes (e.g., Event ID 4663).
- **Process Monitoring:** Track processes executing `reg.exe` or PowerShell commands that modify the registry.
- **Audit Logs:** Utilize Windows auditing to detect unauthorized access or modifications to sensitive registry keys.

### Patterns Analyzed:
- Unauthorized changes to security-related registry keys.
- Modifications enabling persistence mechanisms (e.g., startup entries).
- Changes disabling security features (e.g., antivirus settings).

## Technical Context
Adversaries exploit the flexibility of the Windows registry to achieve various malicious objectives. Common techniques include:

- **Disabling Security Features:** Modifying registry settings to turn off or bypass security software.
- **Enabling Persistence:** Adding keys to startup locations for persistent execution.
- **Evading Detection:** Altering logging and monitoring configurations to avoid detection.

### Adversary Emulation Details:
- Commands like `reg add` and PowerShell scripts are commonly used to modify the registry.
- Test scenarios include disabling Windows Defender notifications or altering RDP settings to allow unauthorized access.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Legitimate administrative changes may not be distinguishable from malicious ones without additional context.
  - Encrypted or obfuscated registry modifications may evade detection.

- **Assumptions:**
  - Monitoring systems are properly configured to capture relevant event logs.
  - Baseline knowledge of normal registry configurations exists for anomaly detection.

## False Positives
Potential benign activities that might trigger false alerts include:

- Legitimate administrative changes during system maintenance or updates.
- Software installations or uninstallations that modify registry settings.
- User actions configuring application preferences stored in the registry.

## Priority
**High.** The ability to modify the registry can significantly undermine security controls and enable further malicious activities, making it a critical vector for defense evasion.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **Modify Registry of Current User:**
   - Command: `reg add HKCU\Software\Test /v KeyName /t REG_SZ /d Value /f`

2. **Disable Windows Defender Notifications:**
   - Command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisablePopups /t REG_DWORD /d 1 /f`

3. **Enable RDP with No Network Level Authentication:**
   - Command: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`

4. **Add Persistence via Run Keys:**
   - Command: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MaliciousApp /t REG_SZ /d "C:\Path\To\Malicious.exe" /f`

5. **Abuse TelemetryController for Persistence:**
   - Command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\Telemetry\NonExistentKey" /v DisableTelemetry /t REG_DWORD /d 0 /f`

## Response
When an alert is triggered:

1. **Immediate Isolation:** Disconnect the affected system from the network to prevent further spread.
2. **Investigation:**
   - Review event logs for context around registry changes.
   - Identify processes that initiated the changes and assess their legitimacy.
3. **Remediation:**
   - Revert unauthorized registry modifications using backup or restore points.
   - Update security policies to prevent similar future incidents.
4. **Reporting:** Document findings and actions taken, and share with relevant stakeholders for awareness.

## Additional Resources
- ShimCache Flush
- Change PowerShell Policies to an Insecure Level
- Suspicious Reg Add BitLocker
- Potential Tampering With RDP Related Registry Keys Via Reg.EXE
- Reg Add Suspicious Paths
- Suspicious Windows Defender Registry Key Tampering Via Reg.EXE
- IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI
- Direct Autorun Keys Modification
- Potential Persistence Attempt Via Run Keys Using Reg.EXE

This strategy provides a comprehensive approach to detecting and responding to adversarial registry modifications, enhancing the security posture against sophisticated threats.