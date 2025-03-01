# Alerting & Detection Strategy (ADS) Report: File and Directory Permissions Modification

## Goal
The objective of this technique is to detect adversarial attempts to bypass security monitoring through unauthorized modifications of file and directory permissions.

## Categorization
- **MITRE ATT&CK Mapping:** T1222 - File and Directory Permissions Modification
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, Windows, macOS  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1222)

## Strategy Abstract
This detection strategy leverages multiple data sources, including file system monitoring tools, security information and event management (SIEM) systems, and endpoint detection and response (EDR) solutions. By analyzing patterns such as unexpected changes in permissions, deviations from baseline configurations, and anomalies in user access levels, the strategy aims to identify potential unauthorized permission modifications.

### Data Sources
- File System Monitoring Logs
- Security Information and Event Management (SIEM)
- Endpoint Detection and Response (EDR)

### Patterns Analyzed
- Unauthorized permission changes
- Deviations from established baselines
- Anomalies in user access levels

## Technical Context
Adversaries often execute file and directory permissions modification to evade detection by altering access controls or hiding their activities. Common methods include changing permissions on critical system files or directories to conceal malicious processes or data.

### Adversary Emulation Details
- **Linux:** Use `chmod` to change permissions.
  - Example: `sudo chmod 777 /important/file`
  
- **Windows:** Modify permissions using `icacls`.
  - Example: `icacls "C:\Program Files\ImportantApp" /grant Everyone:F`

- **macOS:** Similar approach as Linux with `chmod`.

## Blind Spots and Assumptions
- Assumes that baseline configurations are correctly established.
- May not detect changes made by legitimate administrative activities without context.
- Limited effectiveness if permissions modifications are part of normal operations.

## False Positives
Potential benign activities that might trigger false alerts include:
- Scheduled maintenance scripts modifying file permissions as part of routine updates.
- Legitimate system administrators changing permissions for troubleshooting purposes.
- Automated software installations or upgrades altering directory access controls.

## Priority
**High:** Unauthorized permission modifications can significantly impact security by allowing adversaries to hide their presence, escalate privileges, and exfiltrate data. The ability to bypass security measures poses a substantial risk.

## Validation (Adversary Emulation)
### Test Environment Steps

#### Enable Local and Remote Symbolic Links via `fsutil`
```bash
# Windows PowerShell Command
fsutil behavior set SymlinkEvaluation L:1 R:1
```

#### Enable Local and Remote Symbolic Links via `reg.exe`
```cmd
REM Run in Administrator mode
REG ADD "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" /v AllowInsecureRemoteNetDrives /t REG_DWORD /d 1 /f
```

#### Enable Local and Remote Symbolic Links via PowerShell
```powershell
# Windows PowerShell Command
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" -Name "EnableLinkedConnections" -Value 1 -PropertyType DWord
```

## Response
When an alert is triggered, analysts should:
1. **Verify the Change:** Confirm that permission changes are unauthorized and not part of planned activities.
2. **Containment:** Isolate affected systems to prevent further potential damage or data exfiltration.
3. **Investigation:** Examine logs for context, such as user activity leading up to the change.
4. **Remediation:** Revert permissions to their original state if malicious intent is confirmed.

## Additional Resources
- [Fsutil Behavior Set SymlinkEvaluation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior)
  
This report provides a comprehensive overview of detecting unauthorized file and directory permission modifications, following the principles outlined in Palantir's Alerting & Detection Strategy framework.