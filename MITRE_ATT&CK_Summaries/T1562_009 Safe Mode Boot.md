# Palantir Alerting & Detection Strategy (ADS) Report: Safe Mode Boot Detection

## Goal
This technique aims to detect adversarial attempts that involve bypassing security monitoring by booting systems into Windows Safe Mode, a diagnostic mode designed to help troubleshoot and resolve system issues.

## Categorization

- **MITRE ATT&CK Mapping:** T1562.009 - Safe Mode Boot
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/009)

## Strategy Abstract
The detection strategy focuses on identifying the booting of Windows systems into Safe Mode. It leverages data from system event logs, particularly focusing on Event ID 1074 which records safe mode boots. Patterns such as frequent or unexpected Safe Mode entries are analyzed to distinguish between benign and malicious activities.

**Data Sources:**
- Windows Event Logs
- System Boot Records

## Technical Context
Adversaries may leverage Safe Mode to bypass security measures that are only active during a standard operating environment. In real-world scenarios, attackers might use boot configurations or scripts to initiate Safe Mode boot for evading detection while executing malicious activities.

**Execution Example:**
- Using Group Policy settings to configure automatic startup into Safe Mode.
- Modifying the Windows Registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` with `BootStatus` set to `0x1`.

## Blind Spots and Assumptions
- Assumes that event logs are consistently configured and maintained, which may not always be the case.
- Detection relies on log retention policies; insufficient log history can lead to missed detections.

## False Positives
Potential benign activities include:
- System administrators performing legitimate diagnostics or troubleshooting tasks in Safe Mode.
- Scheduled maintenance tasks that require system checks in diagnostic modes.

## Priority
**Severity: Medium**

Justification: While not as commonly exploited as other techniques, Safe Mode booting provides a significant opportunity for adversaries to evade detection. Its medium priority reflects the balance between its potential impact and frequency of use by adversaries.

## Validation (Adversary Emulation)
### Step-by-Step Instructions to Emulate Safe Mode Boot in a Test Environment

1. **Access Group Policy Editor:**
   - Open Run dialog (`Win + R`), type `gpedit.msc`, and press Enter.
   
2. **Configure Automatic Safe Mode Boot:**
   - Navigate to: `Computer Configuration -> Administrative Templates -> System -> Shutdown Options`.
   - Enable the policy "Always use basic startup programs".
   - Set the option to boot into safe mode.

3. **Modify Windows Registry (Alternative Method):**
   - Open Regedit (`Win + R`, type `regedit`).
   - Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.
   - Create or modify the DWORD value named `BootStatus` and set its value to `0x1`.

4. **Reboot System:**
   - Restart the test machine to trigger Safe Mode boot.

5. **Verify Detection:**
   - Check Event Viewer for Event ID 1074 confirming a Safe Mode boot.
   
6. **Reset Configuration:**
   - Revert changes in Group Policy or Registry to disable automatic Safe Mode boot and restore normal operations.

## Response
When an alert indicating a Safe Mode boot is triggered:

1. **Verify the Context:**
   - Determine if the Safe Mode entry correlates with scheduled maintenance or known troubleshooting activities.
   
2. **Investigate Further:**
   - Review related logs for additional indicators of compromise (IoCs) such as unexpected registry changes, unauthorized user access during Safe Mode, etc.

3. **Conduct a Forensic Analysis:**
   - Examine system files and configurations for signs of tampering or malware presence that may have exploited the Safe Mode boot.

4. **Report Findings:**
   - Document all findings and report them to relevant stakeholders for further action.

## Additional Resources
- None available

This strategy provides a comprehensive framework for detecting adversarial activities involving Safe Mode boots, ensuring security teams are equipped with necessary insights and response guidelines.