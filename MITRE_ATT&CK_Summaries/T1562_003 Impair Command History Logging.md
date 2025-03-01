# Alerting & Detection Strategy: Impair Command History Logging

## Goal
The objective of this detection technique is to identify adversarial attempts to bypass security monitoring by impairing command history logging on various operating systems, including Linux, macOS, and Windows.

## Categorization
- **MITRE ATT&CK Mapping:** T1562.003 - Impair Command History Logging
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/003)

## Strategy Abstract
This detection strategy leverages logs and configuration files to identify changes that impair command history logging. The primary data sources include system logs (such as bash or PowerShell logs), environment variable configurations, and registry settings on Windows.

Key patterns analyzed involve:
- Disabling history collection by setting variables like `HISTCONTROL` or modifying the shell's startup files.
- Altering log file paths or sizes to truncate command histories.
- Using registry modifications to disable command line auditing in Windows environments.

## Technical Context
Adversaries impair command history logging to evade detection of malicious activities on a compromised system. This technique is particularly useful when operating in environments where monitoring relies heavily on command logs for anomaly detection and forensic analysis.

### Real-world Execution:
1. **Linux/macOS:**
   - Disable or manipulate shell history settings (`HISTCONTROL`, `HISTSIZE`, `HISTFILESIZE`).
   - Clear existing bash history using commands like `history -c`.
   
2. **Windows:**
   - Modify registry keys to disable command line auditing.
   - Use PowerShell cmdlets or scripts to alter logging behaviors.

## Blind Spots and Assumptions
- This strategy assumes that adversaries are actively manipulating environment settings on the targeted systems.
- It may not detect indirect methods of log tampering, such as altering log rotation scripts.
- The detection relies heavily on monitoring configuration changes, which might be overlooked if an adversary uses more sophisticated means to hide these actions.

## False Positives
Potential false positives include:
- Legitimate administrative tasks where users modify history settings for privacy or performance reasons.
- Software installation scripts that adjust environment variables temporarily.
- Automated backup or maintenance scripts that reset or clear logs as part of their operations.

## Priority
**Priority: High**

Justification:
The technique directly undermines the ability to conduct forensic analysis and detect malicious activities, making it a high-priority target for detection. Successful implementation by adversaries can significantly hinder incident response efforts.

## Validation (Adversary Emulation)
To validate this detection strategy, follow these steps in a controlled test environment:

1. **Disable history collection on Linux/macOS:**
   - Add `export HISTCONTROL=ignorespace` to the shell configuration file (`~/.bashrc`, `/etc/bash.bashrc`).
   
2. **Clear bash history:**
   - Execute `history -c` and optionally append a false entry with `history -s "false command"`.

3. **Modify environment variables on Linux/macOS:**
   - Set `HISTSIZE=0` and `HISTFILESIZE=0` to prevent any commands from being logged.
   - Redirect the history file by setting `export HISTFILE=/dev/null`.

4. **FreeBSD specific adjustments:**
   - Use `setenv HISTIGNORE " *"` in shell configuration files.

5. **Disable Windows Command Line Auditing using `reg.exe`:**
   ```bash
   reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableCmdAudit /t REG_DWORD /d 0 /f
   ```

6. **Disable Windows Command Line Auditing using PowerShell:**
   ```powershell
   Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name "EnableCMDA" -Value 0
   ```

## Response
When an alert is triggered:
1. **Verify the Change:** Confirm whether changes to history logging settings are legitimate or malicious.
2. **Conduct Forensic Analysis:**
   - Examine recent system logs and user activities preceding the change.
   - Check for any unauthorized access or unusual behavior in the affected systems.
3. **Containment:**
   - Revert altered configurations to their default states.
   - Isolate impacted systems from the network if necessary.

## Additional Resources
- None available

---

This report outlines a comprehensive approach following Palantir's Alerting & Detection Strategy framework for identifying and mitigating attempts by adversaries to impair command history logging. Implementing this strategy effectively requires continuous monitoring, validation through adversary emulation, and prompt response actions when alerts are triggered.