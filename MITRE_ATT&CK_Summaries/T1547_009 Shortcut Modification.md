# Alerting & Detection Strategy (ADS) Report: Detecting Shortcut Modification for Persistence and Privilege Escalation on Windows

## Goal
The primary objective of this technique is to detect adversarial attempts to bypass security monitoring by modifying shortcut files, typically used to achieve persistence or privilege escalation. This strategy aims to identify unauthorized modifications that could lead to persistent access or elevated privileges for an attacker.

## Categorization
- **MITRE ATT&CK Mapping:** T1547.009 - Shortcut Modification
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

For more details, see the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/009).

## Strategy Abstract
The detection strategy leverages data from several sources including:
- File integrity monitoring systems for detecting changes in shortcuts.
- Event logs that capture shortcut creation or modification events (e.g., Windows Event Logs).
- User and group activity monitoring to track unauthorized access to shortcut files.

Key patterns analyzed include unusual modifications to known startup directory locations, such as `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`, or the creation of shortcuts in non-standard directories. Any discrepancies between current and baseline states of shortcut files are flagged for further investigation.

## Technical Context
Adversaries often modify or create shortcuts to bypass security measures by embedding malicious commands or scripts within these shortcuts. A common approach involves creating a shortcut that executes command-line utilities such as `cmd.exe` with specific parameters designed to elevate privileges or ensure persistence on the system.

### Adversary Emulation Details
- **Sample Commands:**
  - Create a shortcut with an embedded payload:
    ```bash
    lnkcreate -f "C:\Users\Public\Desktop\MaliciousShortcut.lnk" -p "cmd.exe /c <malicious_command>"
    ```

- **Test Scenarios:**
  1. Modify an existing application shortcut to execute `net user` for privilege escalation.
  2. Create a new shortcut in the Startup folder that executes `powershell.exe` with a script block designed for persistence.

## Blind Spots and Assumptions
### Known Limitations:
- The strategy may not detect modifications if the adversary uses obfuscation techniques to disguise changes.
- Shortcut modification detection might be less effective in environments where users frequently modify shortcuts as part of their normal activities.

### Assumptions:
- Baseline snapshots are accurate reflections of legitimate system states.
- Event logs and file integrity monitoring systems are fully operational without gaps or errors.

## False Positives
Potential benign activities that may trigger false alerts include:
- Legitimate user actions such as creating or modifying shortcuts for personal use in startup folders.
- System updates or software installations that modify shortcuts as part of their process.

## Priority
**Severity Assessment: High**

### Justification:
The high priority is due to the critical nature of persistence and privilege escalation techniques, which can enable adversaries to maintain control over compromised systems with elevated privileges. Detecting such actions early is crucial for preventing further exploitation or data exfiltration.

## Validation (Adversary Emulation)
Step-by-step instructions to emulate this technique in a controlled test environment:

1. **Shortcut Modification:**
   - Open Windows Explorer and navigate to `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`.
   - Create a new shortcut that opens Command Prompt (`cmd.exe`) with elevated privileges or persistence commands.
     ```bash
     lnkcreate -f "C:\Startup\MaliciousShortcut.lnk" -p "cmd.exe /c <malicious_command>"
     ```

2. **Create Shortcut to CMD in Startup Folders:**
   - Navigate to the `Startup` folder as shown above.
   - Create a shortcut for `cmd.exe` with parameters designed to execute malicious scripts or commands upon system startup.

3. **Observe Detection System Response:**
   - Ensure monitoring tools are active and configured to detect changes in the specified directories.
   - Verify alerts are triggered by these modifications and review alert details for accuracy.

## Response
Guidelines for analysts when an alert is triggered:
1. **Initial Assessment:** Quickly assess whether the modification was authorized or expected as part of routine operations.
2. **Investigate User Activity:** Review logs to determine which user made the change, their permissions, and historical activity patterns.
3. **Containment Measures:**
   - Disable the modified shortcut immediately if unauthorized access is confirmed.
   - Temporarily restrict affected user accounts to prevent further changes until an investigation is complete.

4. **Remediation Steps:** Based on findings, remove malicious shortcuts, restore any altered system files from backups, and apply necessary security patches or configuration updates.

5. **Post-Incident Analysis:**
   - Conduct a thorough analysis of how the modification bypassed existing controls.
   - Update detection rules and monitoring configurations to prevent similar incidents in the future.

## Additional Resources
- **Suspicious Calculator Usage:** Check for abnormal applications being launched via shortcuts, as they can serve as decoys or conceal malicious activities.
- **Potentially Suspicious CMD Shell Output Redirect:** Monitor for redirection of command output in shortcut scripts that could be used to exfiltrate data discreetly.

By following these guidelines and utilizing the outlined strategy, organizations can effectively detect and respond to attempts at using shortcut modification for adversarial purposes on Windows systems.