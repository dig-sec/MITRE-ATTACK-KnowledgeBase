# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring via File Deletion

## Goal
This detection strategy aims to identify and mitigate adversarial attempts to bypass security monitoring by deleting files on Linux, macOS, Windows, and other platforms. The primary focus is on recognizing patterns of file deletion that could indicate malicious activity, including attempts to cover tracks or remove evidence.

## Categorization
- **MITRE ATT&CK Mapping:** T1070.004 - File Deletion
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/004)

## Strategy Abstract
The strategy utilizes various data sources such as file integrity monitoring (FIM) logs, system event logs, and command-line history to detect suspicious file deletion activities. Patterns analyzed include unexpected deletions of critical files or directories, usage of elevated privileges for deletion, and anomalies in file modification timestamps.

## Technical Context
Adversaries may execute file deletion techniques to conceal their actions, erase evidence, or disrupt logging mechanisms. Common methods include using system commands (e.g., `rm`, `del`) and utilities like `shred` to overwrite files before deletion. Additionally, attackers might manipulate logs to remove traces of the deleted items.

### Adversary Emulation Details
- **Sample Commands:**
  - `rm /path/to/file` on Linux/macOS
  - `del C:\path\to\file` on Windows cmd
  - `Remove-Item C:\path\to\file` in PowerShell

## Blind Spots and Assumptions
- **Limitations:** 
  - Detection might miss deletions that occur during legitimate operations or maintenance windows.
  - Some file deletion methods, like secure deletion with tools not monitored by the system, may evade detection.
  
- **Assumptions:**
  - The environment logs all deletion activities and user commands comprehensively.

## False Positives
Potential benign activities triggering false alerts include:
- Regular system cleanup scripts deleting temporary files.
- Legitimate administrative tasks involving file removal or purging log directories.

## Priority
**Priority Level:** High

**Justification:**  
File deletion can significantly hinder forensic analysis by removing critical evidence. Detecting such attempts is crucial for maintaining the integrity of security monitoring systems and ensuring timely incident response.

## Validation (Adversary Emulation)
To validate detection mechanisms, follow these steps in a controlled environment:

1. **Delete a Single File:**
   - FreeBSD/Linux/macOS: `rm /tmp/testfile`
   - Windows cmd: `del C:\temp\testfile`
   - Windows PowerShell: `Remove-Item C:\temp\testfile`

2. **Delete an Entire Folder:**
   - FreeBSD/Linux/macOS: `rm -r /tmp/testfolder`
   - Windows cmd: `rd /s /q C:\temp\testfolder`
   - Windows PowerShell: `Remove-Item C:\temp\testfolder -Recurse`

3. **Overwrite and Delete a File with Shred:**
   - Linux/macOS: `shred -u /tmp/securefile`

4. **Delete Filesystem (Linux):**
   - Warning: This will delete all files on the specified filesystem.
     - Example: `rm -rf /*` (Run only in an isolated environment)

5. **Delete Prefetch File:**
   - Windows cmd: Locate and delete prefetch file via `del C:\WINDOWS\Prefetch\*`

6. **Delete TeamViewer Log Files:**
   - Locate and delete log files using the appropriate command based on your system setup.

7. **Clears Recycle Bin via RD:**
   - Clear contents of Recycle Bin using:
     - Windows cmd: `rd /s /q C:\$Recycle.Bin`

## Response
When an alert for file deletion is triggered, analysts should:
- Immediately review the context and origin of the deleted files.
- Determine if the deletions are part of a legitimate process or indicative of malicious activity.
- Check user permissions to identify unauthorized access.
- Conduct a thorough investigation into related activities, such as log modifications or unusual network traffic.

## Additional Resources
For further reading and tools:
- [File Deletion Techniques](https://attack.mitre.org/techniques/T1070/)
- File And SubFolder Enumeration Via Dir Command
- Directory Removal Via Rmdir
- Copy From Or To Admin Share Or Sysvol Folder
- File Deletion Via Del

This report provides a structured approach to detecting and responding to adversarial file deletion activities, ensuring robust security monitoring and incident response capabilities.