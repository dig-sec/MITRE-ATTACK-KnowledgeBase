# Alerting & Detection Strategy Report: Double File Extension

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using double file extensions on Windows systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1036.007 - Double File Extension
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1036/007)

## Strategy Abstract
The detection strategy focuses on identifying file operations involving double extensions, which adversaries use to disguise malicious executables as harmless files. Data sources include filesystem event logs and process monitoring data. Patterns analyzed include file creation or modification events where a file with an extension like `.exe.txt` is manipulated.

## Technical Context
Adversaries often execute this technique by renaming executable files (e.g., `malware.exe`) to appear benign (`malware.exe.txt`). When executed, the system prioritizes the first extension (.exe), allowing the malware to run while appearing harmless in GUI environments. 

### Adversary Emulation Details:
- **Sample Command:** Rename a file using `rename malware.exe malware.exe.txt` via command prompt.
- **Test Scenario:** Create a benign `.txt` and a malicious `.exe` file, rename them to share the same name with double extensions, and observe system behavior.

## Blind Spots and Assumptions
- **Blind Spots:** Detection might not cover scenarios where files are renamed after execution or in environments lacking detailed logging.
- **Assumptions:** Assumes that security tools have access to detailed file metadata and that users do not manually override security alerts.

## False Positives
Potential benign activities include:
- Legitimate renaming of documents for organizational purposes by users.
- Software installation processes that rename files during setup.

## Priority
**Severity: Medium**

Justification: While double extensions are a common evasion technique, their effectiveness relies on the user's inability to recognize or verify file types. The impact can be significant if not detected, but it is less sophisticated compared to other evasion methods like code injection.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Setup Test Environment:**
   - Prepare a Windows environment with logging enabled for filesystem events and process monitoring.
2. **File Extension Masquerading:**
   - Create a benign `.txt` file named `test.txt`.
   - Create a malicious `.exe` file named `malware.exe`.
   - Rename `malware.exe` to `malware.exe.txt` using the command prompt with `rename malware.exe malware.exe.txt`.
3. **Execution and Monitoring:**
   - Execute `malware.exe.txt` by double-clicking or running it through a script.
   - Monitor system logs for execution of an `.exe` file despite its `.txt` extension.

## Response
When an alert fires:
1. **Immediate Action:** Quarantine the affected machine to prevent further spread.
2. **Investigation:**
   - Review the source and destination of the renamed files.
   - Analyze any associated processes for malicious behavior.
3. **User Notification:** Inform users about potential security risks related to file extensions.
4. **Preventative Measures:**
   - Implement file extension policies that prevent renaming of executables with double extensions.
   - Educate users on recognizing and reporting suspicious files.

## Additional Resources
- **Reference Materials:**
  - [LOL-Binary Copied From System Directory](https://attack.mitre.org/techniques/T1218)
  - [Suspicious Copy From or To System Directory](https://attack.mitre.org/techniques/T1047)

This report outlines a comprehensive strategy for detecting and responding to the use of double file extensions as an evasion technique, aligning with Palantir's ADS framework.