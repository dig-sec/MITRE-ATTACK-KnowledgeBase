# Alerting & Detection Strategy: Timestomp - MITRE ATT&CK Mapping T1070.006

## Goal
This detection technique aims to identify adversarial attempts to bypass security monitoring by altering file timestamps, known as timestomping. This method can obscure the true creation, modification, or access times of files and system logs, complicating forensic investigations and evading detection mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1070.006 - Timestomp
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

For more information, visit the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/006).

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing file metadata to identify unusual changes in timestamps. Key data sources include:
- **File Access Logs:** Monitoring access times for discrepancies.
- **Modification Logs:** Tracking unexpected modifications.
- **Creation Timestamps:** Observing anomalies in creation dates.

Patterns analyzed involve sudden, unexplained changes across these timestamps that do not align with normal user or system behavior, particularly those that precede suspicious activity or incidents.

## Technical Context
Adversaries use timestomping to cover their tracks by modifying the metadata of files and logs. This can be done through various tools or scripts available on different operating systems:
- **Linux/macOS:** Tools like `touch` and `atime`.
- **Windows:** PowerShell commands such as `Set-ItemProperty`.

### Adversary Emulation Details
Sample commands include:
- Linux: `touch -t 202301010000.00 target_file`
- Windows PowerShell: 
  ```powershell
  (Get-Item "target_file").LastWriteTime = Get-Date '01/01/2023'
  ```

## Blind Spots and Assumptions
- **Blind Spots:** Detection may miss timestamp changes made by legitimate system processes or applications that have inherent permissions to modify file metadata.
- **Assumptions:** Assumes baseline knowledge of normal user behavior patterns to distinguish between legitimate and malicious activities.

## False Positives
Potential benign triggers include:
- Legitimate use of timestamp modification tools for software development or data management tasks.
- Scheduled maintenance scripts altering timestamps as part of system updates.

## Priority
**Severity: Medium**
Justification: While timestomping is a sophisticated technique that can significantly hinder forensic investigations, its detection relies on establishing baseline behavior. The impact is substantial but not immediate, thus warranting a medium priority status.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

### Set File Timestamps
1. **Linux/macOS:** Use `touch` to set file timestamps.
   ```bash
   touch -t 202301010000.00 target_file
   ```

2. **Windows:**
   - Modify creation timestamp:
     ```powershell
     (Get-Item "target_file").CreationTime = Get-Date '01/01/2023'
     ```
   - Modify last modified timestamp:
     ```powershell
     (Get-Item "target_file").LastWriteTime = Get-Date '01/01/2023'
     ```
   - Modify last access timestamp:
     ```powershell
     (Get-Item "target_file").LastAccessTime = Get-Date '01/01/2023'
     ```

### Timestomp Using Reference File
1. **Linux/macOS:**
   ```bash
   touch -r reference_file target_file
   ```

2. **Windows:**
   - Use PowerShell to mimic the reference file timestamp:
     ```powershell
     (Get-Item "target_file").LastWriteTime = (Get-Item "reference_file").LastWriteTime
     ```

### Event Log Manipulations
- Execute time slipping using PowerShell for event logs.
  ```powershell
  wevtutil slp /rd:true /st:01/01/2023 /et:12/31/2025
  ```

## Response
When an alert fires:
1. **Immediate Investigation:** Analyze the files and logs with altered timestamps to determine if there is a correlation with other suspicious activities.
2. **User Verification:** Confirm whether legitimate users or system processes executed these changes.
3. **Containment Actions:** If malicious intent is confirmed, isolate affected systems and prevent further alterations.
4. **Documentation:** Record findings and response actions for future reference and improvement of detection strategies.

## Additional Resources
Additional references and context are currently not available but can be gathered from security forums or threat intelligence feeds related to timestomping techniques and incidents.

---

This report outlines a structured approach to detecting and responding to timestomp activities, leveraging insights from the MITRE ATT&CK framework.