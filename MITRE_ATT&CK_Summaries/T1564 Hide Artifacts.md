# Alerting & Detection Strategy (ADS) Report

## Goal
This detection strategy aims to identify adversarial attempts to hide files, processes, registry keys, network connections, and other artifacts on endpoints to bypass security monitoring systems.

## Categorization

- **MITRE ATT&CK Mapping:** [T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564)
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows, Office 365

## Strategy Abstract

The detection strategy leverages a combination of data sources and pattern analysis to uncover attempts by adversaries to hide artifacts. Key data sources include:

- **File System Monitoring:** Detects changes in file attributes or hidden files using tools like PowerShell scripts on Windows or `find`/`lsattr` commands on Linux/macOS.
- **Process and Registry Activity Logs:** Monitors for unusual process behaviors, such as processes with hidden windows or registry key modifications that indicate attempts to hide executables or other artifacts.
- **Network Traffic Analysis:** Identifies anomalies in network connections that might be masked by adversaries.
- **Endpoint Detection and Response (EDR):** Collects data on endpoint activities, including service creation and modification.

Patterns analyzed include file attribute changes (e.g., hidden or system files), unusual process behaviors (e.g., running from memory), and anomalous registry key modifications.

## Technical Context

Adversaries often use the following methods to execute T1564 in real-world scenarios:

- **File Hiding:** Modify file attributes using command-line tools like `attrib` on Windows or `chflags` on macOS to hide files.
- **Process Hiding:** Use techniques such as process hollowing or hiding window titles to obscure running processes.
- **Registry Key Modifications:** Alter registry settings to conceal malicious software, often modifying keys associated with startup programs or services.

Adversary emulation details include:

- Sample Command (Windows): `attrib +h targetfile.exe`
- Test Scenario: Create a hidden file and modify its attributes to trigger detection.

## Blind Spots and Assumptions

- **Blind Spots:** 
  - Encrypted files may not be easily detectable if encryption methods are legitimate.
  - Advanced obfuscation techniques might evade simple pattern matching.
  
- **Assumptions:**
  - Baseline behavior is well-understood for accurate anomaly detection.
  - Comprehensive logging and monitoring systems are in place.

## False Positives

Potential benign activities that could trigger false alerts include:

- Legitimate use of file hiding features by users or applications (e.g., system files, temporary files).
- Normal administrative tasks that modify registry keys or create hidden services for maintenance purposes.

## Priority
**Priority: High**

Justification: Hiding artifacts is a critical step in evading detection, allowing adversaries to maintain persistence and execute malicious activities without being discovered. The impact of undetected evasion can be significant, justifying a high priority level for this strategy.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Extract Binary Files via VBA:**
   - Use Excel macros to extract files embedded in documents.
   
2. **Create a Hidden User Called "$":**
   - Command on Windows: `net user $ /add` followed by setting the account as hidden.

3. **Create an "Administrator" User (with a space on the end):**
   - Command on Windows: `net user Administrator  /add`.

4. **Create and Hide a Service with sc.exe:**
   - Create service: `sc create MyService binPath= "C:\path\to\myexe.exe"`
   - Set as hidden: `sc config MyService type= own`

5. **Command Execution with NirCmd:**
   - Execute commands silently using NirCmd, e.g., `nircmd hide C:\targetfile.exe`.

## Response

When an alert fires indicating potential artifact hiding:

1. **Immediate Investigation:** Verify the legitimacy of the hidden files or processes.
2. **Containment:** Isolate affected systems to prevent further spread.
3. **Forensic Analysis:** Conduct a thorough investigation to understand the scope and impact.
4. **Remediation:** Remove malicious artifacts and restore system integrity.

## Additional Resources

- None available at this time.

This ADS framework provides a comprehensive approach to detecting and responding to adversarial attempts to hide artifacts, ensuring robust defense against evasion tactics.