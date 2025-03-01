# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
The primary goal of this technique is to detect adversarial attempts to bypass security monitoring using containers. Specifically, it focuses on identifying the use of Right-to-Left Override (RTLO) attacks in containerized environments.

## Categorization

- **MITRE ATT&CK Mapping:** T1036.002 - Right-to-Left Override
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1036/002)

## Strategy Abstract

This detection strategy utilizes a combination of log analysis and file integrity monitoring to detect RTLO attacks within container environments. The approach involves:

1. **Log Analysis:** Monitoring process creation logs for suspicious command executions that may involve file names with embedded non-printable characters.
2. **File Integrity Checks:** Implementing checks on file names within the containers, especially in critical directories like `/bin`, `/usr/bin`, or application-specific executable paths.

By analyzing these data sources, patterns such as unusual characters or anomalies in file naming conventions are identified to flag potential RTLO attacks.

## Technical Context

Adversaries may use RTLO techniques by appending a Right-to-Left Override Unicode character (U+202E) to filenames, making legitimate commands appear suspicious. This is particularly effective on systems that do not display non-printable characters clearly or where logging mechanisms overlook these anomalies.

### Example Commands
An adversary might execute:
```bash
echo "powershell.exe" | iconv -f UTF-8 -t UTF-16 > maliciousfile.uu2 && echo 202E >> maliciousfile.uu2 && mv maliciousfile.uu2 powershell.exe
```

This command attempts to disguise `maliciousfile.uu2` as `powershell.exe` by using the RTLO character.

### Test Scenarios
1. **Command Execution:** Attempt execution of misleadingly named executables in controlled container environments.
2. **File Creation Monitoring:** Observe file creation processes for patterns indicating RTLO use.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection might not be effective on systems with non-standard or minimal logging configurations.
  - Some legitimate applications may use Unicode characters, potentially leading to misclassification.

- **Assumptions:**
  - The system logs detailed process creation information.
  - Container runtime environments are configured to allow for file integrity checks and log access.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate software using non-standard Unicode characters in filenames (e.g., localized applications).
- Misconfigured scripts or processes inadvertently embedding RTLO characters without malicious intent.
  
To minimize false positives, context-aware analysis should be employed, focusing on anomalous behaviors rather than isolated file characteristics.

## Priority

**Severity: Medium**

Justification:
- While RTLO attacks can bypass security monitoring effectively, they require specific conditions and knowledge to execute successfully. The medium priority reflects the balance between the potential impact of undetected evasion attempts and the likelihood of occurrence in typical environments.

## Response

When an alert for a suspected RTLO attack is triggered:

1. **Immediate Verification:** Confirm the presence of suspicious files by examining their properties and character encoding.
2. **Quarantine Affected Containers:** Isolate containers showing signs of RTLO usage to prevent further spread or data exfiltration.
3. **Investigate Anomalies:** Perform a thorough investigation into related processes, logs, and network activities to understand the scope and intent.
4. **Remediation Steps:**
   - Remove malicious files after verification.
   - Update logging configurations to improve detection capabilities.
   - Educate teams on identifying signs of RTLO usage.

## Additional Resources

- None available

This report outlines a structured approach for detecting Right-to-Left Override attacks within containerized environments, leveraging log and file integrity monitoring techniques. Continuous refinement based on real-world feedback and adversarial trends is recommended to enhance the detection framework's effectiveness.