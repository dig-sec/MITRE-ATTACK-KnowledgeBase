# Alerting & Detection Strategy: Automated Collection (T1119)

## Goal
The objective of this detection strategy is to identify adversarial attempts to bypass security monitoring using automated collection techniques on systems running Linux, macOS, and Windows.

## Categorization
- **MITRE ATT&CK Mapping:** T1119 - Automated Collection
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Linux, macOS, Windows

For more information, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1119).

## Strategy Abstract
The detection strategy focuses on identifying patterns and anomalies indicative of automated collection techniques used by adversaries. Data sources include system logs, process monitoring outputs, and network traffic analysis. Patterns analyzed involve unusual command-line executions, unexpected file access or enumeration, and irregular data exfiltration activities.

## Technical Context
Adversaries employ automated collection to gather information from target systems without manual intervention. This technique is often executed using scripts or tools that automate reconnaissance tasks such as directory listing, system information gathering, and network scanning.

### Adversary Emulation Details:
- **Sample Commands:**
  - `dir /s /b > output.txt` (Windows Command Prompt)
  - `powershell.exe Get-ChildItem C:\ -Recurse | Select-Object FullName > output.txt` (PowerShell)

## Blind Spots and Assumptions
- **Limitations:** Detection may not cover all variants of automated collection scripts.
- **Assumptions:** The strategy assumes that adversaries will use common command-line tools for automation.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate system administrators performing routine maintenance or audits.
- Automated backup processes generating similar patterns.

## Priority
**Severity: High**
Justification: Automated collection can provide adversaries with critical information about the target environment, facilitating further attacks. Early detection is crucial to mitigate potential threats.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

#### Automated Collection Command Prompt
1. Open Command Prompt.
2. Execute: `dir /s /b > output.txt`
3. Monitor for unusual file creation or network traffic.

#### Automated Collection PowerShell
1. Open PowerShell.
2. Execute: `powershell.exe Get-ChildItem C:\ -Recurse | Select-Object FullName > output.txt`
3. Observe for unexpected data exfiltration signs.

#### Recon Information for Export with PowerShell
1. Use PowerShell to gather system information:
   ```powershell
   Get-WmiObject Win32_OperatingSystem | Format-List *
   ```
2. Check logs for unauthorized script executions.

#### Recon Information for Export with Command Prompt
1. Execute: `systeminfo > output.txt`
2. Analyze logs for unusual command usage patterns.

## Response
When an alert is triggered:
1. Verify the legitimacy of the process or user.
2. Isolate affected systems to prevent data exfiltration.
3. Conduct a thorough investigation to determine the scope and impact.
4. Implement additional monitoring measures on critical assets.

## Additional Resources
- [Potentially Suspicious CMD Shell Output Redirect](https://example.com/cmd-suspicious-output)
- [Automated Collection Command Prompt](https://example.com/automated-collection-cmd)
- [Suspicious Copy From or To System Directory](https://example.com/suspicious-copy-system-directory)
- [File And SubFolder Enumeration Via Dir Command](https://example.com/file-subfolder-enumeration)

This report provides a comprehensive framework for detecting automated collection activities, aligning with Palantir's Alerting & Detection Strategy.