# Alerting & Detection Strategy (ADS) Report: Code Signing Policy Modification

## Goal
The primary goal of this detection strategy is to identify adversarial attempts to modify code signing policies on Windows and macOS platforms. This technique falls under the broader category of defense evasion, where adversaries alter or disable security controls that rely on digital signatures for authenticity.

## Categorization
- **MITRE ATT&CK Mapping:** T1553.006 - Code Signing Policy Modification
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, macOS  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1553/006)

## Strategy Abstract
The detection strategy focuses on monitoring changes to code signing policies through various data sources such as system logs and security event managers. Patterns of unauthorized policy modification are analyzed by detecting alterations in registry keys related to digital signature verification or the presence of unauthorized scripts adjusting these settings. The strategy leverages SIEM systems for real-time analysis and alerting based on predefined rules that flag suspicious changes.

## Technical Context
Adversaries may execute code signing policy modifications to allow unsigned or maliciously signed binaries to run without triggering security alerts. On Windows, this often involves altering registry keys like `HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot\Certificates`, whereas on macOS, it could involve tampering with the `/Library/ConfigurationProfiles` and certificate trust settings.

**Adversary Emulation Details:**
- **Windows:** Using PowerShell commands to modify registry keys:
  ```powershell
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot\Certificates" -Name "Certificate Name" -Value $false
  ```
- **macOS:** Modifying trust settings with `trust` command:
  ```bash
  sudo trust set-default-trust-settings --root
  ```

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection may not cover custom implementations of code signing policies.
  - Sophisticated attackers might leverage legitimate administrative tools to bypass monitoring.

- **Assumptions:**
  - The environment has robust logging enabled for registry changes and security policy modifications.
  - SIEM systems are configured with rules tailored to recognize suspicious alterations in these settings.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate IT personnel performing authorized updates or maintenance on code signing policies.
- Software installations or updates that automatically modify registry keys related to digital signatures.

## Priority
**Severity:** High

**Justification:**
Code signing policy modification is a critical threat as it can enable the execution of malicious software without detection, compromising system integrity and confidentiality. The potential impact includes unauthorized access, data exfiltration, and further propagation of malware within an organization's network.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

### Windows:
1. Open PowerShell as Administrator.
2. Execute the command to modify registry keys related to code signing policies:
   ```powershell
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot\Certificates" -Name "Certificate Name" -Value $false
   ```
3. Verify changes through `regedit` by navigating to the specified key and confirming the modification.

### macOS:
1. Open Terminal.
2. Execute a command to modify trust settings:
   ```bash
   sudo trust set-default-trust-settings --root
   ```
3. Confirm modifications via System Preferences > Security & Privacy > General tab, checking for altered certificate trust settings.

## Response
When an alert is triggered indicating potential code signing policy modification:
- Immediately isolate the affected systems from the network to prevent further compromise.
- Conduct a forensic analysis to determine the scope and method of alteration.
- Restore policies to their original state using backups or known good configurations.
- Investigate any associated activities on the system, such as unusual processes or network connections.
- Review and update access controls to prevent future unauthorized changes.

## Additional Resources
Additional references and context are not available for this particular detection strategy. However, organizations can refer to general best practices for securing code signing policies and monitoring registry modifications as part of their security posture.

---

This report outlines a comprehensive approach to detecting and responding to code signing policy modifications under the ADS framework, with specific attention to mitigating potential threats posed by such adversarial techniques.