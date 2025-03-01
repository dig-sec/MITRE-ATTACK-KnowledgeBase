# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Mark-of-the-Web Bypass on Windows

## **Goal**

The goal of this technique is to detect adversarial attempts to bypass security monitoring by manipulating the "Mark-of-the-Web" (MOTW) attribute in Windows. Specifically, it targets scenarios where adversaries remove or alter these attributes to evade detection mechanisms that rely on them for marking downloaded files as web content.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1553.005 - Mark-of-the-Web Bypass
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1553/005)

## **Strategy Abstract**

The detection strategy focuses on monitoring changes to the MOTW attribute, specifically the removal of alternate data streams such as `Zone.Identifier`. The key data sources for this detection are file integrity monitoring logs and process creation events. Patterns analyzed include:

- Deletion or alteration of the `Zone.Identifier` stream in files downloaded from the internet.
- Execution patterns where files lacking a valid MOTW attribute are used.

The strategy leverages Windows Event Logs, particularly those related to filesystem changes (Event ID 4663) and process executions (Event IDs 4688 and 4689).

## **Technical Context**

Adversaries exploit the MOTW feature by removing or altering the `Zone.Identifier` alternate data stream from downloaded files. This can allow executables that would normally be blocked or flagged by security systems to run without raising alerts.

### Real-World Execution

1. **Mount ISO Image**: Adversaries may mount an ISO image as a virtual drive.
2. **Remove Zone.Identifier Alternate Data Stream**:
   - Use command line tools such as `powershell` or `attrib`.
     ```shell
     powershell -Command "Remove-ItemProperty -Path 'C:\path\to\file.exe' -Name :Zone.Identifier"
     ```
3. **Execute File**: Run the executable from the ISO image, bypassing certain security checks that rely on MOTW attributes.

### Adversary Emulation

- **Mount an ISO Image**:
  ```shell
  mountvol Z: /s
  ```

- **Remove Zone.Identifier Alternate Data Stream**:
  ```shell
  powershell -Command "Remove-ItemProperty -Path 'Z:\file.exe' -Name :Zone.Identifier"
  ```

- **Execute LNK File from ISO**:
  - Create a shortcut to the executable.
  - Run the shortcut, which executes the file without MOTW.

## **Blind Spots and Assumptions**

- **Blind Spots**: Detection may not cover scenarios where adversaries use sophisticated techniques to reapply MOTW attributes dynamically or employ other evasion tactics.
- **Assumptions**: Assumes that security monitoring systems are configured to log relevant filesystem and process events. It also assumes no tampering with logs by the adversary.

## **False Positives**

Potential benign activities that might trigger false alerts include:

- Legitimate use of administrative tools to remove MOTW attributes for testing or configuration purposes.
- Users downloading files from trusted sources who manually alter file properties without malicious intent.

## **Priority**

**Severity: High**

Justification: The removal of MOTW attributes can allow untrusted executables to bypass security mechanisms, potentially leading to significant breaches. Given the critical role of MOTW in Windows security postures, this technique poses a high risk.

## **Validation (Adversary Emulation)**

1. **Mount ISO Image**:
   - Use `mountvol` or similar tools.
     ```shell
     mountvol Z: /s
     ```

2. **Remove Zone.Identifier Alternate Data Stream**:
   - Execute the following command in PowerShell to remove the MOTW attribute:
     ```shell
     powershell -Command "Remove-ItemProperty -Path 'Z:\file.exe' -Name :Zone.Identifier"
     ```

3. **Execute LNK File from ISO**:
   - Create a shortcut (`file.lnk`) pointing to `file.exe` within the mounted ISO.
   - Double-click the `.lnk` file to execute, simulating the bypass.

## **Response**

When an alert is triggered:

1. **Immediate Isolation**: Disconnect the affected system from the network to prevent further potential spread or data exfiltration.
2. **Investigation**:
   - Verify if the file execution was legitimate or malicious by checking user activity logs and contextual information.
3. **Forensic Analysis**:
   - Analyze the contents of the executable and any associated files for malicious behavior.
4. **Remediation**:
   - Restore MOTW attributes where appropriate and ensure all security systems are updated to detect similar attempts in the future.

## **Additional Resources**

- Further reading on Windows security mechanisms can be found through Microsoft's official documentation.
- Community forums and threat intelligence platforms may provide additional insights into emerging techniques related to this evasion tactic.