# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Use of Security Support Provider on Windows

## Goal
The aim of this technique is to detect adversarial attempts to modify and exploit the Security Support Provider (SSP) mechanisms in Windows systems, which can be used to bypass security monitoring and escalate privileges.

## Categorization
- **MITRE ATT&CK Mapping:** T1547.005 - Security Support Provider
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

For more information on this technique: [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/005)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing changes to the Security Support Provider configurations in the Windows registry. Key data sources include:
- **Windows Event Logs:** To capture any alterations to security-sensitive registry keys.
- **Sysmon Events:** Specifically, events that log modifications to the HKLM\SYSTEM\CurrentControlSet\Control\Lsa registry subtree.
- **File Integrity Monitoring (FIM):** To detect unauthorized changes in executable files associated with SSP.

The strategy involves identifying patterns such as:
- Unusual or unauthorized modifications to registry keys related to LSA and OSConfig Security Support Providers.
- Anomalies in the usage of `secedit` commands, which might be indicative of SSP configuration tampering.

## Technical Context
Adversaries exploit this technique by modifying specific registry settings that dictate how Windows handles security tokens. By altering these configurations, they can potentially bypass security measures like User Account Control (UAC) and achieve persistence or escalate privileges without detection.

### Adversary Emulation Details:
- **Sample Command:** `secedit /configure /db secedit.sdb /cfg SSP.xml`
  - This command allows the application of configuration changes to the Security Support Provider by modifying a registry through a configuration file.
  
- **Test Scenario:** An adversary can gain administrative access and use PowerShell or command-line tools to modify the following:
  - `HKLM:\System\CurrentControlSet\Control\Lsa\Security`
  - `HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig`

## Blind Spots and Assumptions
- **Blind Spots:** The strategy assumes that all relevant registry changes are logged and accessible. However, sophisticated adversaries might use techniques to suppress or delay log generation.
  
- **Assumptions:** It is assumed that Sysmon is properly configured on the target systems to capture necessary events. Additionally, it presumes a baseline of normal behavior has been established for accurate anomaly detection.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative changes made by IT personnel using `secedit` or similar tools.
- Scheduled tasks or scripts that modify registry settings as part of regular maintenance operations.

## Priority
**Priority: High**

Justification: The technique allows adversaries to bypass security mechanisms and achieve persistence, making it a critical vector for privilege escalation. Early detection is essential to prevent further compromise within the environment.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Prerequisites:** Ensure you have administrative access to the test machine.
2. Modify the registry:
   - Open Registry Editor (`regedit`).
   - Navigate to `HKLM:\System\CurrentControlSet\Control\Lsa`.
   - Change relevant settings, such as enabling or disabling specific security providers.
3. **Modify OSConfig SSP:**
   - Navigate to `HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig`.
   - Make similar modifications as above.
4. Use the following command to apply changes:
   ```shell
   secedit /configure /db secedit.sdb /cfg SSP.xml
   ```
5. Verify changes through event logs and Sysmon output.

## Response
When an alert for this technique fires, analysts should:

1. **Verify Alert Validity:** Check if the registry modifications are legitimate or part of scheduled maintenance.
2. **Assess Impact:** Determine if any security mechanisms have been bypassed or compromised.
3. **Containment:** Isolate affected systems to prevent lateral movement by adversaries.
4. **Remediation:** Revert unauthorized changes and restore default configurations.
5. **Investigation:** Conduct a thorough investigation to determine the extent of the compromise and identify potential indicators of compromise (IOCs).
6. **Reporting:** Document findings and update security policies to prevent future occurrences.

## Additional Resources
Additional references and context are currently not available, but further research into related ATT&CK techniques may provide deeper insights into detection and response strategies.

---

This report outlines a comprehensive approach to detecting and responding to adversarial exploitation of Security Support Providers on Windows systems. By focusing on registry changes and leveraging existing monitoring tools, organizations can enhance their ability to detect and mitigate such threats effectively.