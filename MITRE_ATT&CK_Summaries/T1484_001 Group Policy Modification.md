# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Group Policy Modification (T1484.001)

## Goal
The aim of this technique is to detect adversarial attempts to bypass security monitoring through the modification of Windows Group Policies. Specifically, it focuses on adversaries altering registry settings that control audit policies and other critical configurations to evade detection.

## Categorization

- **MITRE ATT&CK Mapping:** T1484.001 - Group Policy Modification
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1484/001)

## Strategy Abstract

This detection strategy leverages security event logs and registry monitoring to identify unauthorized changes to Group Policies. By analyzing patterns such as unexpected modifications in audit policy settings, the strategy detects potential evasion attempts by adversaries. Key data sources include:

- Windows Security Event Logs
- Registry Audit Logs

Patterns analyzed include:
- Changes to `AuditPol` settings
- Modifications to specific Group Policy Object (GPO) registry keys (`HKLM\Software\Policies`)

## Technical Context

Adversaries often execute this technique by modifying the system's audit policies via command-line tools or PowerShell scripts, which allows them to suppress logging of critical activities. This modification can occur through direct manipulation of registry entries responsible for controlling group policy settings and auditing configurations.

### Adversary Emulation Details
- **Sample Commands:**
  - `auditpol /set /category:"Policy Change" /success:enable /failure:enable`
  - PowerShell: 
    ```powershell
    Set-GPRegistryValue -Name "ExampleGPO" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -Type DWord -Value 2048
    ```

## Blind Spots and Assumptions

- **Blind Spots:**
  - Adversaries may use alternative methods (e.g., direct file system manipulation) to achieve similar outcomes.
  - Detection might miss modifications made by advanced persistent threats with extensive knowledge of the environment.

- **Assumptions:**
  - Assumes that audit policies are configured and enforced prior to any adversarial activity.
  - Relies on comprehensive logging being enabled in the environment.

## False Positives

Potential benign activities that may trigger false alerts include:
- Authorized IT personnel performing routine maintenance or updates.
- Legitimate software installations requiring policy modifications for compatibility.
- Misconfigured scripts running under administrative privileges unintentionally altering policies.

## Priority
**Severity: High**

Justification: Modifying audit policies can significantly hinder the ability to detect and respond to further malicious activities. This tactic directly impacts an organization's defense posture by reducing visibility into unauthorized actions on critical systems.

## Validation (Adversary Emulation)

### LockBit Black - Modify Group Policy Settings

#### Command Line:
1. Open a command prompt with administrative privileges.
2. Execute the following command to modify audit settings:
   ```shell
   auditpol /set /category:"Policy Change" /success:enable /failure:enable
   ```

#### PowerShell:
1. Open PowerShell as an administrator.
2. Run the following script to change GPO registry values:
   ```powershell
   Set-GPRegistryValue -Name "ExampleGPO" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -Type DWord -Value 2048
   ```

## Response

Upon detection of an alert related to unauthorized Group Policy modifications:

1. **Immediate Actions:**
   - Isolate affected systems from the network.
   - Review recent changes in security event logs and registry audit logs for additional indicators.

2. **Investigation:**
   - Identify the source and method of modification (e.g., user account, script).
   - Determine whether other systems are similarly compromised.

3. **Remediation:**
   - Revert unauthorized changes to restore original policy settings.
   - Strengthen access controls for Group Policy Management Console (GPMC).

4. **Follow-up:**
   - Conduct a thorough review of security policies and audit configurations.
   - Update incident response plans to include detection and remediation procedures for similar threats.

## Additional Resources

- None available

By following this strategy, organizations can enhance their ability to detect and respond to attempts by adversaries to modify Group Policies for evading security monitoring.