# Alerting & Detection Strategy Report: Active Setup for Privilege Escalation on Windows

## Goal
This detection strategy aims to identify adversarial attempts to establish persistence and escalate privileges using Windows Active Setup techniques. The focus is on detecting manipulations within the Windows registry that adversaries use to execute malicious code during user logon or system startup.

## Categorization
- **MITRE ATT&CK Mapping:** T1547.014 - Active Setup
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

For more information on this technique, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/014).

## Strategy Abstract
The detection strategy leverages monitoring of registry keys and values associated with Active Setup. By analyzing changes to specific registry paths, particularly those involving `Setup` and `StubPath`, we can identify potential malicious activities aimed at achieving persistence or privilege escalation.

### Data Sources:
- Windows Event Logs
- Registry Monitoring Tools

### Patterns Analyzed:
- Creation of new `atomic_test` keys in `HKLM\Software\Microsoft\Active Setup\Installed Components`
- Modification of existing `Setup` and `StubPath` values
- Execution of unusual or unexpected payloads within the Active Setup entries

## Technical Context
Active Setup is a Windows feature that allows administrators to execute scripts during user logon, enabling customization and configuration tasks. Adversaries exploit this by injecting malicious commands into these registry paths.

### Adversary Execution:
Adversaries typically inject malicious code into the `StubPath` value or create new entries with deceptive names, such as those mimicking legitimate software installations. This can lead to the execution of malware during user logon, establishing persistence and potentially escalating privileges.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may not cover all variations of Active Setup manipulation.
  - Techniques that do not modify registry keys but use other persistence methods (e.g., scheduled tasks) are outside this strategy's scope.

- **Assumptions:**
  - The environment has comprehensive monitoring capabilities for registry changes.
  - Analysts have baseline knowledge of typical user and system activities to differentiate between benign and malicious actions.

## False Positives
Potential false positives include:
- Legitimate software installations or updates that modify Active Setup entries.
- System maintenance scripts configured by IT administrators.
- User-initiated actions that inadvertently change relevant registry keys.

## Priority
**High**: Given the potential for significant impact, including unauthorized access and data exfiltration, detecting misuse of Active Setup is critical. This technique can be used to establish persistence and escalate privileges, posing a severe threat if left unchecked.

## Validation (Adversary Emulation)
To validate this detection strategy, follow these steps in a controlled test environment:

1. **HKLM - Add atomic_test key**:
   - Create a new registry entry under `HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components`.
   - Name the key `atomic_test` and set appropriate values to simulate user setup execution.

2. **HKLM - Add malicious StubPath value**:
   - Identify an existing Active Setup entry.
   - Modify its `StubPath` value to point to a test executable that mimics malicious behavior.

3. **Re-execute payload by version manipulation**:
   - Decrease the version number of a legitimate entry, such as 'Internet Explorer Core Fonts', to trigger re-execution of its associated `StubPath`.

These steps should be performed in a secure and isolated environment to prevent unintended consequences.

## Response
When an alert related to Active Setup manipulation is triggered, analysts should:

1. **Verify the Alert**: Cross-reference with other data sources (e.g., network traffic, process monitoring) to confirm suspicious activity.
2. **Containment**: Isolate affected systems to prevent further spread or execution of malicious code.
3. **Investigation**: Determine the scope and origin of the manipulation. Identify any related indicators of compromise (IOCs).
4. **Remediation**: Remove malicious registry entries and restore legitimate configurations.
5. **Documentation**: Record findings, actions taken, and lessons learned to improve future detection and response efforts.

## Additional Resources
Currently, no additional resources are available for this specific strategy. Analysts are encouraged to refer to general Active Directory monitoring guides and Windows security best practices for further context.