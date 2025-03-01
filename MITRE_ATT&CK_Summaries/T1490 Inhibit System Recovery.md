# Alerting & Detection Strategy (ADS) Report: Inhibit System Recovery (T1490)

## Goal
The goal of this detection strategy is to identify and prevent adversarial attempts to bypass security monitoring by inhibiting system recovery processes across various platforms, specifically focusing on the deletion or manipulation of Volume Shadow Copies on Windows systems.

## Categorization

- **MITRE ATT&CK Mapping:** T1490 - Inhibit System Recovery
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Windows, macOS, Linux
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1490)

## Strategy Abstract

The detection strategy aims to monitor and detect activities related to the inhibition of system recovery mechanisms. It leverages data sources such as process monitoring logs, WMI (Windows Management Instrumentation) events, file system changes, and registry modifications. The patterns analyzed include:

- Deletion or modification of Volume Shadow Copies
- Changes to system restore settings and backup configurations
- Modifications to service permissions impacting system recovery tools

By correlating these data sources and identifying suspicious activities, the strategy seeks to alert security teams to potential attempts at inhibiting system recovery.

## Technical Context

Adversaries often target system recovery mechanisms to hinder forensic analysis and prevent the restoration of compromised systems. Techniques include:

- **Deleting Volume Shadow Copies:** Using commands like `vssadmin delete shadows` or through WMI scripting.
- **Disabling System Restore:** Modifying registry keys related to system protection.
- **Modifying VSS Service Permissions:** Altering permissions to disable Volume Shadow Copy Service.

These actions are typically executed using administrative privileges and may involve the use of built-in utilities like `wbadmin`, PowerShell scripts, or direct registry modifications.

## Blind Spots and Assumptions

- Assumes that security monitoring tools have full visibility into WMI events and file system changes.
- May not detect indirect methods of inhibiting recovery, such as those involving third-party backup solutions.
- Relies on the assumption that Volume Shadow Copies are a primary method of recovery for monitored systems.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate administrative tasks to manage disk space by deleting old backups or shadow copies.
- Scheduled maintenance scripts designed to modify system settings without malicious intent.
- Software updates or patches that may alter backup configurations as part of their deployment process.

## Priority

**Priority:** High

**Justification:** Inhibiting system recovery can significantly impact an organization's ability to respond to and recover from security incidents. Early detection is crucial to maintaining the integrity of forensic investigations and ensuring business continuity.

## Validation (Adversary Emulation)

To validate this detection strategy, follow these steps in a controlled test environment:

1. **Windows - Delete Volume Shadow Copies**
   - Command: `vssadmin delete shadows /all`

2. **Windows - Delete Volume Shadow Copies via WMI**
   - Script: Use PowerShell to execute WMI commands that target shadow copies.

3. **Windows - wbadmin Delete Windows Backup Catalog**
   - Command: `wbadmin delete catalog /quiet`

4. **Windows - Disable Windows Recovery Console Repair**
   - Modify registry keys related to the recovery console settings.

5. **Windows - Delete Volume Shadow Copies via WMI with PowerShell**
   - Script: Execute a PowerShell script that leverages WMI for shadow copy deletion.

6. **Windows - Delete Backup Files**
   - Command: `del /f /q C:\Backup\*.*`

7. **Windows - wbadmin Delete systemstatebackup**
   - Command: `wbadmin delete systemstatebackup only`

8. **Windows - Disable the SR scheduled task**
   - Use Task Scheduler to disable tasks related to System Restore.

9. **Disable System Restore Through Registry**
   - Modify registry keys under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SystemRestore`.

10. **Windows - vssadmin Resize Shadowstorage Volume**
    - Command: `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=1GB`

11. **Modify VSS Service Permissions**
    - Adjust permissions using the Services console to disable the Volume Shadow Copy service.

12. **Disable Time Machine (macOS)**
    - Use command: `sudo tmutil disable`

## Response

When an alert for inhibiting system recovery is triggered, analysts should:

1. Immediately isolate affected systems to prevent further changes.
2. Conduct a thorough investigation using available logs and monitoring tools to determine the scope of the activity.
3. Restore any deleted or altered recovery components from known good backups.
4. Review recent administrative activities to identify potential unauthorized access or misuse.
5. Update security policies and controls to mitigate similar attempts in the future.

## Additional Resources

- [Allow Service Access Using Security Descriptor Tampering Via Sc.EXE](https://attack.mitre.org/techniques/T1547)
- [Service Security Descriptor Tampering Via Sc.EXE](https://attack.mitre.org/techniques/T1547)
- [Deny Service Access Using Security Descriptor Tampering Via Sc.EXE](https://attack.mitre.org/techniques/T1547)
- [Shadow Copies Deletion Using Operating Systems Utilities](https://attack.mitre.org/techniques/T1490)
- [Disable Important Scheduled Task](https://attack.mitre.org/techniques/T1073)
- [File Deletion Via Del](https://attack.mitre.org/techniques/T1081)
- [Boot Configuration Tampering Via Bcdedit.EXE](https://attack.mitre.org/techniques/T1546)

This report provides a comprehensive framework for detecting and responding to attempts at inhibiting system recovery, ensuring robust security monitoring and incident response capabilities.