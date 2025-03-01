# Alerting & Detection Strategy (ADS) Report: Detecting Adversarial File and Directory Discovery

## Goal
This technique aims to detect adversarial attempts to discover files and directories on a host system as part of their reconnaissance phase. This is critical for identifying potential lateral movement or data exfiltration efforts.

## Categorization
- **MITRE ATT&CK Mapping:** T1083 - File and Directory Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1083)

## Strategy Abstract
The detection strategy focuses on identifying abnormal or unauthorized file and directory discovery activities across multiple platforms. Key data sources include:
- Syslog for Unix/Linux systems.
- Event logs from Windows (Event ID 4656 for directory listing, Event ID 4688 for process creation).
- Process monitoring tools to identify suspicious command executions.

Patterns analyzed involve unexpected usage of commands like `dir`, `ls`, `find`, PowerShell cmdlets (`Get-ChildItem`), and third-party enumeration tools such as DirLister or Nmap scripts. Alerts are generated when these activities occur outside of regular maintenance windows or from unusual locations (e.g., external IP addresses, non-standard user accounts).

## Technical Context
Adversaries use file and directory discovery to map out a network's structure, identify sensitive data stores, and plan further attacks. Common methods include:
- **Windows:** Utilizing `dir`, PowerShell cmdlets (`Get-ChildItem`), or third-party tools (e.g., DirLister).
- **Linux/macOS:** Executing commands like `ls`, `find`, or using tools like `tree`.
- **Cross-platform tools**: Such as Nmap scripts for directory enumeration.

Adversaries often run these commands from compromised accounts with elevated privileges to avoid detection. They might also redirect output to files or network shares, complicating forensic analysis.

## Blind Spots and Assumptions
- Detection relies on the assumption that normal discovery activities are within expected patterns, which may vary by organization.
- Tools designed for legitimate system administration tasks could trigger false positives if not properly whitelisted.
- Command obfuscation techniques can evade detection based on command name alone.

## False Positives
- Legitimate use of file and directory commands during IT maintenance or software installations.
- Automated backup processes that involve directory enumeration.
- Use of discovery tools for legitimate security audits or penetration testing activities.

## Priority
**High**: File and directory discovery is a common precursor to more damaging actions like data exfiltration. Early detection can prevent further compromise and mitigate potential damage.

## Validation (Adversary Emulation)
### File and Directory Discovery (cmd.exe)
1. Execute `dir C:\ > C:\temp\dir_output.txt` on a Windows machine.
2. Monitor Event Logs for directory access events (Event ID 4656).

### File and Directory Discovery (PowerShell)
1. Run `Get-ChildItem -Recurse | Out-File C:\temp\ps_output.txt`.
2. Capture PowerShell process creation logs (Event ID 4688) and file write operations.

### Nix File and Directory Discovery
1. Execute `ls -R / > /tmp/ls_output.txt` on a Unix/Linux system.
2. Check Syslog for entries related to unauthorized access or unusual command usage.

### Nix File and Directory Discovery 2
1. Use `find / -type f > /tmp/find_output.txt`.
2. Monitor for unexpected file discovery operations in Syslog.

### Simulating MAZE Directory Enumeration
1. Execute a known MAZE malware command: `dir /s C:\Users\* > C:\temp\maze_output.txt`.
2. Track for unusual directory access patterns and process behaviors.

### Launch DirLister Executable
1. Run `DirLister.exe` on the target system.
2. Monitor network traffic for unusual outbound connections or data transfers, alongside process execution logs.

### ESXi - Enumerate VMDKs available on an ESXi Host
1. Execute a command to list VM disk files: `ls /vmfs/volumes/*/*.vmdk`.
2. Capture and analyze logs from the ESXi management interface for unauthorized access attempts.

## Response
When alerts are triggered:
- Immediately isolate affected systems to prevent further enumeration or data exfiltration.
- Conduct a thorough investigation of process execution logs and network traffic associated with the discovery activities.
- Verify if any discovered files or directories were accessed or modified following enumeration.
- Update security controls, such as whitelisting legitimate activities and enhancing monitoring for file access patterns.

## Additional Resources
For further context on related techniques:
- [Tunneling Tool Execution](https://attack.mitre.org/techniques/T1132/)
- [Potentially Suspicious CMD Shell Output Redirect](https://attack.mitre.org/software/S0016/)
- [File And SubFolder Enumeration Via Dir Command](https://attack.mitre.org/techniques/T1083/)

These resources provide additional insight into common adversary behaviors and can help refine detection strategies.