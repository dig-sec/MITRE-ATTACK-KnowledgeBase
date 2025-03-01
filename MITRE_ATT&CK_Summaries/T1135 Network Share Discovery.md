# Palantir Alerting & Detection Strategy (ADS) Report

## Goal
The aim of this technique is to detect adversarial attempts at discovering network shares across various platforms including macOS, Windows, and Linux. Network share discovery can be a precursor to lateral movement within networks, as it allows attackers to identify accessible resources.

## Categorization
- **MITRE ATT&CK Mapping:** T1135 - Network Share Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** macOS, Windows, Linux

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1135)

## Strategy Abstract
The detection strategy focuses on identifying patterns of network share discovery attempts across different operating systems. Data sources include system logs (e.g., Windows Event Logs), network traffic captures, and command-line monitoring outputs. Patterns analyzed include unusual usage of commands like `net view`, PowerShell scripts involving `Get-NetShare`, or other OS-specific commands indicative of enumeration activities.

## Technical Context
Adversaries often execute network share discovery to understand the layout and accessible shares within a target environment. They may use native system tools, third-party utilities, or custom scripts to perform these actions. For example:

- **Windows:** Adversaries might utilize `net view` or PowerShell with `Get-NetShare`.
- **Linux/FreeBSD:** Commands like `smbclient`, `nmblookup`, or direct SMB enumeration via shell scripts are common.
- **macOS:** Although less frequent, adversaries may use tools like `smbutil`.

### Adversary Emulation Details
1. **Windows Command Prompt:**
   ```bash
   net view \\target_machine_name
   ```

2. **PowerShell Commands:**
   ```powershell
   Get-NetShare -ComputerName target_machine_name
   ```

3. **Linux/FreeBSD Shell Script Example:**
   ```bash
   smbclient -L target_machine_name -U%
   ```

## Blind Spots and Assumptions
- Detection might miss techniques utilizing encrypted or obfuscated command executions.
- The strategy assumes that all relevant data sources are being monitored effectively, which may not always be the case in distributed environments.
- Some network discovery attempts can blend into regular administrative activities.

## False Positives
- Legitimate IT administrators conducting network audits or resource management tasks.
- Scheduled scripts running maintenance checks on shared resources.
- Users accessing and viewing shared directories as part of their normal duties.

## Priority
**Severity: Medium**

Justification: While network share discovery is a crucial phase for adversaries to progress in lateral movement, it can also be an expected part of legitimate network administration. The impact depends heavily on the subsequent actions taken by the adversary after discovering shares.

## Validation (Adversary Emulation)
To emulate and validate detection:

1. **Network Share Discovery**
   - Execute `net view` from command prompt on Windows to list available shares.
2. **Linux Network Share Discovery:**
   - Use `smbclient -L target_machine_name -U%` to enumerate shares.
3. **FreeBSD Specific Tools:**
   - Utilize `nmblookup -S` to check for active SMB servers.
4. **Command Prompt on Windows:**
   - `net view \\target_machine_name`
5. **PowerShell Execution:**
   - Execute PowerShell command `Get-NetShare -ComputerName target_machine_name`.
6. **View Available Shares:**
   - Use GUI or scripts to list accessible shares for verification.
7. **PowerView Script:**
   - Execute PowerView's `Invoke-SmbMap` to map out SMB sessions and shares.
8. **WinPwn Share Enumeration:**
   - Utilize WinPwn’s share enumeration feature to identify network shares.
9. **Directory Listing with `dir`:**
   - Use `dir \\target_machine_name\sharename` on command line to list directory contents.
10. **SharpShares Utility:**
    - Run SharpShares for comprehensive SMB share enumeration in Windows environments.
11. **Snaffler Usage:**
    - Deploy Snaffler for advanced enumeration of network shares.

## Response
Upon detection:

- Verify the legitimacy of the activity by cross-referencing with known administrative schedules or tasks.
- Monitor any subsequent activities that could indicate lateral movement attempts.
- Isolate and investigate systems where unauthorized share discovery was detected.
- Implement additional logging around sensitive shares to capture further details on access patterns.

## Additional Resources
- **Malicious PowerShell Commandlets - ProcessCreation:** Track suspicious processes initiated via PowerShell.
- **Suspicious Program Names:** Monitor for unusual or unexpected program execution names.
- **Import New Module Via PowerShell CommandLine:** Observe PowerShell sessions importing unauthorized modules.
- **Net.EXE Execution:** Detect abnormal uses of `net.exe` which might indicate share enumeration.
- **Windows Share Mount Via Net.EXE:** Validate instances where Windows shares are being mounted in an unusual manner.

By adhering to this strategy, organizations can better detect and respond to network share discovery attempts by adversaries, maintaining a robust defense posture.