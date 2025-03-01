# Alerting & Detection Strategy (ADS) Report: Network Share Connection Removal

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring and persistence mechanisms by removing network share connections. Specifically, it focuses on identifying instances where attackers remove shared network drives that may be used for exfiltration or as a persistence vector.

## Categorization
- **MITRE ATT&CK Mapping:** T1070.005 - Network Share Connection Removal
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/005)

## Strategy Abstract
The detection strategy involves monitoring and analyzing events related to network share connections on Windows systems. Key data sources include:
- **Security Event Logs**: For auditing actions such as adding or removing network shares.
- **PowerShell Activity Logs**: To detect commands that manipulate network connections.

Patterns analyzed include unauthorized removal of network shares, especially those with administrative privileges, which can indicate an effort to evade detection by disabling access points for monitoring tools.

## Technical Context
Adversaries execute this technique to disrupt security controls and monitoring. Commonly used methods involve:
- **Net Use Command**: To remove shares using CLI.
- **PowerShell Cmdlets**: Such as `Remove-PSDrive`, targeting mapped network drives.

**Example Commands:**
```shell
net use Z: /delete
```

Adversaries might also disable automatic administrative share creation at startup to prevent automated monitoring systems from detecting these shares.

## Blind Spots and Assumptions
### Known Limitations:
- Detection may not cover all methods, particularly if custom scripts or tools are used.
- Legitimate administrators' actions can be indistinguishable from malicious activities without context.

### Assumptions:
- The system logs necessary events with sufficient detail to identify share removal attempts.
- Monitoring systems have visibility over both standard command-line and PowerShell activities.

## False Positives
Potential benign activities that might trigger false alerts include:
- Regular administrative tasks involving legitimate modification of network shares.
- Automated maintenance scripts designed to manage network resources efficiently.

## Priority
**Priority: High**

Justification:
The ability for an adversary to remove network shares can significantly hinder security monitoring and response capabilities, enabling further malicious actions without detection. The potential impact on critical systems and data integrity necessitates a high priority in detecting this behavior.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Add Network Share**
   - Use `net use` to map a network drive.
     ```shell
     net use Z: \\server\share
     ```

2. **Remove Network Share**
   - Remove the mapped drive using `net use`.
     ```shell
     net use Z: /delete
     ```

3. **Remove Network Share PowerShell**
   - Utilize PowerShell to unmap network drives.
     ```powershell
     Remove-PSDrive -Name Z
     ```

4. **Disable Administrative Share Creation at Startup**
   - Modify registry settings or group policies to prevent automatic creation of administrative shares.

5. **Remove Administrative Shares**
   - Manually remove existing administrative shares using `net share` command.
     ```shell
     net share ADMIN$ /delete
     ```

## Response
When an alert for network share removal fires, analysts should:
- Verify the context and source of the activity to differentiate between malicious intent and legitimate actions.
- Investigate associated activities or accounts to identify potential compromise.
- Re-establish necessary shares and ensure monitoring systems have access to critical data paths.

## Additional Resources
Additional references and context on related techniques:
- **Windows Share Mount Via Net.EXE**
- **Unmount Share Via Net.EXE**
- **Net.EXE Execution**

Understanding these commands and their use in both legitimate operations and adversarial tactics is essential for effective detection and response.