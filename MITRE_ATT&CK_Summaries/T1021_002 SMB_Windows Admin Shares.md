# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Use of SMB/Windows Admin Shares for Lateral Movement

## Goal
The aim of this technique is to detect adversarial attempts to bypass security monitoring using Windows Server Message Block (SMB) shares, specifically targeting administrative shares for lateral movement within a network.

## Categorization
- **MITRE ATT&CK Mapping:** T1021.002 - SMB/Windows Admin Shares
- **Tactic / Kill Chain Phases:** Lateral Movement
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1021/002)

## Strategy Abstract
This detection strategy leverages log data from Windows Event Logs and network traffic monitoring to identify unauthorized access or unusual activity on administrative shares. The primary focus is on detecting patterns such as unexpected remote connections, file transfers, or command execution attempts via SMB shares.

Key data sources include:
- **Event Viewer Logs**: Specifically, events related to network share access (e.g., logon events, file operations).
- **Network Traffic Monitoring**: Analyzing SMB protocol traffic for anomalous behavior.

Patterns analyzed involve:
- Unusual login times or from unexpected IP addresses.
- Large volume of file transfers or command execution attempts on administrative shares.
- Access to shares typically reserved for internal use only.

## Technical Context
Adversaries often exploit SMB/Windows Admin Shares by mapping these shares and executing commands or transferring files to move laterally across the network. Common methods include:
- Using tools like **PsExec** to execute commands remotely through mapped shares.
- Leveraging legitimate administrative accounts to gain access.

Real-world execution might involve adversaries using PowerShell scripts to map admin shares, followed by command execution using tools like PsExec to exploit privileges and bypass security controls.

## Blind Spots and Assumptions
- Assumes that all network traffic can be monitored and logged comprehensively.
- May not detect highly stealthy methods where adversaries disguise their activities as benign operations.
- Relies on the assumption that administrative shares are consistently configured with default settings, which may not always be true.

## False Positives
Potential false positives could arise from:
- Legitimate IT maintenance or management tasks involving remote access to admin shares.
- Scheduled scripts that perform regular backups or updates through these shares.

## Priority
**High**: The use of administrative shares for lateral movement poses a significant risk due to the elevated privileges typically associated with these accounts, making them attractive targets for attackers aiming to compromise multiple systems within an environment.

## Validation (Adversary Emulation)
To validate this detection strategy in a controlled test environment, follow these steps:

1. **Map Admin Share**:
   - Use `net use` command: 
     ```shell
     net use \\target-machine\C$ /USER:domain\username password
     ```

2. **Map Admin Share PowerShell**:
   - Execute the following in PowerShell:
     ```powershell
     New-PSDrive -Name Z -PSProvider FileSystem -Root "\\target-machine\C$" -Credential (Get-Credential)
     ```

3. **Copy and Execute File with PsExec**:
   - Download `PsExec` from a trusted source.
   - Use the following command to execute a file on the target machine:
     ```shell
     psexec \\target-machine -u domain\username -p password cmd.exe
     ```

4. **Execute Command Writing Output to Local Admin Share**:
   - After mapping, run a command and redirect output:
     ```shell
     dir C:\ > \\target-machine\C$\output.txt
     ```

## Response
When an alert indicating suspicious activity on SMB admin shares is triggered, analysts should:

1. Verify the legitimacy of the source IP address and user account involved in the connection.
2. Check for any recent changes to administrative share configurations that might have expanded access.
3. Review network traffic logs for patterns indicative of lateral movement or data exfiltration.
4. Isolate affected systems if necessary, and conduct a thorough forensic analysis.

## Additional Resources
For further context and information:
- **Suspicious Redirection to Local Admin Share**: Investigate scenarios where outputs are redirected to admin shares without clear authorization.
- **HackTool - CrackMapExec Execution Patterns**: Understanding tools like CrackMapExec can provide insights into potential attack vectors.
- **Psexec Execution**: Familiarity with Psexec usage patterns can aid in recognizing malicious activities.
- **Potential Execution of Sysinternals Tools**: Analyze the use of Sysinternals tools that may be leveraged for privilege escalation or lateral movement. 

This ADS framework provides a comprehensive approach to detecting and responding to adversarial use of Windows administrative shares, focusing on both technical detection mechanisms and strategic response guidelines.