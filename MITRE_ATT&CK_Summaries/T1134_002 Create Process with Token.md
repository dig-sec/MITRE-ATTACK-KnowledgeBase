# Palantir's Alerting & Detection Strategy (ADS) Framework: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## **Goal**
The aim of this technique is to detect adversarial attempts that use containers as a method to bypass security monitoring mechanisms on Windows platforms.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1134.002 - Create Process with Token
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1134/002)

## **Strategy Abstract**
The detection strategy focuses on identifying unusual activities related to container usage that could indicate an attempt at evasion or privilege escalation. Data sources include process creation logs, network traffic analysis, and container orchestration platform logs. Patterns analyzed involve the creation of processes with elevated privileges using tokens manipulated within containers.

## **Technical Context**
Adversaries might use Windows containers to execute malicious code while evading detection by security tools that are less effective inside containerized environments. They may leverage token manipulation techniques like WinPwn's "Get SYSTEM shell" to gain higher privileges from a lower-privileged container. This method involves using the `win32process` module in PowerShell to create processes with elevated tokens.

### **Adversary Emulation Details**
1. **Access Token Manipulation:** Using tools such as WinPwn to escalate privileges within a container environment.
2. **WinPwn - Get SYSTEM shell:** Executing commands that allow adversaries to gain higher-level access by manipulating process tokens.

## **Blind Spots and Assumptions**
- Detection may not cover all variations of token manipulation techniques.
- Assumes comprehensive logging is enabled across containers and host systems.
- Relies on accurate correlation between container logs and host system activity.

## **False Positives**
Potential false positives include:
- Legitimate administrative tasks using elevated privileges within a containerized environment.
- Automated deployment scripts that temporarily escalate privileges for configuration purposes.

## **Priority**
**High:** This technique is prioritized due to the significant risk posed by successful privilege escalation and evasion tactics, which can lead to extensive network compromise and data exfiltration.

## **Validation (Adversary Emulation)**
To emulate this technique in a test environment:

1. **Set up Windows Containers:**
   - Install necessary containerization software on a Windows host.
   - Create a basic container with limited user privileges.

2. **Access Token Manipulation:**
   - Within the container, install WinPwn.
   - Execute the `Get SYSTEM shell` command to escalate privileges:
     ```powershell
     Import-Module .\win32process
     $token = [System.Diagnostics.Process]::GetCurrentProcess().Token
     $identity = New-Object System.Security.Principal.WindowsIdentity($token)
     $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
     if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
         Write-Host "Elevated privileges acquired."
     } else {
         # Execute token manipulation to gain SYSTEM privileges
         Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Get-SystemShell`""
     }
     ```

3. **Monitor and Validate:**
   - Observe process creation logs for anomalies indicating privilege escalation.
   - Verify the system's response to detect if the alert is triggered.

## **Response**
When an alert fires:
1. Isolate the affected container environment to prevent further unauthorized access.
2. Conduct a thorough investigation of the processes and network activity related to the incident.
3. Review logs for any additional indicators of compromise or lateral movement attempts.
4. Update security policies and monitoring tools based on findings to enhance detection capabilities.

## **Additional Resources**
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious PowerShell Download and Execute Pattern
- Malicious PowerShell Commandlets - ProcessCreation
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets

This report provides a comprehensive view of the ADS framework for detecting adversarial container-based activities, ensuring robust security posture against advanced evasion techniques.