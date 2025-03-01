# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## **Goal**
This strategy aims to detect adversarial attempts to bypass security monitoring using containers across various platforms such as Windows, macOS, Linux, IaaS environments, and containerized workloads. The focus is on identifying methods used by adversaries to disable or modify security tools, thereby evading detection.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1562.001 - Disable or Modify Tools
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, macOS, Linux, Containers, IaaS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/001)

## **Strategy Abstract**
The detection strategy involves monitoring and analyzing data from a variety of sources such as endpoint logs, network traffic, container runtime events, system configuration changes, and security tool status. Patterns indicative of attempts to disable or modify security tools are identified through:

- Monitoring for specific commands and scripts that alter the state of security software.
- Detecting unexpected service stoppages or configurations changes that indicate tampering with security solutions like antivirus programs or endpoint detection and response (EDR) agents.
- Observing container runtime activity that correlates with known evasion techniques, such as disabling logging.

## **Technical Context**
Adversaries often seek to bypass security monitoring by leveraging weaknesses in system configurations or exploiting vulnerabilities. They may use scripts or command-line tools to stop critical security services, modify registry keys, or disable security features at runtime. Common methods include:

- Using PowerShell, Bash, or batch scripts to execute commands that change service settings.
- Modifying the operating system's configuration files to prevent security tools from starting on boot.

**Example Commands:**
- Disabling a Windows service via PowerShell:
  ```powershell
  Stop-Service -Name "WindowsDefender"
  Set-Service -Name "WindowsDefender" -StartupType Disabled
  ```

- Unloading Sysmon Driver in Linux:
  ```bash
  rmmod sysmon_module_name
  ```

## **Blind Spots and Assumptions**
- Assumes continuous monitoring of system configurations and security tool statuses.
- Blind spots may exist if adversaries use zero-day vulnerabilities that are not yet recognized by detection systems.
- The strategy assumes no unauthorized changes to the baseline configurations that could mask or mimic legitimate administrative actions.

## **False Positives**
Potential benign activities include:

- Legitimate IT maintenance tasks where security tools are temporarily disabled for updates or configuration changes.
- Software installations that may inadvertently alter service settings or registry keys without malicious intent.
- Automated scripts run by system administrators to optimize performance or apply patches, which might unintentionally impact security tool configurations.

## **Priority**
**High**: Given the critical nature of maintaining operational security and the potential for significant damage if adversaries successfully bypass monitoring systems, this strategy is prioritized highly. The ability to detect such attempts early can prevent data breaches and unauthorized access.

## **Validation (Adversary Emulation)**
To validate detection strategies in a controlled environment:

1. **Disable Syslog** on Linux:
   ```bash
   service syslog stop
   update-rc.d -f rsyslog remove
   ```

2. **Stop Crowdstrike Falcon** on Linux and macOS:
   - On Linux, use the provided utility to stop the service.
   - On macOS, unload using:
     ```bash
     sudo launchctl unload /Library/LaunchDaemons/com.crowdstrike.FalconSensor.plist
     ```

3. **Uninstall Sysmon** from Windows:
   ```powershell
   msiexec.exe /qn /x {sysmon_package_guid}
   ```

4. **Disable LittleSnitch** on macOS:
   - Open LittleSnitch configuration and disable monitoring.

5. **Tamper with Defender Registry** using Regedit or PowerShell:
   - Modify registry paths associated with Windows Defender to simulate disabling features.

6. **Reboot Linux Host via Kernel System Request**:
   ```bash
   echo 1 > /proc/sysrq-trigger
   ```

7. **Disable Memory Swap** on Linux:
   ```bash
   sysctl vm.swappiness=0
   ```

8. **AWS - GuardDuty Suspension or Deletion**:
   - Use AWS CLI to disable or delete GuardDuty detectors.

## **Response**
Upon detection of an attempt to bypass security monitoring:

1. Immediately isolate the affected systems from the network to prevent further spread.
2. Conduct a thorough forensic analysis to determine the scope and method of the breach.
3. Reinstate any disabled security tools and ensure they are configured correctly.
4. Notify relevant stakeholders, including IT security teams and management.
5. Review and update detection policies to address any gaps identified during the incident.

## **Additional Resources**
- [Disable Or Stop Services](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/service)
- [Disabling Security Tools](https://www.securityintelligence.com/disabling-security-tools/)
- [Container Security Monitoring](https://www.datadoghq.com/blog/container-security-monitoring/)

By following this comprehensive strategy, organizations can enhance their ability to detect and respond to adversarial attempts at bypassing security monitoring systems using containers.