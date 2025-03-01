# Palantir's Alerting & Detection Strategy (ADS) Framework: Security Software Discovery

## **Goal**
The aim of this technique is to detect adversarial attempts to discover and potentially bypass security monitoring mechanisms by identifying installed security software on various platforms, including Windows, Linux, macOS, Azure AD, Office 365, SaaS, IaaS, and Google Workspace.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1518.001 - Security Software Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1518/001)

## **Strategy Abstract**
The detection strategy involves monitoring various data sources such as logs from endpoint security software (e.g., Sysmon on Windows, auditd on Linux), command execution events in PowerShell or Unix shells, and management activity within cloud environments. Key patterns analyzed include unusual queries for installed applications, attempts to enumerate security solutions, and processes indicative of reconnaissance activities.

## **Technical Context**
Adversaries often execute this technique to understand the defensive posture they face when compromising a system. By identifying which security tools are active, adversaries can decide whether to disable or evade them. This could involve using built-in commands like `wmic`, PowerShell cmdlets (`Get-CimInstance`, `Get-WmiObject`), or custom scripts that list installed applications and services related to antivirus, firewall, and endpoint detection.

### Adversary Emulation Details
- **Sample Commands:**
  - Windows: `wmic /output:software.txt product get name`
  - PowerShell (Windows): `Get-CimInstance Win32_Product | Select-Object -Property Name`
  - Unix Shell: `ps aux | grep -i 'security'`

### Test Scenarios
1. Execute the above commands on a controlled environment to simulate adversary reconnaissance.
2. Monitor and log system responses, including any alerts triggered by security software.

## **Blind Spots and Assumptions**
- Assumes that all systems are configured to monitor command execution and management queries effectively.
- May not detect sophisticated adversaries who use obfuscated or encoded commands to bypass detection mechanisms.
- Relies on the completeness of logging configurations across platforms.

## **False Positives**
Potential benign activities that might trigger false alerts include:
- Routine IT audits using similar enumeration techniques for compliance checks.
- Legitimate software updates or maintenance tasks querying installed applications.
- Internal penetration testing activities conducted without malicious intent.

## **Priority**
**Severity: High**

Justification: The ability to bypass security monitoring can significantly compromise the integrity and confidentiality of an organization's data. Detecting this technique early is crucial in preventing further exploitation.

## **Validation (Adversary Emulation)**
### Step-by-step Instructions:
1. **Security Software Discovery - PowerShell**
   - Execute `Get-CimInstance Win32_Product | Select-Object -Property Name` on a Windows machine to list installed applications.
   
2. **Security Software Discovery - ps (macOS)**
   - Run `system_profiler SPApplicationsDataType` to enumerate installed applications.

3. **Security Software Discovery - ps (Linux)**
   - Use `dpkg --get-selections | grep -v deinstall` on Debian-based systems or `rpm -qa` on RedHat-based systems to list installed packages.

4. **Security Software Discovery - pgrep (FreeBSD)**
   - Execute `pgrep -fl security` to find processes related to security tools.

5. **Security Software Discovery - Sysmon Service**
   - Observe logs for process creation events with command-line strings indicating system scans or enumerations (`tasklist.exe`, `wmic.exe`).

6. **Security Software Discovery - AV Discovery via WMI**
   - Run `wmic /namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName, pathToSignedProductExe`.

7. **Security Software Discovery - Windows Defender Enumeration**
   - Use PowerShell: `Get-MpComputerStatus | Select-Object AntivirusEnabled`.

8. **Security Software Discovery - Windows Firewall Enumeration**
   - Execute in PowerShell: `(Get-NetFirewallProfile).Name, (Get-NetFirewallProfile).Enabled`.

9. **Get Windows Defender exclusion settings using WMIC**
   - Run `wmic /namespace:\\root\default path MSFT_MpPreference get ExclusionPath,ExcludedFileExtensions`.

## **Response**
When the alert fires:
1. Verify if the source of the command execution is legitimate or suspicious.
2. Assess whether any security software was disabled or modified following enumeration.
3. Escalate findings to incident response teams for further investigation and potential containment.

## **Additional Resources**
- Security Software Discovery - Linux: Explore tools like `lsof`, `netstat` for active service discovery.
- Potential Product Class Reconnaissance Via Wmic.EXE
- Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE
- Recon Command Output Piped To Findstr.EXE
- Suspicious Tasklist Discovery Command

This report provides a structured approach to detecting and responding to Security Software Discovery activities, aligning with Palantir's ADS framework.