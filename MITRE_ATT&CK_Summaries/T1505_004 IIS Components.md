# Alerting & Detection Strategy (ADS) Report: Detecting Adversarial Use of IIS Components for Persistence

## Goal
The goal of this technique is to detect adversarial attempts to use Internet Information Services (IIS) components to establish persistence on a Windows environment. This involves adversaries exploiting IIS modules to maintain access and control over compromised systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1505.004 - Web Service Execution via Compromised Components
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows

For more information, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1505/004).

## Strategy Abstract
The detection strategy focuses on monitoring for unusual or unauthorized IIS module installations and configurations that could indicate persistence mechanisms. Data sources include Windows Event Logs (particularly Security and System logs), process execution logs, file integrity monitoring alerts, and network traffic analysis.

Patterns analyzed involve:
- Unexpected installation or removal of IIS modules.
- Anomalous registry changes related to IIS.
- Unusual outbound connections from the server following module updates.
- Execution patterns that match known adversarial techniques for deploying malicious IIS modules.

## Technical Context
Adversaries often target web services like IIS due to their availability and potential to execute code remotely. They may deploy custom IIS modules or manipulate existing ones to achieve persistence, allowing them continued access even after system restarts or reboots. This is typically done by:
- Dropping malicious DLL files into the server's module directory.
- Configuring IIS to load these modules automatically on boot.

Adversaries might use command-line tools such as `AppCmd.exe` or PowerShell cmdlets like `New-WebGlobalModule` for deployment, often obfuscating their actions to evade detection. 

## Blind Spots and Assumptions
- **Blind Spots:** The strategy may not detect persistence mechanisms that do not involve IIS modules or those using encrypted/obfuscated payloads.
- **Assumptions:** Assumes a baseline of legitimate IIS module configurations and typical server behavior is established.

## False Positives
Potential false positives might include:
- Legitimate software updates to IIS modules by IT staff.
- Scheduled tasks that modify IIS settings as part of routine maintenance.
- Misconfigurations resulting in benign log entries similar to adversarial actions.

## Priority
**Severity: High**

Justification: The exploitation of web services like IIS for persistence is a critical threat. It enables adversaries to maintain long-term access, complicating detection and remediation efforts.

## Validation (Adversary Emulation)
To validate the detection strategy, follow these steps in a controlled test environment:

1. **Install IIS Module using AppCmd.exe:**
   - Open Command Prompt as Administrator.
   - Run: `appcmd add module /name:"TestModule" /image:"C:\path\to\malicious.dll"`
   
2. **Install IIS Module using PowerShell Cmdlet New-WebGlobalModule:**
   - Open PowerShell as Administrator.
   - Execute: `New-WebGlobalModule -Name "TestModule" -Path "C:\path\to\malicious.dll"`

Monitor for alerts related to these actions and verify that detection mechanisms capture the installation process.

## Response
When an alert fires indicating potential adversarial use of IIS components:
1. **Verify the Alert:** Cross-reference with known maintenance schedules or IT change logs.
2. **Investigate Further:** Examine event logs, file integrity checks, and network traffic for corroborating evidence.
3. **Containment:** Temporarily isolate affected systems to prevent further spread.
4. **Remediation:** Remove unauthorized IIS modules and restore legitimate configurations.
5. **Post-Incident Analysis:** Review incident response actions and update detection strategies as needed.

## Additional Resources
- [IIS Native-Code Module Command Line Installation](https://learn.microsoft.com/en-us/iis/get-started/installing-iis/installing-a-native-code-module)
- [MITRE ATT&CK Framework for IIS Techniques](https://attack.mitre.org/techniques/T1505/004)

This report provides a comprehensive strategy to detect and respond to adversarial use of IIS components, ensuring robust security monitoring and incident response capabilities.