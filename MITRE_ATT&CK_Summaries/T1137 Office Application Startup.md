# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this strategy is to detect adversarial attempts to use Office Application Startup techniques, particularly focusing on launching Outlook as a command-and-control (C2) channel. This technique aims at bypassing security monitoring by exploiting legitimate application behaviors.

## Categorization

- **MITRE ATT&CK Mapping:** T1137 - Office Application Startup
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, Office 365
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1137)

## Strategy Abstract

This detection strategy leverages telemetry data from endpoint security solutions and email gateways to identify suspicious patterns indicative of an Office Application Startup attack. By analyzing PowerShell execution logs, registry modifications, and unusual email behaviors related to Outlook, the strategy aims to detect anomalies that signify adversary activities.

### Data Sources:
- **Endpoint Security Logs:** Monitoring PowerShell executions and startup processes.
- **Email Gateway Logs:** Tracking outgoing emails from Outlook.
- **Registry Access Events:** Observing changes in registry keys associated with Office applications.

### Patterns Analyzed:
- Unusual PowerShell scripts launching Outlook as a background process.
- Abnormal modifications to the Windows Registry related to Office startup configurations.
- Unexpected email traffic initiated by client applications like Outlook, particularly those not typical for user behavior profiles.

## Technical Context

Adversaries often use legitimate tools and processes to maintain persistence on compromised systems. By leveraging the Office Application Startup technique (T1137), attackers can initiate or resume malicious activities without triggering traditional security measures. This is achieved by configuring Office applications such as Outlook to execute a C2 server connection upon startup, often using PowerShell scripts.

### Adversary Emulation Details:
- **Sample Commands:** Attackers might use PowerShell commands like `Start-Job` to launch Outlook with specific parameters that connect back to an external server.
  
  ```powershell
  Start-Job -ScriptBlock {Start-Process "outlook.exe" "/c2connect"} 
  ```

- **Test Scenario:**
  - Modify registry entries under `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Outlook\Startup`.
  - Set a value to launch Outlook with command-line arguments connecting to a C2 server upon user logon.

## Blind Spots and Assumptions

### Known Limitations:
- The strategy may not detect encrypted PowerShell scripts or registry settings that use obfuscation.
- It assumes attackers will modify local system configurations, potentially missing remote execution scenarios.
- Limited visibility into cloud-based email traffic without integration with Office 365 security analytics.

### Assumptions:
- Endpoint detection and response (EDR) tools have comprehensive logging of PowerShell and application startup events.
- Analysts are familiar with baseline behavior patterns for the organization's typical use of Outlook.

## False Positives

Potential benign activities that could trigger false alerts include:

- Legitimate automation scripts using PowerShell to launch Outlook with specific parameters for business workflows.
- Regular IT maintenance tasks involving registry modifications or scheduled Outlook startups during system updates or deployments.
- User-defined macros within Office applications that legitimately alter startup behaviors without malicious intent.

## Priority
**Severity: High**

The use of Office Application Startup techniques can significantly undermine security defenses by enabling persistent access and covert communication channels. The high priority is justified due to the technique's ability to bypass traditional monitoring methods, posing a substantial risk if undetected.

## Validation (Adversary Emulation)

### Step-by-Step Instructions:

1. **Environment Preparation:**
   - Set up a controlled test environment with Windows OS and Office 365.
   - Ensure logging for PowerShell and registry changes is enabled on the endpoint.

2. **Registry Modification:**
   - Navigate to `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Outlook\Startup`.
   - Create or modify a DWORD value named `LaunchOnStartup` with data set to `1`.

3. **PowerShell Script Execution:**
   - Execute the following PowerShell command:

     ```powershell
     Start-Job -ScriptBlock {Start-Process "outlook.exe" "-c2connect"} 
     ```

4. **Observation:**
   - Monitor endpoint logs for PowerShell job initiation and Outlook process startup.
   - Check email gateway logs for outgoing emails initiated by the newly launched Outlook instance.

## Response

When an alert fires indicating potential use of Office Application Startup techniques:

1. **Immediate Actions:**
   - Isolate the affected endpoint from the network to prevent further unauthorized access or data exfiltration.
   - Conduct a thorough analysis of PowerShell and registry logs to understand the scope of changes made by the adversary.

2. **Investigation Steps:**
   - Review email gateway logs for suspicious outgoing communications initiated by Outlook.
   - Identify any lateral movement attempts from compromised endpoints using network traffic analysis tools.

3. **Mitigation:**
   - Revert unauthorized registry modifications and remove malicious PowerShell scripts or jobs.
   - Update security policies to restrict startup parameters in Office applications if feasible.

4. **Follow-Up:**
   - Conduct a post-incident review to refine detection rules and improve visibility into similar techniques.
   - Provide training for analysts on recognizing and responding to such threats effectively.

## Additional Resources

- [Microsoft's Guidelines on PowerShell Security](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-script)
- [Office 365 Threat Intelligence Insights](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/overview-of-the-office-365-ti-dashboard)

By following this strategy, organizations can enhance their detection capabilities against adversaries leveraging Office Application Startup techniques to maintain persistence and execute covert operations.