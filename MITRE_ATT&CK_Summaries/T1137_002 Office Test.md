# Alerting & Detection Strategy: Office Application Startup Test Persistence (HKCU)

## Goal
The objective of this detection strategy is to identify adversarial attempts that leverage startup persistence mechanisms in Windows environments using Office applications, specifically targeting the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry key. This technique allows adversaries to maintain persistence by executing malicious scripts or binaries when a user logs into their system.

## Categorization
- **MITRE ATT&CK Mapping:** T1137.002 - Office Application Startup Test Persistence
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, Office 365
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1137/002)

## Strategy Abstract
This detection strategy focuses on monitoring the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry key for unauthorized or suspicious entries. The approach includes collecting data from Windows event logs, file integrity checks, and user activity monitoring to identify anomalies indicating persistence through Office application startup scripts.

The strategy leverages pattern analysis to detect deviations from normal behavior by examining:
- Unusual entries in the specified registry key.
- Unexpected modifications of existing registry keys.
- Execution patterns of scripts or binaries that align with known malicious signatures or behaviors.

## Technical Context
Adversaries use this technique to establish persistence on Windows systems by adding a startup entry under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. This allows them to execute their payload every time the user logs in, ensuring continuous presence and control over the system.

### Execution Details:
- **Common Commands:** Adversaries might use PowerShell or command-line tools like `reg add` to manipulate registry entries. For example:
  ```shell
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyMaliciousApp /t REG_SZ /d "C:\Path\To\MaliciousScript.bat"
  ```
- **Test Scenario:** Adversaries often test their persistence mechanisms to ensure the malicious payload executes as expected upon user login, potentially using benign scripts for initial testing before deploying malware.

## Blind Spots and Assumptions
- **Assumptions:**
  - Users have standard privileges; elevated users may bypass some detection controls.
  - The strategy assumes regular monitoring of the specified registry key is possible without alert fatigue.
  
- **Limitations:**
  - Legitimate software updates or configurations might create false positives if not properly whitelisted.
  - Highly skilled adversaries could obfuscate their activity, making it harder to detect malicious intent.

## False Positives
Potential benign activities that might trigger alerts include:
- Legitimate applications adding entries for startup tasks (e.g., antivirus, backup software).
- Users manually configuring startup scripts or applications.
- System updates or maintenance tools altering registry settings.

## Priority
**Severity: High**

Justification: This technique provides adversaries with a reliable method to maintain persistent access to compromised systems. It can facilitate lateral movement and further exploitation of network resources, making it critical to detect and mitigate promptly.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Setup Test Environment:** Ensure you have a controlled Windows environment for testing.
2. **Create Registry Entry:**
   - Open Command Prompt as an administrator.
   - Execute the following command to add a benign entry under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`:
     ```shell
     reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersistenceApp /t REG_SZ /d "C:\Path\To\TestScript.bat"
     ```
3. **Create a Test Script:**
   - Create `TestScript.bat` with basic commands like logging output to a file.
4. **Reboot System:** Log out and back in or restart the system to trigger the startup entry.
5. **Monitor Alerts:** Ensure detection systems flag this activity, verifying alert triggers without false negatives.

## Response
When an alert is triggered:
- **Immediate Actions:**
  - Isolate the affected machine from the network.
  - Verify the legitimacy of the detected registry entry and associated script or binary.
  
- **Investigation Steps:**
  - Analyze user account activity to determine how the change was made.
  - Check file integrity for any changes that might indicate tampering.
  
- **Remediation:**
  - Remove unauthorized entries from the registry.
  - Update security policies and whitelists as necessary.
  - Conduct a broader review of similar entries across other user profiles.

## Additional Resources
Additional references and context are not available. Analysts should rely on internal threat intelligence, updated security baselines, and collaboration with IT and security teams to refine detection mechanisms continually.