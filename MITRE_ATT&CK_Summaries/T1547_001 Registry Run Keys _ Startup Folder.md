# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## **Goal**
The goal of this technique is to detect adversarial attempts that leverage containers as a means to bypass traditional security monitoring systems and frameworks.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1547.001 - Registry Run Keys / Startup Folder
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/001)

## **Strategy Abstract**
This detection strategy focuses on identifying malicious activities associated with the use of containers to maintain persistence and escalate privileges. Data sources include system logs, registry monitoring tools, and container activity logs. Patterns analyzed involve unusual registry modifications related to startup folders and run keys, unexpected container deployments, and anomalous interactions between host systems and containerized environments.

## **Technical Context**
Adversaries exploit containers by embedding malicious payloads that can evade detection by traditional security mechanisms. This is often achieved through:

- Tampering with Windows Registry Run Keys/Startup Folder to ensure execution of malware when a system boots or a user logs in.
- Deploying containers with persistence mechanisms such as scheduled tasks, exploiting container escape vulnerabilities, and using containers for lateral movement.

**Adversary Emulation Details:**
1. **Sample Commands:** 
   - `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MalwareName /t REG_SZ /d "C:\malicious_container.exe" /f`
2. **Test Scenarios:** 
   - Deploy a benign container with startup scripts that mimic malicious behavior, such as attempting to modify system registry keys or accessing sensitive files.

## **Blind Spots and Assumptions**
- Blind spots include detection evasion techniques like using legitimate containers for illegitimate purposes without obvious signs of compromise.
- Assumes regular monitoring of both host-level activities and container-level interactions is in place.
- Relies on the assumption that any unusual registry modifications or unexpected container activity are potentially malicious.

## **False Positives**
Potential benign activities that might trigger false alerts include:

- Legitimate software updates modifying startup scripts.
- IT administrative tasks involving container deployment for testing purposes.
- User-installed applications with legitimate use of startup folders or registry keys.

## **Priority**
**Severity: High**

Justification:
- Containers are increasingly popular in both legitimate and adversarial contexts, making them a significant vector for persistent threats.
- Successful exploitation can lead to privilege escalation and lateral movement within an organization's network.

## **Validation (Adversary Emulation)**

### Step-by-Step Instructions:

1. **Reg Key Run:**
   - Add malicious entry to registry run keys using `reg add` command.

2. **Reg Key RunOnce:**
   - Use `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` for one-time execution scenarios.

3. **PowerShell Registry RunOnce:**
   - Execute PowerShell script that adds a registry entry to `RunOnce`.

4. **Suspicious vbs file run from startup Folder:**
   - Place a VBScript with suspicious behavior in the Startup folder and verify execution at boot.

5. **Suspicious jse file run from startup Folder:**
   - Deploy JavaScript file containing malicious code in the Startup folder.

6. **Suspicious bat file run from startup Folder:**
   - Add batch script to execute upon system start-up, mimicking malicious activity.

7. **Add Executable Shortcut Link to User Startup Folder:**
   - Create a shortcut linking to an executable within the user's startup directory.

8. **Add persistence via Recycle bin:**
   - Configure malware to persist in the Recycle Bin for execution upon opening.

9. **SystemBC Malware-as-a-Service Registry:**
   - Use SystemBC services to modify registry entries related to startup and persistence.

10. **Change Startup Folder - HKLM Modify User Shell Folders Common Startup Value:**
    - Alter `User Shell Folders` in the `HKLM` hive to add new startup folders.

11. **Change Startup Folder - HKCU Modify User Shell Folders Startup Value:**
    - Similar modification within the `HKCU` hive for user-specific configurations.

12. **HKCU - Policy Settings Explorer Run Key:**
    - Add entries under `Policy Settings\Explorer\Run` in `HKCU`.

13. **HKLM - Policy Settings Explorer Run Key:**
    - Insert malicious run keys under `HKLM`'s `Policy Settings\Explorer\Run`.

14. **HKLM - Append Command to Winlogon Userinit KEY Value:**
    - Modify the `Userinit` key in `Winlogon` to execute additional commands.

15. **HKLM - Modify default System Shell - Winlogon Shell KEY Value:**
    - Change the system shell via `Winlogon\Shell` for persistence through user logins.

16. **secedit used to create a Run key in the HKLM Hive:**
    - Utilize `secedit` command-line tool to manipulate registry keys for persistence.

17. **Modify BootExecute Value:**
    - Alter `BootExecute` value within the system hive to execute commands at boot time.

18. **Allowing custom application to execute during new RDP logon session:**
    - Configure remote desktop settings to launch applications on user login.

19. **Creating Boot Verification Program Key for application execution during successful boot:**
    - Modify registry settings to run verification programs as part of the boot process.

20. **Add persistence via Windows Context Menu:**
    - Insert entries into context menus for automatic payload execution.

## **Response**
When an alert is triggered:

- Isolate affected systems and containers to prevent further spread.
- Investigate suspicious registry changes or container activities using forensic tools.
- Review logs and correlate events with known malicious patterns.
- Implement remediation steps such as removing unauthorized registry entries and terminating malicious processes.

## **Additional Resources**

For further context and reference, consider reviewing the following:

- **Potential Persistence Attempt Via Existing Service Tampering**
  - Investigate services that may have been altered for persistence purposes.
  
- **Direct Autorun Keys Modification**
  - Monitor direct changes to autorun keys within the registry.

- **Potential Persistence Attempt Via Run Keys Using Reg.EXE**
  - Analyze usage of `reg.exe` for modifying run keys, which can indicate malicious intent. 

These resources provide additional insights into techniques used by adversaries to maintain persistence and evade detection.