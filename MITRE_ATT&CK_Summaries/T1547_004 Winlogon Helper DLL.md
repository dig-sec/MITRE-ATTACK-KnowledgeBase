# Alerting & Detection Strategy: Detecting Winlogon Helper DLL Modifications

## Goal
The objective of this detection strategy is to identify attempts by adversaries to modify the Windows Registry related to the `Winlogon` process. This technique often aims to bypass security monitoring and maintain persistence or escalate privileges.

## Categorization
- **MITRE ATT&CK Mapping:** T1547.004 - Winlogon Helper DLL
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1547/004)

## Strategy Abstract
This detection strategy focuses on monitoring changes to specific Windows Registry keys associated with the `Winlogon` process. The data sources include Windows Event Logs, specifically focusing on events related to registry modifications (Event ID 4656) and service configuration changes. Patterns analyzed involve unexpected or unauthorized changes to `Winlogon` helper DLLs.

## Technical Context
Adversaries often modify `Winlogon` settings to load malicious DLLs into memory when the user logs in, allowing them to execute code with elevated privileges. This is typically done by altering registry keys such as:

- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

These modifications can facilitate persistence and privilege escalation.

### Adversary Emulation Details
- **Sample Commands:**
  - PowerShell: `Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "C:\malicious.dll,cmd.exe"`
  
- **Test Scenarios:**
  - Emulate registry changes by modifying the above keys with benign test DLLs and observe event logs for detection.

## Blind Spots and Assumptions
- Assumes that all legitimate modifications to `Winlogon` are monitored and authorized.
- Relies on comprehensive logging of registry changes; missing logs can create blind spots.
- May not detect in-memory or other non-persistent modifications.

## False Positives
Potential benign activities include:
- Legitimate system updates or software installations modifying `Winlogon`.
- System administrators performing maintenance tasks that alter these keys.

## Priority
**Priority: High**

Justification: Modifications to `Winlogon` can lead to significant security breaches by granting adversaries persistent access and elevated privileges, potentially compromising the entire system.

## Validation (Adversary Emulation)
### Steps to Emulate in a Test Environment

1. **Winlogon Shell Key Persistence - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "C:\test.dll,cmd.exe"
   ```

2. **Winlogon Userinit Key Persistence - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\test.dll,explorer.exe"
   ```

3. **Winlogon Notify Key Logon Persistence - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Notify" -Value "C:\test.dll"
   ```

4. **Winlogon HKLM Shell Key Persistence - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "C:\test.dll,cmd.exe"
   ```

5. **Winlogon HKLM Userinit Key Persistence - PowerShell**
   ```powershell
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\test.dll,explorer.exe"
   ```

## Response
When an alert is triggered:
1. **Verify the source** of the registry modification to ensure it was not authorized.
2. **Check user activity logs** for suspicious behavior leading up to the change.
3. **Isolate the affected system** to prevent further spread or damage.
4. **Conduct a full system scan** using updated antivirus and anti-malware tools.
5. **Rollback changes** if possible, restoring registry keys to their previous state.

## Additional Resources
Additional references and context are currently not available for this technique. However, maintaining up-to-date knowledge of Windows security best practices is recommended for effective monitoring and response.