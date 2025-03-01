# Alerting & Detection Strategy: Detecting Non-Standard Remote Desktop Protocol (RDP) Port Changes

## **Goal**
The aim of this technique is to detect adversarial attempts to bypass security monitoring by changing the default RDP port on Windows systems, facilitating unauthorized lateral movement within a network.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1021.001 - Remote Desktop Protocol
- **Tactic / Kill Chain Phases:** Lateral Movement
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1021/001)

## **Strategy Abstract**
This detection strategy focuses on monitoring for changes to the default RDP port from 3389 to a non-standard port. The primary data sources include:
- Windows Event Logs (specifically, Security and System logs)
- Network Traffic Monitoring
- Registry Changes

Patterns analyzed include unusual registry modifications that alter the RDP listening port, unexpected network traffic on non-standard ports, and PowerShell or Command Prompt activity related to modifying RDP settings.

## **Technical Context**
Adversaries often change the default RDP port to avoid detection by security tools configured to monitor standard ports. In real-world scenarios, attackers may use command-line utilities such as `netsh` or scripts in PowerShell to alter these configurations.

### Adversary Emulation Details
- **Sample Commands:**
  - PowerShell: 
    ```powershell
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value 12345
    ```
  - Command Prompt:
    ```cmd
    netsh interface portproxy add v4tov4 listenport=12345 listenaddress=0.0.0.0 connectport=3389 connectaddress=localhost
    ```

- **Test Scenarios:**
  - Modify RDP port to a non-standard port via PowerShell.
  - Change the listening port using Command Prompt with `netsh`.
  - Disable Network Level Authentication (NLA) for RDP.

## **Blind Spots and Assumptions**
- Assumes security tools are configured to monitor registry changes and network traffic effectively.
- Relies on logs being properly maintained and not tampered with by the adversary.
- Assumes that standard ports are correctly identified in the security configurations.

## **False Positives**
Potential benign activities include:
- Legitimate system administrators changing RDP settings for maintenance or troubleshooting purposes.
- Misconfigurations during software installations or updates that alter registry settings inadvertently.

## **Priority**
**High:** Changing the default RDP port is a common technique used by attackers to avoid detection and facilitate unauthorized access, making it crucial to detect and respond promptly.

## **Validation (Adversary Emulation)**
### Step-by-step Instructions
1. **RDP to DomainController:**
   - Use legitimate credentials to establish an RDP session.
   
2. **Change RDP Port via PowerShell:**
   ```powershell
   Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value 12345
   ```

3. **Change RDP Port via Command Prompt:**
   ```cmd
   netsh interface portproxy add v4tov4 listenport=12345 listenaddress=0.0.0.0 connectport=3389 connectaddress=localhost
   ```

4. **Disable NLA for RDP via Command Prompt:**
   ```cmd
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDenyTSConnections /t REG_DWORD /d 0 /f
   ```

## **Response**
When an alert is triggered:
- Immediately review the source of the registry modification or network traffic change.
- Verify whether the activity was authorized by checking against known administrative tasks and maintenance schedules.
- If unauthorized, isolate the affected system from the network to prevent further lateral movement.

## **Additional Resources**
- [Potential Tampering With RDP Related Registry Keys Via Reg.EXE](https://attack.mitre.org/techniques/T1021/001)
- [New Firewall Rule Added Via Netsh.EXE](https://attack.mitre.org/techniques/T1562/004)
- [Potential Tampering With RDP Related Registry Keys Via Reg.EXE](https://attack.mitre.org/techniques/T1546/007)

This strategy emphasizes the importance of monitoring changes to critical configurations and maintaining robust logging practices to detect adversarial activities effectively.