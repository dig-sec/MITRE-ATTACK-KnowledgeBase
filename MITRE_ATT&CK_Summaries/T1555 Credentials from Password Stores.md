# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Credential Access Techniques

## **Goal**
This technique aims to detect adversarial attempts to access and exploit credentials stored in password managers or credential stores on various operating systems, potentially bypassing security monitoring controls.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1555 - Credentials from Password Stores
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1555)

## **Strategy Abstract**
The detection strategy focuses on monitoring unauthorized access to credential stores across multiple platforms. Data sources include system logs, process monitoring events, and network traffic capturing the execution of specific commands or scripts known for extracting credentials. Patterns analyzed involve unusual access times, non-administrative user attempts to extract credentials, and anomalies in command-line activity related to credential store manipulation.

## **Technical Context**
Adversaries often use tools like PowerShell on Windows, `pass` on Linux, or Keychain Access on macOS to retrieve stored credentials for escalating privileges or gaining lateral movement. These techniques can be executed silently, making them difficult to detect without robust monitoring and correlation of suspicious activities.

### Adversary Emulation Details
- **Sample Commands:** 
  - PowerShell: `Get-Credential`, `vaultcmd.exe`
  - Linux: `pass show <entry> | grep password`
  - macOS: `security find-generic-password -l "<login>"`

## **Blind Spots and Assumptions**
- Assumes credentials are stored in default or known locations; alternative methods may not be detected.
- Limited by the visibility of credential access logs on certain platforms.
- Relies heavily on predefined command patterns, which can evolve.

## **False Positives**
Potential benign activities include:
- Legitimate administrative tasks involving credential retrieval for maintenance.
- Scheduled scripts accessing credentials during routine operations.
- Development environments where frequent access to password stores is common.

## **Priority**
**Severity: High**

Justification: Credential theft directly undermines security by potentially providing adversaries with unrestricted access, leading to further compromise and data exfiltration. The impact of successful credential access can be significant across various environments.

## **Validation (Adversary Emulation)**

To validate this detection strategy in a controlled test environment, follow these steps:

1. **Extract Windows Credential Manager via VBA:**
   - Use Excel with embedded VBA scripts to extract credentials.
2. **Dump Credentials from Windows Credential Manager With PowerShell [Windows Credentials]:**
   ```powershell
   Get-StoredCredential | Select-Object Target, UserName, Password
   ```
3. **Dump Credentials from Windows Credential Manager With PowerShell [Web Credentials]:**
   ```powershell
   cmdkey /list
   ```
4. **Enumerate Credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]:**
   ```shell
   vaultcmd.exe list
   ```
5. **Enumerate Credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]:**
   ```shell
   vaultcmd.exe list | findstr "WEB"
   ```
6. **WinPwn - Loot local Credentials - lazagne:**
   - Execute `lazagne.exe` to extract credentials.
7. **WinPwn - Loot local Credentials - Wifi Credentials:**
   - Utilize command-line tools like `netsh wlan show profile name=<SSID> key=clear`.
8. **WinPwn - Loot local Credentials - Decrypt Teamviewer Passwords:**
   - Use specific decryption tools to extract TeamViewer stored credentials.

## **Response**
When the alert fires, analysts should:

1. **Verify Legitimacy:** Determine if the credential access was part of a legitimate process.
2. **Isolate Affected Systems:** Prevent potential lateral movement by containing affected systems.
3. **Investigate User Activity:** Analyze user behavior and recent changes in access patterns or permissions.
4. **Notify Security Teams:** Alert incident response teams for further investigation.

## **Additional Resources**
- Windows Credential Manager Access via VaultCmd
- PowerShell Download and Execution Cradles
- Usage Of Web Request Commands And Cmdlets
- PowerShell Web Download

This comprehensive strategy ensures robust detection of credential access attempts, reducing the risk of adversaries bypassing security monitoring.