# Alerting & Detection Strategy (ADS) Report

## Goal

This technique aims to detect adversarial attempts to bypass security monitoring by exploiting various methods of credential dumping across different operating systems.

---

## Categorization

- **MITRE ATT&CK Mapping:** T1003 - OS Credential Dumping
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows, Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1003)

---

## Strategy Abstract

The detection strategy involves monitoring multiple data sources and analyzing specific patterns associated with credential dumping techniques. Key data sources include:

- **Windows Event Logs**: Focus on events related to credential access, suspicious processes, and remote procedure calls.
- **Sysmon Logs**: Capture detailed process creation information, network connections, and file modifications.
- **Endpoint Detection & Response (EDR) Tools**: Leverage EDR for endpoint behavioral analysis.
- **Network Traffic Analysis**: Monitor for unusual outbound connections indicative of credential theft.

Patterns analyzed include:

- Execution of known credential dumping tools like `gsecdump`, `nppsypy`, `dumpcap`.
- Suspicious usage of Windows APIs related to credential management.
- Unusual processes or services executing with elevated privileges.
- Network traffic associated with remote credential access attempts.

---

## Technical Context

Adversaries execute credential dumping by exploiting vulnerabilities in the operating system, misconfigured services, or using legitimate tools for malicious purposes. Common techniques include:

- **Memory Scraping**: Extracting credentials directly from memory.
- **Exploiting Trusted Services**: Using built-in Windows services like `svchost.exe` to access sensitive information.

Adversary emulation involves executing commands such as:

- **gsecdump**: A tool for dumping credentials stored in the LSASS process.
- **NPPSpy**: Captures and dumps passwords by hooking into network processes.
- **AppCmd**: Used to extract IIS service account credentials through specific configurations.

---

## Blind Spots and Assumptions

- Detection strategies may not cover all zero-day vulnerabilities or novel credential dumping methods.
- Assumes that logging and monitoring tools are properly configured and operational across all endpoints.
- Limited detection capability on encrypted traffic where credential dumping occurs without explicit indicators.

---

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate administrative tasks using credential management tools.
- System updates or patches deploying services requiring elevated privileges.
- Authorized penetration testing activities mimicking adversary behavior.

---

## Priority

**High**: Credential access is a critical phase in the attack lifecycle, providing adversaries with the means to escalate privileges and move laterally within an environment. The potential impact of undetected credential theft can be severe, leading to data breaches and unauthorized system control.

---

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **gsecdump**: Execute `gsecdump.exe` on a test Windows machine with administrative privileges to extract LSASS memory credentials.
   
2. **Credential Dumping with NPPSpy**: Deploy NPPSpy in a controlled environment to capture and dump network passwords.

3. **Dump svchost.exe**: Use tools like Mimikatz to dump `svchost.exe` processes for RDP credentials retrieval.

4. **Microsoft IIS Service Account Credentials**:
   - Using AppCmd: Execute `appcmd list apppool /text:applicationPoolDefaults.processModel.identityType` to gather credential information.
   - Using AppCmd Config: Execute `appcmd config apppool "DefaultAppPool" /processModel.identityType:"SpecificIdentity"`.

5. **Credential Manager Dump**: Utilize `keymgr.dll` and `rundll32.exe` with appropriate commands to dump credentials stored in Windows Credential Manager.

6. **Send NTLM Hash with RPC Test Connection**: Use `net use \\machine\c$ /user:domain\username *` to trigger an NTLM hash capture via RPC test connection.

---

## Response

When the alert fires:

1. **Immediate Containment**: Isolate affected systems from the network to prevent lateral movement.
2. **Investigation**: Review logs and alerts for indicators of compromise (IOCs) and determine the scope of the breach.
3. **Remediation**: Patch vulnerabilities, update credentials, and apply necessary configuration changes.
4. **Forensics**: Conduct a detailed forensic analysis to understand the attack vector and adversary behavior.
5. **Notification**: Inform stakeholders and comply with incident response protocols.

---

## Additional Resources

- [Capture Credentials with Rpcping.exe](https://example.com/rpcping)
- [Suspicious Execution of Powershell with Base64](https://example.com/powershell-base64)
- [Suspicious Key Manager Access](https://example.com/key-manager-access)
- [Potentially Suspicious PowerShell Child Processes](https://example.com/powershell-child-processes)
- [Rundll32 Execution With Uncommon DLL Extension](https://example.com/rundll32-uncommon-dll)
- [Microsoft IIS Service Account Password Dumped](https://example.com/iis-password-dump)

---

This report provides a comprehensive overview of the detection strategy for credential dumping techniques, aligning with Palantir's ADS framework to enhance security posture and response capabilities.