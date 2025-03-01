# Alerting & Detection Strategy (ADS) Framework for Forced Authentication via RPC Calls on Windows

## Goal
The technique aims to detect adversarial attempts to bypass security monitoring by exploiting Remote Procedure Call (RPC) mechanisms to force authentication and gain unauthorized access, particularly targeting Windows platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1187 - Forced Authentication
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1187)

## Strategy Abstract
This detection strategy focuses on monitoring unauthorized or suspicious RPC call activities that might be used to force authentication without proper user consent. The data sources utilized include network traffic logs, system event logs, and security incident and event management (SIEM) systems. Patterns analyzed involve unexpected RPC requests targeting specific services known for credential access vulnerabilities, such as the Netlogon service.

## Technical Context
Adversaries executing this technique typically attempt to exploit weaknesses in Windows' authentication mechanisms by initiating an authenticated RPC call to a target server without setting the Sign flag. This method allows them to intercept and manipulate authentication credentials.

### Adversary Emulation Details:
- **PetitPotam**: A tool used for exploiting NTLM relay vulnerabilities, particularly focusing on SMB and Netlogon service weaknesses.
- **WinPwn - PowerSharpPack**: Utilized for retrieving NTLM hashes without directly accessing LSASS, leveraging PowerShell scripts to automate the process.
- **Test Scenario**: Initiating an RPC call with no Sign flag set to a target server, aiming to capture or manipulate authentication credentials.

## Blind Spots and Assumptions
- Assumes that all potential targets are correctly identified and monitored for unauthorized RPC access attempts.
- Limited detection capability if adversaries use advanced obfuscation techniques to mask RPC traffic.
- Relies on the assumption that network security controls are in place to detect abnormal RPC patterns.

## False Positives
- Legitimate administrative tasks involving authenticated RPC calls, such as remote management or software deployment activities.
- Network configurations where certain services inherently require frequent and legitimate RPC communication.

## Priority
**Severity: High**

Justification: Forced authentication via RPC calls can lead to significant credential theft and unauthorized access, posing a severe threat to organizational security. The potential impact on sensitive data integrity and confidentiality necessitates prioritizing this detection strategy.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Environment Setup**: Prepare a controlled test environment with Windows-based systems.
2. **PetitPotam Deployment**:
   - Download PetitPotam from a trusted source.
   - Configure it to target the Netlogon service for NTLM relay attacks.
3. **WinPwn Execution**:
   - Use PowerSharpPack to simulate credential harvesting without accessing LSASS.
   - Execute PowerShell scripts designed to perform these actions in the test environment.
4. **RPC Call Triggering**:
   - Initiate an authenticated RPC call to a target server within the test network.
   - Ensure the Sign flag is not set during this operation.

## Response
When an alert related to forced authentication via RPC calls fires, analysts should:
- Immediately investigate the source and destination of the suspicious RPC traffic.
- Verify whether the involved systems are authorized for such interactions.
- Temporarily disable affected services if unauthorized access is confirmed.
- Conduct a thorough review of system logs and network traffic for additional indicators of compromise.

## Additional Resources
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious PowerShell Download and Execute Pattern
- Malicious PowerShell Commandlets - ProcessCreation
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets
- Capture Credentials with Rpcping.exe
- Suspicious Execution of Powershell with Base64
- Potential SMB Relay Attack Tool Execution

These resources provide further context and examples of techniques used in conjunction with forced authentication strategies, enhancing the understanding and detection capabilities within an organization.