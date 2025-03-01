# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring using native API calls on different platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1106 - Native API
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** Windows, macOS, Linux  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1106)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing native API calls across various platforms to identify malicious activities. Key data sources include process creation events, syscall logs, and behavioral analysis tools that capture API usage patterns indicative of adversarial behavior.

- **Data Sources:**
  - Process monitoring and logging
  - Syscall auditing
  - Behavioral analytics
  
- **Patterns Analyzed:**
  - Unusual or unauthorized API calls (e.g., CreateProcess)
  - Deviations from normal application behavior

## Technical Context
Adversaries leverage native APIs to execute code stealthily, often achieving elevated privileges without detection. This technique is commonly used across Windows, macOS, and Linux for executing payloads that can evade traditional antivirus solutions.

### Adversary Emulation Details:
- **Sample Commands:**
  - `WinPwn`: Utilizes Get SYSTEM shell techniques.
    - *CreateProcess*: Creates a process to escalate privileges.
    - *NamedPipe Impersonation*: Uses named pipes to impersonate and gain system-level access.

- **Test Scenarios:**
  - Emulate adversary actions in controlled environments using tools like WinPwn or scripting languages such as Go for syscall execution, focusing on CreateProcess invocations.

## Blind Spots and Assumptions
- **Limitations:**
  - May not detect highly obfuscated API calls.
  - Limited effectiveness against zero-day exploits that use undocumented APIs.
  
- **Assumptions:**
  - The system has comprehensive monitoring tools capable of capturing low-level API interactions.
  - Analysts are familiar with normal vs. abnormal behavior for the environment.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate administrative tasks involving elevated privileges.
- Software development processes utilizing native APIs for testing or automation.

## Priority
**Severity:** High  
**Justification:** This technique is a common method used by adversaries to execute malicious code and elevate privileges, making it crucial to detect and mitigate promptly.

## Validation (Adversary Emulation)
### Step-by-step Instructions:
1. **Execution through API - CreateProcess:**
   - Use tools like WinPwn or scripting in Go to simulate the execution of a process via CreateProcess.
   
2. **WinPwn Techniques:**
   - *Get SYSTEM shell using CreateProcess technique:* Execute code that attempts privilege escalation using CreateProcess.
   - *Bind System Shell using CreateProcess technique:* Bind an executable as a system service.
   - *Pop System Shell using NamedPipe Impersonation technique:* Emulate NamedPipe impersonation to gain elevated access.

3. **Run Shellcode via Syscall in Go:**
   - Write and execute shellcode through syscalls, focusing on those that can lead to privilege escalation or unauthorized process creation.

## Response
When an alert fires:
- Immediately isolate the affected system from the network.
- Conduct a thorough investigation to determine the scope of compromise.
- Review logs for additional suspicious activities correlating with the alert.
- Update detection rules and signatures based on findings to enhance future detection capabilities.

## Additional Resources
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious PowerShell Download and Execute Pattern
- Malicious PowerShell Commandlets - ProcessCreation
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets

These resources provide further context on similar tactics that adversaries may employ, aiding in comprehensive detection strategy development.