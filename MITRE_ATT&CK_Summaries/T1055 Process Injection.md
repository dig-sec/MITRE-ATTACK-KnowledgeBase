# Palantir's Alerting & Detection Strategy (ADS) Framework Report: Process Injection

## **Goal**

The primary goal of this detection strategy is to identify adversarial attempts to bypass security monitoring through various process injection techniques on different platforms.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1055 - Process Injection
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1055)

## **Strategy Abstract**

This strategy leverages multiple data sources such as system logs (Windows Event Logs, Syslog), process monitoring tools, and network traffic analysis. Patterns analyzed include unusual parent-child relationships in processes, unexpected API calls like `CreateRemoteThread` or `LoadLibrary`, memory manipulation activities, and anomalous registry entries.

## **Technical Context**

Adversaries utilize process injection to insert malicious code into the address space of legitimate processes. This technique allows them to execute code with elevated privileges while avoiding detection by security software that might not scrutinize legitimate processes closely. Common methods include:
- Using shellcode in memory.
- Leveraging tools like `mimikatz` for remote injections.
- Manipulating process memory directly.

Adversaries may also use scripts or compiled programs to automate these tasks, often employing APIs such as `NtCreateUserProcess`, `VirtualAllocEx`, and `WriteProcessMemory`.

## **Blind Spots and Assumptions**

- **Blind Spots:** Detection might miss novel techniques that do not match known patterns. Some highly sophisticated attacks may utilize anti-detection mechanisms or leverage zero-day vulnerabilities.
- **Assumptions:** Assumes the availability of comprehensive logging and monitoring on all endpoints, and that security tools are configured to capture relevant API calls.

## **False Positives**

Potential benign activities that might trigger false alerts include:
- Legitimate use of debugging tools like WinDbg.
- Software development environments executing code in memory for testing purposes.
- Use of legitimate process management tools by system administrators.

## **Priority**

**Severity: High**

Justification: Process injection is a critical technique used to achieve both defense evasion and privilege escalation, often forming the backbone of advanced persistent threats (APTs).

## **Validation (Adversary Emulation)**

### Step-by-step instructions:

1. **Shellcode Execution via VBA**
   - Utilize Visual Basic for Applications in Office documents to execute shellcode.

2. **Remote Process Injection in LSASS via Mimikatz**
   - Use `mimikatz` with the command: `sekurlsa::pth /user:<domain>/<username> /ntlm:<hash>`.

3. **Section View Injection**
   - Utilize Windows API to map sections into process memory.

4. **Dirty Vanity Process Injection**
   - Run a dummy executable (`svchost.exe`) and inject code into it using `CreateRemoteThread`.

5. **Read-Write-Execute Process Injection**
   - Use the `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` APIs to achieve RWX memory.

6. **Process Injection with Go using UuidFromStringA WinAPI**
   - Leverage Go's Windows API binding to invoke `UuidFromStringA`.

7. **Process Injection with Go using EtwpCreateEtwThread WinAPI**
   - Use the Event Tracing for Windows (ETW) APIs in Go.

8. **Remote Process Injection with Go using RtlCreateUserThread WinAPI**
   - Create user threads remotely within another process using Go bindings.

9. **Remote Process Injection with Go using CreateRemoteThread WinAPI**
   - Invoke `CreateRemoteThread` via Go to inject code into a remote process.

10. **Process Injection with Go using CreateThread WinAPI**
    - Directly create a thread in the target process using Go's Windows API wrappers.

11. **UUID Custom Process Injection**
    - Customize injection techniques based on UUID patterns or identifiers for specific processes.

## **Response**

When an alert is triggered:
1. Verify if the activity originates from a known or legitimate source.
2. Isolate the affected system to prevent further compromise.
3. Collect detailed logs and evidence for forensic analysis.
4. Update detection rules to reduce false positives based on findings.
5. Coordinate with incident response teams to contain and remediate threats.

## **Additional Resources**

- [Potential WinAPI Calls Via CommandLine](https://example.com/winapi-calls)
- [HackTool - Mimikatz Execution](https://github.com/gentilkiwi/mimikatz)
- [Sysinternals Tools Overview](https://docs.microsoft.com/en-us/sysinternals/)

This report provides a comprehensive overview of process injection detection, enabling organizations to identify and respond to sophisticated threats effectively.