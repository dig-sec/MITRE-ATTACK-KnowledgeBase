# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring by executing malicious binaries via legitimate system processes and services on Windows platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1218 - Signed Binary Proxy Execution
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1218)

## Strategy Abstract
The detection strategy focuses on identifying abnormal behaviors and patterns associated with the execution of malicious binaries through legitimate system processes. Key data sources include:

- Process monitoring logs to detect unusual parent-child process relationships.
- File integrity checks to identify unauthorized changes or executions in critical directories.
- Registry analysis for unexpected modifications or command injections.

Patterns analyzed involve deviations from typical process lifecycles, anomalous file access behaviors, and suspicious registry key manipulations.

## Technical Context
Adversaries utilize this technique by exploiting legitimate system binaries or processes to execute malicious payloads. This can include:

- Injecting DLLs into running processes using tools like `mavinject`.
- Executing malicious code via system utilities such as `Register-CimProvider` or the Windows Update Client (`wuauclt.exe`).
- Using registry keys and logon scripts (e.g., `gpscript`) to execute code during system startup.

Adversaries may also manipulate well-known processes like `svchost.exe` or use tools like `lolbas` for command execution via legitimate services.

## Blind Spots and Assumptions
Known limitations include:

- Difficulty in distinguishing between benign and malicious usage of common system utilities.
- Limited visibility into encrypted or obfuscated payloads that can evade signature-based detection.
- Potential gaps in detecting advanced persistence mechanisms where adversaries disguise their activities within normal operations.

Assumptions made involve the assumption that deviations from typical process behavior are indicative of an adversarial action.

## False Positives
Potential benign activities triggering false alerts include:

- Legitimate use of system tools like `wuauclt.exe` for updates or maintenance.
- Normal variations in startup scripts and logon processes.
- Routine execution of administrative tasks that may temporarily mirror suspicious behaviors.

## Priority
**Severity: High**

Justification: This technique allows adversaries to evade detection by leveraging trusted system components, posing a significant risk to the integrity and confidentiality of sensitive data.

## Validation (Adversary Emulation)
To emulate this technique in a controlled test environment:

1. **mavinject:** Inject a benign DLL into a running process and observe the process behavior.
2. **Register-CimProvider:** Use it to execute a benign script, monitoring for unexpected behaviors.
3. **InfDefaultInstall.exe:** Execute a harmless `.inf` file to analyze system responses.
4. **ProtocolHandler.exe:** Download and run a safe file, simulating suspicious activity.
5. **Microsoft.Workflow.Compiler.exe:** Execute with non-malicious payloads to observe any abnormal executions or renamings.
6. **Invoke-ATHRemoteFXvGPUDisablementCommand:** Perform base tests using legitimate commands.
7. **DiskShadow Command Execution:** Use for benign scripting and observe outcomes.
8. **Load Arbitrary DLL via Wuauclt:** Execute a safe DLL through the Windows Update Client to test detection mechanisms.
9. **Lolbin Gpscript logon/startup options:** Use these scripts for routine tasks without malicious intent.
10. **Lolbas ie4uinit.exe as proxy:** Spawn processes legitimately for testing.
11. **CustomShellHost via LOLBAS:** Execute non-malicious processes to observe detection capabilities.
12. **Provlanch.exe through Registry Key:** Test benign command execution via registry manipulation.
13. **LOLBAS Msedge to Spawn Process:** Use Edge browser to execute legitimate tasks.

## Response
When the alert fires, analysts should:

- Immediately isolate affected systems to prevent further compromise.
- Conduct a thorough investigation of process relationships and file activities.
- Review logs for any unauthorized access or changes in critical directories and registry keys.
- Update detection signatures based on findings to improve future response efficacy.
- Report the incident through appropriate channels within the organization, including notifying relevant stakeholders.

## Additional Resources
For further context and reference:

- **Diskshadow Script Mode Execution:** Understand how legitimate scripts can be used maliciously.
- **Suspicious Process Masquerading As SvcHost.EXE:** Analyze potential disguises of malicious processes.
- **Uncommon Svchost Parent Process:** Investigate unexpected parent-child process relationships.
- **System File Execution Location Anomaly:** Identify deviations in file execution paths.
- **Mavinject DLL Injection:** Monitor for unauthorized DLL injections into running processes.
- **Wlrmdr.EXE Uncommon Arguments/Processes:** Examine unusual command-line arguments or child processes.
- **Provisioning Registry Key Abuse:** Detect potential misuse of registry keys for proxy execution.
- **Suspicious System Directory Access:** Flag unauthorized file operations in system directories.
- **Gpscript Execution:** Monitor logon and startup scripts for anomalies.
- **Proxy Execution via Wuauclt.EXE:** Watch for indirect command executions through Windows Update Client.
- **RemoteFXvGPUDisablement Abuse:** Test scenarios involving RemoteFX GPU disablement commands.
- **Microsoft Workflow Compiler Execution:** Observe workflow compiler activities for irregularities.
- **InfDefaultInstall.exe .inf Execution:** Evaluate execution patterns of INF files.

This report provides a comprehensive overview and actionable insights to enhance detection and response strategies against sophisticated adversarial techniques leveraging legitimate Windows processes.