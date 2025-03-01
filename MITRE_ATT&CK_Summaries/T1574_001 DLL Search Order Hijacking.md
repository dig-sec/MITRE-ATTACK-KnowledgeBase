# Alerting & Detection Strategy: DLL Search Order Hijacking (T1574.001)

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring and escalate privileges by manipulating the Windows Dynamic Link Library (DLL) search order, allowing unauthorized DLLs to be executed in place of legitimate system files.

## Categorization

- **MITRE ATT&CK Mapping:** T1574.001 - DLL Search Order Hijacking
- **Tactic / Kill Chain Phases:**
  - Persistence
  - Privilege Escalation
  - Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1574/001)

## Strategy Abstract
The strategy leverages various data sources, including process monitoring logs and system event records, to detect anomalies in DLL loading behavior. By analyzing patterns such as unexpected changes to the PATH environment variable or unusual DLL loads during critical processes execution, we aim to identify potential hijacking attempts.

### Data Sources Utilized:
- Process monitoring tools (e.g., Sysmon)
- Windows Event Logs
- File Integrity Monitoring (FIM) systems

## Technical Context
DLL Search Order Hijacking involves adversaries modifying the system's DLL search path or placing malicious DLLs in strategic locations to be loaded by legitimate processes. This can lead to unauthorized code execution with elevated privileges.

### Execution Method:
Adversaries typically execute this technique through command-line tools or scripts that alter environment variables or modify directory structures. For example, they might place a rogue DLL in the same directory as an executable and rename it identically to a legitimate system DLL expected by the process.

#### Sample Commands:
- Modify PATH: `setx PATH "C:\malicious;%PATH%"`
- Rename/Move DLLs: `copy /y C:\Windows\System32\legit.dll C:\Windows\System32\evil.dll`

## Blind Spots and Assumptions
- **Assumption:** The system's default DLL search order is not extensively modified by legitimate administrative processes.
- **Limitation:** Detection may miss attacks that leverage non-standard execution contexts or advanced obfuscation techniques to blend in with normal activities.

## False Positives
Potential benign activities triggering false alerts include:
- Legitimate software updates that temporarily alter directory contents or PATH variables.
- Administrative tasks that involve DLL manipulation for maintenance purposes (e.g., troubleshooting scripts).

## Priority
**Severity: High**

Justification: The technique allows adversaries to execute malicious code with elevated privileges, potentially leading to full system compromise. Its ability to bypass traditional defenses makes it a critical threat vector.

## Validation (Adversary Emulation)

### DLL Search Order Hijacking - amsi.dll

1. **Prepare Environment:**
   - Set up a controlled Windows environment.
   - Install Sysmon for logging and monitoring.

2. **Emulate Technique:**
   - Copy `amsi.dll` to the directory of a legitimate process (e.g., `C:\Windows\System32`).
   - Rename it to mimic a known DLL loaded by the process (e.g., `legit.dll`).

3. **Trigger Process Execution:**
   - Execute a benign process that loads `legit.dll`.

4. **Analyze Results:**
   - Review Sysmon logs for unexpected DLL loads.

### Phantom Dll Hijacking - WinAppXRT.dll

1. **Prepare Environment:**
   - Ensure Windows App Compatibility Shims are installed.
   
2. **Emulate Technique:**
   - Place `WinAppXRT.dll` in a directory that appears early in the search order.
   - Rename it to match an expected DLL.

3. **Trigger Process Execution:**
   - Run a process known to use WinAppX shims.

4. **Analyze Results:**
   - Check for discrepancies in shim logs or unexpected DLL loads.

### Phantom Dll Hijacking - ualapi.dll

1. **Prepare Environment:**
   - Set up a test environment with appropriate logging enabled.

2. **Emulate Technique:**
   - Copy `ualapi.dll` to a directory within the search order.
   - Rename it to imitate a legitimate DLL.

3. **Trigger Process Execution:**
   - Execute a process that would typically load `ualapi.dll`.

4. **Analyze Results:**
   - Examine logs for unusual DLL load events.

## Response
When an alert fires, analysts should:

1. **Verify Alert Validity:** Confirm the event is not due to legitimate administrative activity.
2. **Isolate Affected Systems:** Prevent further spread or data exfiltration by isolating compromised systems from the network.
3. **Conduct Forensic Analysis:** Investigate logs and affected files for indicators of compromise (IOCs).
4. **Mitigate Threat:** Remove malicious DLLs, restore legitimate ones, and correct environment variables.
5. **Update Defense Mechanisms:** Enhance monitoring rules to reduce false positives and refine detection capabilities.

## Additional Resources
No additional references currently available. Analysts should consult internal documentation for related threat intelligence and incident response procedures.