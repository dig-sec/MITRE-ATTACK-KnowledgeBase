# Alerting & Detection Strategy: Process Hollowing (T1055.012)

## Goal
This technique aims to detect adversarial attempts to execute malicious payloads in memory by replacing a legitimate process's image with that of the malicious payload while keeping the original execution flow intact, thereby evading static security defenses.

## Categorization

- **MITRE ATT&CK Mapping:** T1055.012 - Process Hollowing
- **Tactic / Kill Chain Phases:**
  - Defense Evasion
  - Privilege Escalation
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1055/012)

## Strategy Abstract
The detection strategy leverages process monitoring and memory analysis. It focuses on detecting anomalies in how processes are initiated and executed, particularly looking for signs of legitimate processes being replaced by malicious payloads during runtime. Key data sources include:

- **Process Creation Events:** Monitoring unusual parent-child process relationships or unexpected use of `CreateProcessW`.
- **Memory Analysis:** Detecting discrepancies between the memory image of a running process and its on-disk executable.
- **API Call Patterns:** Analyzing patterns indicative of hollowing, such as repeated calls to `NtCreateUserProcess` or modifications to the Process Environment Block (PEB).

## Technical Context
Adversaries utilize Process Hollowing to evade detection by disguising malicious payloads as legitimate processes. This involves:
1. Starting a benign process in suspended mode.
2. Allocating memory within the target process's address space and writing the malicious payload there.
3. Overwriting the original process image with the malicious one while preserving thread execution.
4. Resuming the modified process to execute the malicious code.

Adversary emulation typically involves using scripting languages like PowerShell or programming environments such as Go, which interact directly with Windows APIs (`CreateProcessW`, `NtCreateUserProcess`) to perform these steps.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection might miss sophisticated techniques that further obfuscate memory modifications.
  - May not detect if the malicious payload is executed entirely in memory without any disk-based footprint.

- **Assumptions:**
  - The strategy assumes baseline knowledge of normal process behavior for accurate anomaly detection.
  - It relies on timely and comprehensive logging of process creation and API calls, which might be limited by system configurations or resource constraints.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate software development tools or debugging sessions that perform similar memory manipulations during testing.
- Software using dynamic loading techniques for performance optimization without malicious intent.
- Systems with custom scripts or automation tools that modify process behavior as part of regular operations.

## Priority
**Severity:** High

**Justification:** Process Hollowing is a critical evasion technique used by sophisticated adversaries to execute malware undetected, making it a high-priority threat. Its ability to bypass traditional detection mechanisms necessitates robust monitoring and alerting strategies.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Process Hollowing using PowerShell:**
   - Utilize scripts that leverage `Start-Process` with `-PassThru` to initiate processes in suspended mode.
   - Use `System.Diagnostics.Process.StartInfo` and manipulate the process memory space.

2. **RunPE via VBA:**
   - Embed VBA macros in Office documents to exploit macro execution for hollowing using `ShellExecuteEx`.

3. **Process Hollowing in Go using CreateProcessW WinAPI:**
   - Write a Go program that interfaces with Windows API to create a process, suspend it, and replace its executable code.

4. **Process Hollowing in Go using CreateProcessW and CreatePipe WinAPIs (T1055.012):**
   - Implement a Go application that uses `CreatePipe` for inter-process communication while performing hollowing through `CreateProcessW`.

## Response
When an alert for process hollowing is triggered, analysts should:

1. **Verify the Alert:** Confirm the legitimacy of the detected activity by cross-referencing with known good behaviors or whitelisted processes.
2. **Isolate Affected Systems:** Temporarily disconnect systems from the network to prevent further spread or data exfiltration.
3. **Collect Forensic Data:** Gather memory dumps and logs for a detailed post-incident analysis.
4. **Analyze Payload:** Investigate the payload to understand its capabilities, potential impact, and origin.
5. **Update Detection Rules:** Refine detection rules based on insights gained from the incident to reduce false positives and enhance future detection accuracy.

## Additional Resources
Currently, no additional resources are available beyond standard security frameworks and documentation related to Windows API usage and memory analysis techniques.

---

This report provides a comprehensive overview of detecting Process Hollowing using Palantir's Alerting & Detection Strategy framework. It outlines the necessary steps for implementation, potential challenges, and response actions to ensure effective detection and mitigation.