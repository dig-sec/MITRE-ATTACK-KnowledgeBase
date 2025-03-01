# Palantir's Alerting & Detection Strategy: Windows Management Instrumentation (WMI)

## Goal
The goal of this detection strategy is to identify adversarial attempts to exploit Windows Management Instrumentation (WMI) for executing unauthorized activities, bypassing security controls, and gaining persistence on Windows systems.

## Categorization

- **MITRE ATT&CK Mapping:** T1047 - Windows Management Instrumentation
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1047)

## Strategy Abstract
This detection strategy leverages data from system logs, WMI event subscriptions, and process monitoring to identify anomalous behaviors associated with the exploitation of WMI. Key patterns analyzed include unusual WMI queries, unexpected WMI command executions, and unauthorized changes in WMI configurations. The focus is on detecting activities that indicate reconnaissance or execution attempts through WMI.

## Technical Context
Adversaries use WMI due to its native integration within Windows environments and its capability to execute commands remotely. Commonly exploited for lateral movement and persistence, adversaries may utilize WMI to enumerate system information, create new processes, or uninstall software stealthily. 

Examples of adversary tactics include:
- Using `wmic` to query system information.
- Executing payloads via encoded scripts.
- Creating remote process executions with WMI.

## Blind Spots and Assumptions
- Assumes that all legitimate WMI activity is documented and understood by security teams.
- May not detect sophisticated adversaries who obfuscate their commands effectively or mimic normal behavior patterns.
- Relies on logging and monitoring configurations being comprehensive and properly set up to capture relevant WMI activities.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate system administrators using `wmic` for routine maintenance tasks.
- Scheduled jobs executing legitimate scripts via WMI.
- System updates or software installations querying WMI as part of their operations.

## Priority
**Priority: High**

Justification: The use of WMI by adversaries is a significant threat due to its deep integration within Windows environments, providing attackers with powerful capabilities for stealthy execution and reconnaissance. Detecting such activities promptly can prevent further exploitation and lateral movement.

## Validation (Adversary Emulation)
To validate this detection strategy, follow these steps in a controlled test environment:

1. **WMI Reconnaissance Users**
   - Execute: `wmic useraccount get name`

2. **WMI Reconnaissance Processes**
   - Execute: `wmic process list brief`

3. **WMI Reconnaissance Software**
   - Execute: `wmic product get caption, version`

4. **WMI Reconnaissance List Remote Services**
   - Execute: `wmic service get name, startname, state`

5. **WMI Execute Local Process**
   - Execute: `cscript //nologo wmiprvsr.vbs`

6. **WMI Execute Remote Process**
   - Use WMI tools to initiate a process on a remote machine.

7. **Create a Process using WMI Query and an Encoded Command**
   - Use PowerShell with Base64 encoding to execute a command via WMI.

8. **Create a Process using obfuscated Win32_Process**
   - Modify the `Win32_Process` class properties for execution.

9. **WMI Execute rundll32**
   - Execute: `wmic process call create rundll32.exe some.dll,FunctionName`

10. **Application Uninstall using WMIC**
    - Execute: `wmic product where "name like 'Software%' delete"`

## Response
When an alert related to suspicious WMI activity fires:
1. Verify the legitimacy of the detected activity through contextual analysis and cross-referencing with known benign operations.
2. Isolate affected systems to prevent potential lateral movement.
3. Conduct a thorough investigation using forensic tools to determine the scope of the compromise.
4. Update security policies to mitigate similar future attempts, such as tightening WMI access controls.

## Additional Resources
For further reading and context on WMI exploitation:
- WMIC Remote Command Execution
- Application Removed Via Wmic.EXE
- Potential Product Reconnaissance Via Wmic.EXE
- Suspicious Process Created Via Wmic.EXE
- New Process Created Via Wmic.EXE
- PowerShell Base64 Encoded Invoke Keyword
- Suspicious Execution of Powershell with Base64
- Suspicious PowerShell Parameter Substring
- Change PowerShell Policies to an Insecure Level

These resources provide additional insights into various facets of WMI exploitation and recommended detection approaches.