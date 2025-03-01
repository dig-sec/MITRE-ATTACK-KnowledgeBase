# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Log Clearing Techniques

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by clearing Windows Event Logs, a common technique used for evading detection and obscuring activity.

## Categorization

- **MITRE ATT&CK Mapping:** T1070.001 - Clear Windows Event Logs
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/001)

## Strategy Abstract
The detection strategy involves monitoring Windows Event Log activities for unusual patterns that indicate attempts to clear logs. This includes identifying unauthorized changes in log configurations or deletions of log entries, which can signal an adversary's effort to erase traces of their activities. Key data sources utilized are:

- **Windows Event Logs:** Specifically targeting event IDs related to log modifications.
- **Security Information and Event Management (SIEM) Systems:** To correlate events and identify suspicious patterns.
  
Patterns analyzed include:
- Unauthorized access attempts to the Windows Event Viewer.
- Frequent deletion or truncation of security-related logs, such as Security, Application, and System logs.

## Technical Context
Adversaries may use several methods to clear Windows Event Logs:

1. **Clearing Logs Manually:**
   - Using built-in Windows utilities like `wevtutil` command-line tool.
   - Example Command: `wevtutil cl Security`

2. **Using Scripts or Tools:**
   - PowerShell scripts that automate log clearing.
   - Example Script:
     ```powershell
     Get-EventLog -LogName Application | Clear-EventLog
     ```

3. **Employing VBA Macros:**
   - Executing Visual Basic for Applications (VBA) scripts to clear logs through Windows applications like Excel or Word.
   - Example VBA Code:
     ```vba
     Set WSHShell = CreateObject("WScript.Shell")
     WSHShell.Run "wevtutil cl Security", 0, True
     ```

### Adversary Emulation Details

- **Test Scenario:**
  - Use a controlled environment to execute `Clear-EventLog` commands.
  - Deploy scripts that mimic adversary behavior.

## Blind Spots and Assumptions

- Assumes all log clearing activities are malicious without considering legitimate administrative tasks.
- May not detect indirect methods of log manipulation, such as altering system configurations to suppress logging.
- Relies on the integrity and completeness of event logs prior to any tampering.

## False Positives
Potential benign activities that might trigger alerts include:

- Authorized IT personnel performing routine maintenance or clearing space in event logs.
- Automated scripts used by applications for legitimate log management purposes.
- Misconfigured systems where logs are cleared due to insufficient storage rather than malicious intent.

## Priority
**High**

Justification: Clearing Windows Event Logs can significantly hinder incident response efforts, making it difficult to track adversary movements and understand the scope of a breach. The potential impact on security posture justifies prioritizing detection of this technique.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Clear Logs:**
   - Execute `wevtutil cl Security` in Command Prompt with administrative privileges.
   
2. **Delete System Logs Using Clear-EventLog:**
   - Run the PowerShell command:
     ```powershell
     Get-EventLog -LogName Application | Clear-EventLog
     ```

3. **Clear Event Logs via VBA:**
   - Open a VBA-enabled application (e.g., Excel).
   - Insert and run the following code:
     ```vba
     Sub ClearLogs()
         Set WSHShell = CreateObject("WScript.Shell")
         WSHShell.Run "wevtutil cl Security", 0, True
     End Sub
     ```

## Response

Upon alert activation:

1. **Immediate Investigation:**
   - Verify the source of log clearing activity to determine if it was authorized.
   - Assess any potential data loss or tampering.

2. **Containment and Mitigation:**
   - Temporarily restrict access rights related to event logs.
   - Increase monitoring for further suspicious activities.

3. **Incident Response:**
   - Document the incident, including timeline and affected systems.
   - Notify relevant stakeholders and adjust security policies if necessary.

## Additional Resources
- [SANS Institute Guide on Event Log Monitoring](https://www.sans.org/)
- [Windows Event Log Management Best Practices](https://docs.microsoft.com/en-us/windows/win32/wes/event-log-management-best-practices)
  
This strategy provides a comprehensive approach to detecting and responding to attempts by adversaries to clear Windows Event Logs, ensuring robust security monitoring and incident response capabilities.