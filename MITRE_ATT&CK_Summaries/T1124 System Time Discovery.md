# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this technique is to detect adversarial attempts to discover system time, which may be indicative of efforts to align their activities with specific events or to bypass security monitoring mechanisms that rely on timestamps.

## Categorization
- **MITRE ATT&CK Mapping:** T1124 - System Time Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1124)

---

## Strategy Abstract
This detection strategy focuses on identifying unusual or unauthorized attempts to query the system time. It leverages data from multiple sources, including Windows event logs and command execution logs, to detect patterns indicative of system time discovery activities. Key indicators include:
- Anomalies in scheduled task executions.
- Unusual PowerShell script invocations querying time-related information.
- Abnormal network requests for time synchronization.

By analyzing these patterns, the strategy aims to flag potential adversarial attempts to gather system time data without being detected by standard monitoring tools.

---

## Technical Context
Adversaries often need to determine the exact system time to coordinate their activities with specific events or to ensure that malicious payloads trigger at intended times. This can involve:
- Executing commands like `wmic os get localdatetime`.
- Using PowerShell scripts such as `[System.DateTime]::Now` to retrieve current date and time.
- Utilizing tools like `net time` or `w32tm /query /status`.

These techniques allow adversaries to align their operations with other malicious activities, evade detection by masking the timing of their actions, or ensure accurate execution of time-based scripts.

---

## Blind Spots and Assumptions
- **Blind Spots:** 
  - The strategy might miss sophisticated attempts that employ obfuscation techniques or custom-built tools not recognized by standard monitoring.
  - Detection may be limited if adversaries use encrypted channels for communication, hiding their queries within legitimate traffic.

- **Assumptions:**
  - It assumes a baseline of normal behavior against which anomalies can be detected.
  - The environment is adequately instrumented to capture relevant logs and network traffic.

---

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks querying system time for maintenance purposes.
- Scheduled tasks or scripts designed to log system metrics, including timestamps.
- Network devices performing routine synchronization checks with time servers.

---

## Priority
**Priority: Medium**

Justification: System time discovery is a common reconnaissance technique used by adversaries to align their activities. While it may not directly lead to compromise on its own, it often precedes more critical phases of an attack, making its detection valuable for early warning and threat hunting efforts.

---

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **System Time Discovery**
   - Execute `wmic os get localdatetime` on a Windows machine to retrieve the system time.
   
2. **System Time Discovery - PowerShell**
   - Run the PowerShell command `[System.DateTime]::Now` to obtain the current date and time.

3. **System Time Discovery in FreeBSD/macOS**
   - Use `date` or `timedatectl status` to check the system's date and time settings.

4. **System Time Discovery W32tm as a Delay**
   - Execute `w32tm /query /status` on Windows to get detailed information about the system clock.

5. **System Time with Windows time Command**
   - Run `time /T` or `time /Z` in the command prompt to display local or UTC system time.

6. **Discover System Time Zone via Registry**
   - Access the registry editor (`regedit`) and navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` to view the system's time zone settings.

---

## Response
When an alert for this technique fires, analysts should:
- Verify if there is a legitimate reason for querying system time, such as maintenance activities.
- Examine user accounts and processes involved in the activity to determine if they are authorized or compromised.
- Review network logs for any associated suspicious communications that might indicate further reconnaissance or lateral movement.

---

## Additional Resources
- **Use of W32tm as Timer:** Explore how `w32tm` can be used by adversaries to delay actions based on precise timing information.
- **Windows Share Mount Via Net.EXE:** Investigate how time queries might correlate with network share activities.
- **Discovery of a System Time:** Understand the broader implications of system time discovery in attack scenarios.

By following this ADS framework, organizations can better detect and respond to adversarial attempts at system time discovery, enhancing their overall security posture.