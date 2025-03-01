# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## Goal
The objective of this strategy is to detect adversarial attempts to bypass security monitoring using containers. This involves identifying unauthorized use of the `at` command in Windows environments, which adversaries often leverage for scheduling malicious tasks.

## Categorization

- **MITRE ATT&CK Mapping:** T1053.002 - At (Windows)
- **Tactic / Kill Chain Phases:** Execution, Persistence, Privilege Escalation
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1053/002)

## Strategy Abstract
The detection strategy involves monitoring for suspicious use of the `at` command across various data sources, including process logs and task scheduler entries. By analyzing patterns such as unexpected scheduling of tasks or execution at unusual times, we can identify potential adversarial activities.

### Data Sources Utilized:
- Process execution logs
- Task Scheduler events

### Patterns Analyzed:
- Unusual scheduling patterns (e.g., high frequency)
- Execution by unauthorized users
- Tasks scheduled to run during off-hours

## Technical Context
Adversaries often use the `at` command to schedule tasks that execute with elevated privileges, potentially leading to persistence and privilege escalation. This technique is particularly insidious because it can bypass traditional real-time monitoring systems.

### Adversary Emulation Details:
- **Sample Commands:**
  - `at 02:00 /interactive cmd.exe`
  - `schtasks /create /tn "MaliciousTask" /tr "cmd.exe" /sc ONCE /st 02:00`

## Blind Spots and Assumptions
- **Limitations:** The strategy may not detect well-camouflaged tasks that mimic legitimate user behavior.
- **Assumptions:** Assumes that all instances of the `at` command are logged accurately in process and task scheduler logs.

## False Positives
Potential benign activities include:
- Legitimate use by administrators for maintenance scripts.
- Scheduled backups or updates during off-hours.

## Priority
**High** - The technique poses a significant risk due to its potential to bypass security measures, leading to unauthorized access and data exfiltration.

## Validation (Adversary Emulation)
### Step-by-step Instructions:
1. **At.exe Scheduled Task**
   - Open Command Prompt as Administrator.
   - Execute: `at 02:00 /interactive cmd.exe`
   - Verify the task appears in Task Scheduler.

2. **At - Schedule a Job**
   - Use Task Scheduler to create a new task.
   - Set it to run at an unusual time (e.g., 02:00 AM).
   - Ensure the task executes `cmd.exe` or another executable with potential malicious intent.

## Response
When an alert fires:
1. **Verify and Investigate:** Confirm whether the scheduled task is legitimate by reviewing its origin, purpose, and permissions.
2. **Containment:** Disable any suspicious tasks immediately.
3. **Incident Response:** Initiate a broader investigation to determine if additional compromise has occurred.

## Additional Resources
- [Interactive AT Job](https://attack.mitre.org/techniques/T1053/002)
- Microsoft's Task Scheduler documentation for understanding legitimate task creation and management.

This report provides a comprehensive framework for detecting adversarial use of the `at` command in Windows environments, aligned with Palantir's ADS strategy.