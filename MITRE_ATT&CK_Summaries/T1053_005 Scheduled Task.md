# Detection Strategy for Adversarial Use of Windows Scheduled Tasks

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring by leveraging Windows Scheduled Tasks. Attackers often exploit these tasks for malicious purposes such as execution, persistence, and privilege escalation.

## Categorization
- **MITRE ATT&CK Mapping:** T1053.005 - Scheduled Task
- **Tactic / Kill Chain Phases:** Execution, Persistence, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1053/005)

## Strategy Abstract
The detection strategy focuses on monitoring various data sources to identify suspicious activities associated with Scheduled Tasks. Key data sources include:
- Task Scheduler logs
- Event Logs (e.g., Security, Application)
- PowerShell execution logs

Patterns analyzed involve:
- Creation of tasks via unusual methods or tools (e.g., Schtasks.exe, PowerShell)
- Execution of base64 encoded commands
- Tasks with hidden attributes or set to run with high privileges
- Unexpected modifications to existing tasks

## Technical Context
Adversaries often use Scheduled Tasks for executing malicious payloads due to their native integration within Windows environments. This technique provides stealth and persistence, making it challenging to detect without proper monitoring.

Common methods include:
- **Scheduled Task Startup Script:** Executing a script at system startup.
- **Powershell Cmdlet:** Using PowerShell cmdlets like `Register-ScheduledTask` for task creation.
- **WMI Invoke-CimMethod:** Leveraging WMI methods to configure tasks remotely.

Adversaries might also modify existing tasks or create "ghost" tasks that are difficult to detect through traditional means, using techniques such as:
- **Registry Key Manipulation**: Creating tasks via registry key alterations.
- **VBA Macros**: Using Office applications to set up tasks indirectly.

## Blind Spots and Assumptions
- Assumes all necessary logs are being collected and monitored effectively.
- Potential blind spots include highly obfuscated task names or command-line arguments that evade pattern detection.
- Dependence on the integrity of event logging mechanisms, which might be tampered with by sophisticated adversaries.

## False Positives
- Legitimate administrative tasks created via Schtasks.exe for system maintenance.
- Scheduled backups or updates initiated by enterprise management software.
- Tasks executed under standard user privileges for routine operations.

## Priority
**High.** Windows Scheduled Tasks are a prevalent method for achieving persistence and executing malicious code, making it imperative to detect such activities promptly to prevent potential breaches.

## Validation (Adversary Emulation)
### Step-by-step Instructions:

1. **Scheduled Task Startup Script**
   - Create a startup script that launches on boot.
   ```powershell
   schtasks /create /tn "TestStartupTask" /tr "C:\Windows\System32\cmd.exe /c echo Test" /sc onstart /f
   ```

2. **Scheduled task Local**
   - Set up a local scheduled task using Task Scheduler GUI or command line.
   
3. **Scheduled task Remote**
   - Use PowerShell to create a remote task:
   ```powershell
   Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument "/c echo Test") -Trigger (New-ScheduledTaskTrigger -AtStartup) -TaskName "TestRemoteTask" -User "Administrator"
   ```

4. **Powershell Cmdlet Scheduled Task**
   - Register a task using PowerShell cmdlets.
   ```powershell
   $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\calc.exe"
   $trigger = New-ScheduledTaskTrigger -AtStartup
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "PowerShellTest" -Description "Test Task"
   ```

5. **Task Scheduler via VBA**
   - Use a macro in an Office document to create tasks.

6. **WMI Invoke-CimMethod Scheduled Task**
   ```powershell
   $task = Get-WmiObject Win32_ScheduledJob | where {$_.Name -eq "TestWMI"}
   $task.Create("$env:TEMP\TestTask.ps1")
   ```

7. **Scheduled Task Executing Base64 Encoded Commands From Registry**
   - Encode a command and store it in the registry for execution.

8. **Import XML Schedule Task with Hidden Attribute**
   ```xml
   <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
     <!-- Define task with hidden attribute -->
   </Task>
   ```

9. **PowerShell Modify A Scheduled Task**
   - Use PowerShell to modify an existing task:
   ```powershell
   Get-ScheduledTask -TaskName "TestTask" | Set-ScheduledTask -Description "Modified Test"
   ```

10. **Scheduled Task ("Ghost Task") via Registry Key Manipulation**
    - Create a task entry in the registry without using Task Scheduler GUI.

11. **Scheduled Task Persistence via CompMgmt.msc**
    - Use Computer Management Console for task creation.

12. **Scheduled Task Persistence via Eventviewer.msc**
    - Leverage event viewer settings to create persistent tasks.

## Response
When an alert is triggered:
1. Verify the legitimacy of the scheduled task by checking its origin and purpose.
2. If malicious, terminate the process associated with the task.
3. Remove or disable the suspicious scheduled task immediately.
4. Investigate any related activities in event logs for further insights into potential lateral movement or privilege escalation.

## Additional Resources
- **Potential Execution of Sysinternals Tools:** Monitor usage patterns that may indicate exploitation attempts.
- **Suspicious Schtasks Schedule Type With High Privileges:** Pay attention to tasks scheduled with elevated privileges.
- **Scheduled Task Creation Via Schtasks.EXE:** Investigate any unusual command-line arguments or schedules.
- **Schtasks Creation Or Modification With SYSTEM Privileges:** Assess tasks created by system-level accounts for anomalies.

This comprehensive strategy equips security teams to detect and respond effectively to adversarial use of Windows Scheduled Tasks, ensuring robust defense against potential breaches.