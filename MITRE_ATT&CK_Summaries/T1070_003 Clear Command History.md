# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this detection strategy is to detect adversarial attempts to bypass security monitoring through clearing command history on various operating systems and platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1070.003 - Clear Command History
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/003)

## Strategy Abstract
This strategy aims to detect attempts by adversaries to erase command history in order to obscure their activities from security monitoring systems. The detection approach utilizes log analysis and behavioral anomaly detection across multiple data sources, including shell logs (Bash, PowerShell), Docker container logs, and system audit records. Patterns indicative of history clearing are analyzed, such as the use of specific commands (`rm`, `echo`, etc.) or alterations to configuration files related to command logging.

## Technical Context
Adversaries often execute this technique to remove traces of their activities from command-line interfaces. This can involve:
- Deleting or truncating history files directly (e.g., using `history -c` in Bash).
- Redirecting output streams to null devices to prevent logging.
- Disabling automatic history logging via configuration changes.

Adversaries may employ these methods on Linux, macOS, and Windows systems, utilizing tools and commands native to each environment. Understanding the common commands and tactics used for clearing command history is crucial for effective detection.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection might not cover all variations or novel techniques that adversaries could use.
  - Encrypted or obfuscated commands may evade pattern-based detection.

- **Assumptions:**
  - Assumes baseline logging configurations are intact and actively monitoring command history.
  - Relies on the presence of logs, which can be disabled by sophisticated attackers.

## False Positives
Potential benign activities that could trigger false alerts include:
- Routine system maintenance tasks involving clearing caches or temporary files.
- Administrators intentionally clearing command histories for privacy or security reasons.
- Scripts designed to reset environments as part of legitimate operations (e.g., automated testing frameworks).

## Priority
**Severity:** Medium

**Justification:**
Clearing command history is a common technique used by adversaries to hide their tracks. While it does not indicate an immediate threat, the detection of such behavior can be pivotal in uncovering more extensive malicious activities and understanding adversary tactics.

## Validation (Adversary Emulation)
To validate this strategy, follow these steps in a controlled test environment:

1. **Clear Bash History:**
   - Use `history -c` to clear the current session history.
   - Execute `rm ~/.bash_history` to remove the history file.
   - Run `echo '' > ~/.bash_history` or `cat /dev/null > ~/.bash_history` for truncation.
   - Create a symlink with `ln /dev/null ~/.bash_history`.
   - Use `truncate -s 0 ~/.bash_history` to clear contents.

2. **Clear History of Multiple Shells:**
   - Execute the above commands within different shell sessions concurrently.

3. **Disable Bash History Logging:**
   - Set `HISTFILE=""` and `HISTSIZE=0` in the shell configuration files.
   - Use space before commands, e.g., ` echo command`, to avoid logging.
   - Disable history over SSH with `-T`: `ssh -T user@host 'echo command'`.

4. **Clear Docker Container Logs:**
   - Run `docker logs --tail 0 <container_id>` or remove container log files directly.

5. **Prevent PowerShell History Logging:**
   - Use `Remove-Item $env:HOMEDRIVE+$env:HOMEPATH\Documents\WindowsPowerShell\PSHistory.xml`.
   - Set `$null = New-Object -TypeName System.Management.Automation.PSSession` to reset history.
   - Define a custom `AddToHistoryHandler` function that does nothing.

6. **Clear PowerShell Session History:**
   - Execute `Get-History | ForEach { Remove-History $_.Id }`.

## Response
When an alert for clearing command history is triggered, analysts should:
- Investigate the context of the activity by reviewing related logs and user actions.
- Assess whether the behavior aligns with known maintenance schedules or legitimate administrative tasks.
- Escalate any suspicious findings to a broader incident response team for further analysis.

## Additional Resources
For more details on techniques to detect history file deletion and command obfuscation, refer to:
- **History File Deletion Techniques**
- **Command Line Obfuscation Methods**

---

This comprehensive ADS report provides a structured approach to detecting attempts at clearing command histories across diverse platforms, aiding in proactive security measures.