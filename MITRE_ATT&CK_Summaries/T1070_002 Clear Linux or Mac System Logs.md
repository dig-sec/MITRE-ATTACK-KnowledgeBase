# Alerting & Detection Strategy (ADS) Report: Detecting Log Tampering Techniques on Linux and macOS Systems

## Goal
The goal of this detection strategy is to identify adversarial attempts aimed at bypassing security monitoring by clearing or manipulating system logs on Linux and macOS platforms. These activities often fall under the Defense Evasion tactic in the MITRE ATT&CK framework.

## Categorization
- **MITRE ATT&CK Mapping:** T1070.002 - Clear Linux or Mac System Logs
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1070/002)

## Strategy Abstract
This detection strategy focuses on monitoring and analyzing system logs to identify patterns indicative of log tampering. The key data sources include:
- System event logs (e.g., syslog, auditd)
- Log integrity tools outputs (e.g., AIDE)
- File access and modification timestamps

Patterns analyzed for detecting log tampering involve sudden deletions or truncations of log files, unexpected changes in file sizes, or unauthorized use of utilities that can alter or clear logs.

## Technical Context
Adversaries may employ various techniques to clear system logs as part of their efforts to evade detection. Common methods include:
- Deleting log files using commands like `rm`.
- Truncating logs with the `truncate` utility.
- Overwriting logs by redirecting output to `/dev/null`.
- Using utilities such as `unlink`, `shred`, or `srm`.

Adversaries often execute these actions after gaining elevated privileges, allowing them to alter critical security data without detection.

### Adversary Emulation Details
To emulate this technique in a test environment, consider the following commands:
- `rm -rf /var/log/syslog`
- `truncate -s 0 /var/log/auth.log`
- `cat /dev/null > /var/log/messages`
- `find /var/log -type f -delete`

## Blind Spots and Assumptions
- **Assumptions:** The system logs are intact at the time of deployment, allowing baseline comparisons.
- **Blind Spots:** 
  - Legitimate administrative activities may also clear or truncate logs for maintenance purposes.
  - Log tampering techniques not covered by this strategy (e.g., remote log alteration).
  - Lack of coverage for cloud-based logging systems.

## False Positives
Potential benign activities that might trigger false alerts include:
- System administrators clearing log files as part of routine maintenance.
- Automated scripts designed to rotate logs or perform housekeeping tasks.
- Legitimate use of utilities like `truncate` for non-malicious purposes.

## Priority
**Severity: High**

Justification: Log tampering directly impacts the ability to detect and respond to security incidents. The absence of log data can prevent organizations from understanding the scope and nature of an attack, thus undermining their overall security posture.

## Validation (Adversary Emulation)
To validate this detection strategy, follow these steps in a controlled test environment:

1. **Delete Log Files:**
   - Execute `rm -rf /var/log/syslog` to remove logs.
   - Use `unlink /var/log/messages` for file unlinking.

2. **Truncate Logs:**
   - Apply `truncate -s 0 /var/log/auth.log`.

3. **Overwrite Logs with Null Output:**
   - Run `cat /dev/null > /var/log/*.log`.

4. **Use Built-in Utilities to Clear Logs:**
   - Use `echo "" > /var/log/syslog` for overwriting.
   - Apply `srm /var/log/auth.log` to securely remove logs.

5. **Real-time Log Clearance:**
   - Set up a cron job or script that periodically clears specific log files.

6. **Overwrite macOS System Logs:**
   - Use `echo "" > ~/Library/Logs/system.log`.

7. **Overwrite FreeBSD System Logs:**
   - Execute `echo "" > /var/log/messages` on FreeBSD systems.

## Response
When an alert for potential log tampering is triggered, analysts should:
- Immediately isolate the affected system to prevent further data loss or manipulation.
- Review recent access logs and audit trails for unauthorized activities.
- Restore logs from backups if available, ensuring that integrity checks are performed.
- Investigate any related alerts or anomalies to assess the extent of the breach.

## Additional Resources
For more information on securing log files and detecting tampering:
- Refer to the official [Clear Linux Logs documentation](https://docs.01.org/clearlinux/latest/guides/maintenance/logging.html).
- Consult tools like AIDE for monitoring file integrity.

This strategy aims to provide a comprehensive approach to detecting and responding to adversarial attempts at clearing system logs, ensuring that security teams can maintain visibility over critical events on their systems.