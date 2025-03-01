# Alerting & Detection Strategy (ADS) Report: System Language Discovery

## Goal
This technique aims to detect adversarial attempts to discover system languages on various platforms as a precursor for potential malicious activities.

## Categorization
- **MITRE ATT&CK Mapping:** T1614.001 - System Language Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Linux, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1614/001)

## Strategy Abstract
The detection strategy focuses on identifying patterns and anomalies related to the discovery of system languages. It leverages data sources such as process monitoring, command execution logs, registry queries, and environment variable analysis across Windows, Linux, and macOS platforms. Key patterns include unexpected or unauthorized use of commands like `chcp`, `locale`, and PowerShell scripts that query language settings.

## Technical Context
Adversaries may execute this technique to tailor their payloads according to the system's locale, enhancing the efficacy of social engineering attacks or ensuring compatibility with local configurations. Common methods involve querying registry settings on Windows, utilizing built-in commands like `chcp` and `locale`, or scripting environments for automated discovery.

### Adversary Emulation Details
- **Sample Commands:**
  - `chcp`
  - `locale`
  - PowerShell scripts to query system information

## Blind Spots and Assumptions
- Limited visibility into encrypted command execution.
- Assumes that all language-discovery activities are adversarial without considering legitimate administrative actions.
- Potential gaps in detection when adversaries use obfuscated or non-standard methods.

## False Positives
- Legitimate IT administration tasks involving language configuration checks.
- Software installations that query system settings as part of compatibility checks.
- Automated scripts used for system audits or compliance reporting.

## Priority
**Severity: Medium**

Justification: While not directly harmful, discovering system languages can be a precursor to more targeted attacks. The medium priority reflects the need to balance detection with minimizing false positives from legitimate activities.

## Validation (Adversary Emulation)
### Instructions to Emulate System Language Discovery

1. **Discover System Language by Registry Query**
   - On Windows: Use `reg query` to inspect registry keys related to system locale settings.
   
2. **Discover System Language with chcp**
   - Execute `chcp` in command prompt or PowerShell to display the active console code page.

3. **Discover System Language with locale**
   - Run `locale` on Linux/macOS to view current language and regional settings.

4. **Discover System Language with localectl**
   - On Linux: Use `localectl status` to check system locale information.

5. **Discover System Language by Locale File**
   - Inspect files such as `/etc/locale.conf` or similar on Linux/macOS for language configurations.

6. **Discover System Language by Environment Variable Query**
   - Check environment variables like `LANG` and `LC_ALL` on Unix-based systems.

7. **Discover System Language with dism.exe**
   - On Windows: Use `dism /online /get-locale-info` to retrieve locale information.

8. **Discover System Language by Windows API Query**
   - Utilize PowerShell scripts or applications that call Windows APIs to gather language data.

9. **Discover System Language with WMIC**
   - Execute `wmic os get Locale` on Windows to obtain the system locale setting.

10. **Discover System Language with PowerShell**
    - Use PowerShell commands such as `[System.Globalization.CultureInfo]::CurrentCulture` to extract current culture settings.

## Response
When an alert for this technique fires, analysts should:
- Validate the context and origin of the detected activity.
- Assess whether the command execution aligns with known administrative or operational tasks.
- Investigate any anomalies in user behavior patterns that coincide with language discovery attempts.
- Escalate findings if there are indicators of compromise or suspicious activities.

## Additional Resources
Currently, no additional resources are available for this technique. Analysts should refer to internal documentation and threat intelligence feeds for further context on potential threats related to system language discovery.