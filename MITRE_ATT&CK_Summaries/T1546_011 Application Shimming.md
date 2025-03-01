# Detection Strategy for Application Shimming (T1546.011)

## Goal
The objective of this detection strategy is to identify adversarial attempts to bypass security monitoring using application shimming techniques. Specifically, it targets scenarios where attackers modify the behavior of legitimate applications to execute malicious activities without triggering traditional security mechanisms.

## Categorization

- **MITRE ATT&CK Mapping:** T1546.011 - Application Shimming
- **Tactic / Kill Chain Phases:** Privilege Escalation, Persistence
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1546/011)

## Strategy Abstract

The detection strategy leverages various data sources to identify patterns associated with application shimming. Key data sources include:

- **Event Logs:** Monitoring for unusual registry modifications and file activities, particularly those involving the shim database.
- **File Integrity Monitoring (FIM):** Detecting unexpected changes in shim database files or related executable files like `Sdbinst.exe`.
- **Process Activity Monitoring:** Identifying execution of tools such as `sdbinst` or suspicious process creation patterns.

Patterns analyzed include:
- Creation or modification of registry keys associated with the Shim Database (`Software\Microsoft\Windows\AppCompat`)
- Execution of applications that are typically not shimmable, indicating possible malicious intent.
- Changes in the default shim database directory.

## Technical Context

Adversaries often use application shimming to bypass security controls by altering how legitimate software behaves. This is achieved through tools like `sdbinst.exe`, which installs shim entries into the Windows Application Compatibility Database (ACDB). These entries can be used to manipulate processes, redirect file accesses, or modify function calls.

### Adversary Emulation Details

- **Sample Commands:**
  - Use of `Sdbinst.exe` with a custom shim database XML to install new shims.
    ```
    sdbinst malicious.sdb
    ```

- **Test Scenarios:**
  - Install a shim that redirects a benign process to execute a payload.
  - Modify registry keys associated with the shim database.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection might not cover all variations of shim configurations, especially if custom or obfuscated techniques are used by adversaries.
  - Real-time detection can be challenging in environments with high volumes of legitimate shimming activities.

- **Assumptions:**
  - The environment has monitoring capabilities for registry changes and file integrity checks.
  - Analysts have baseline knowledge of typical shim usage patterns within their systems.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate application compatibility settings applied by IT departments.
- Software updates or patches that modify application behavior through shims.
- Common administrative tasks involving `Sdbinst.exe` for troubleshooting or configuration purposes.

## Priority

**Severity: Medium**

Justification: While application shimming is a sophisticated technique used by adversaries to bypass security controls, its impact can be significant if successful. However, the prevalence of legitimate use cases necessitates careful tuning of detection mechanisms to minimize false positives.

## Validation (Adversary Emulation)

To emulate this technique in a test environment, follow these steps:

1. **Application Shim Installation:**
   - Create or obtain a custom shim database file (`malicious.sdb`).

2. **New Shim Database Files Created:**
   - Use `Sdbinst.exe` to install the shim into the system's default shim database directory.
     ```
     sdbinst malicious.sdb
     ```

3. **Registry Key Creation/Modification Events:**
   - Monitor for registry events related to `Software\Microsoft\Windows\AppCompat`.

## Response

When an alert is triggered:
- Investigate the source and context of the shim installation or modification.
- Verify if the application associated with the shim is legitimate and expected within your environment.
- Assess any changes in behavior or execution paths of affected applications.
- Consider isolating impacted systems for further analysis to prevent potential lateral movement.

## Additional Resources

For more context on detecting suspicious activities related to shimming:
- Investigate unusual copy operations involving system directories that may involve shim files.
- Review documentation and community resources about `Sdbinst.exe` and its legitimate uses versus malicious exploitation scenarios.

By following this structured approach, organizations can enhance their detection capabilities against adversaries using application shimming techniques.