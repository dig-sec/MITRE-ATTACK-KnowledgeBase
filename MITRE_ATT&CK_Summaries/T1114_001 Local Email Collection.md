# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to collect emails locally using scripting tools like PowerShell on Windows platforms. The focus is on identifying actions that bypass typical network-based email monitoring.

## Categorization
- **MITRE ATT&CK Mapping:** T1114.001 - Local Email Collection
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1114/001)

## Strategy Abstract
The detection strategy leverages endpoint telemetry and script execution logs to identify patterns indicative of local email collection. Key data sources include PowerShell event logs, process monitoring tools, and file access records.

Patterns analyzed:
- Use of `Get-Inbox` or similar commands in PowerShell scripts.
- Execution of scripts from suspicious directories (e.g., Temp folder).
- Modifications to PowerShell policies enabling script execution from untrusted locations.

## Technical Context
Adversaries execute local email collection by leveraging native scripting tools like PowerShell to extract emails directly from an Outlook profile on the victim's machine. This method circumvents network monitoring systems by operating entirely within the endpoint environment, making it a stealthy data exfiltration technique.

### Adversary Emulation Details
- **Sample Commands:**
  ```powershell
  $mail = New-Object -ComObject Outlook.Application
  $namespace = $mail.GetNamespace("MAPI")
  $inbox = $namespace.GetDefaultFolder([Microsoft.Office.Interop.Outlook.OlDefaultFolders]::olFolderInbox)
  $inbox.Items | ForEach-Object { $_.SaveAsHTML("C:\Temp\emails\$($_.Subject).html") }
  ```

## Blind Spots and Assumptions
- **Limitations:**
  - Detection relies on the assumption that local email collection is executed using PowerShell, which might not cover all methods.
  - Out-of-band data exfiltration techniques may evade detection if logs are insufficiently granular.

- **Assumptions:**
  - The presence of Outlook and its configurations allows for local script-based data extraction.
  - Standard logging mechanisms are active and capturing relevant events.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate automation scripts using `Get-Inbox` for business purposes.
- IT administrators performing maintenance or updates on email systems using PowerShell scripts.
- Developers testing email integration features locally.

## Priority
**Severity: High**

Justification:
- Local email collection can bypass network-level security measures, providing adversaries with sensitive information undetected.
- The technique targets critical assets (email data) and is often part of broader attacks aimed at information exfiltration.

## Validation (Adversary Emulation)
### Step-by-step Instructions

1. **Environment Setup:**
   - Ensure a Windows machine with Outlook installed and configured to the user’s email profile.
   - Enable PowerShell script execution via `Set-ExecutionPolicy Unrestricted` if necessary, noting that this is typically restricted for security reasons.

2. **Script Execution:**
   - Open PowerShell as Administrator.
   - Execute the following command:
     ```powershell
     $mail = New-Object -ComObject Outlook.Application
     $namespace = $mail.GetNamespace("MAPI")
     $inbox = $namespace.GetDefaultFolder([Microsoft.Office.Interop.Outlook.OlDefaultFolders]::olFolderInbox)
     $inbox.Items | ForEach-Object { $_.SaveAsHTML("C:\Temp\emails\$($_.Subject).html") }
     ```

3. **Observation:**
   - Monitor for PowerShell events and file creation in the specified directory.
   - Verify that logs capture script execution, command-line usage, and file operations.

## Response
Upon detection of this technique:
- Isolate the affected system to prevent further data exfiltration.
- Conduct a thorough forensic analysis to determine the scope of access and any other compromised systems or data.
- Review and adjust security policies to enhance monitoring for similar activities in the future.
- Educate users on identifying suspicious scripts and email anomalies.

## Additional Resources
- **Use Short Name Path in Command Line:** Exploitation of command-line path parsing can obscure script execution details.
- **Script Interpreter Execution From Suspicious Folder:** Monitoring script executions from non-standard directories can indicate malicious activity.
- **Suspicious Script Execution From Temp Folder:** Scripts run from temporary locations may be attempting to avoid detection.
- **Change PowerShell Policies to an Insecure Level:** Altering policy settings to enable script execution from untrusted sources is a precursor to many PowerShell-based attacks.

This report provides a comprehensive framework for detecting and responding to local email collection activities on Windows platforms, addressing both technical and operational considerations.