# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## Goal

This technique aims to detect adversarial attempts to bypass security monitoring by identifying unauthorized software discovery activities within various platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1518 - Software Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1518)

## Strategy Abstract

The detection strategy focuses on monitoring and analyzing data sources such as system logs, application usage records, and network traffic to identify patterns indicative of unauthorized software discovery. Key indicators include unusual queries for installed applications, unexpected access to version information, and the presence of tools known for reconnaissance purposes.

### Data Sources Used:
- System logs (Windows Event Logs, macOS syslog)
- Application usage logs
- Network traffic analysis

### Patterns Analyzed:
- Unusual or repeated access to system inventory data
- Presence of reconnaissance scripts or binaries
- Anomalies in application version information queries

## Technical Context

Adversaries often execute software discovery techniques by leveraging legitimate administrative tools and scripts to gather information about the environment they have penetrated. These activities might include querying installed applications, identifying browser versions, or discovering available system services.

### Adversary Emulation Details:
- **Sample Commands:**
  - Windows: `wmic product get name` for listing installed software
  - Linux/macOS: `dpkg --list`, `brew list`
  - Network queries using tools like `nmap`

## Blind Spots and Assumptions

- **Limitations:** The detection strategy may not cover all possible methods of software discovery, especially those leveraging encrypted channels or novel zero-day techniques.
- **Assumptions:** Assumes that the baseline of normal behavior is well-established to distinguish between legitimate administrative actions and adversarial activity.

## False Positives

Potential benign activities that might trigger false alerts include:
- Routine system maintenance scripts querying installed applications
- Legitimate use of software inventory tools by IT staff for compliance checks
- Regular updates or audits conducted on systems

## Priority

**Severity:** High

**Justification:** Unauthorized software discovery can provide adversaries with critical information about the environment, enabling further exploitation and lateral movement. Early detection is crucial to prevent escalation.

## Validation (Adversary Emulation)

### Step-by-Step Instructions:

1. **Find and Display Internet Explorer Browser Version**
   - Use command: `reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion`

2. **Applications Installed**
   - Windows: Execute `wmic product get name`
   - Linux: Run `dpkg --list` or `rpm -qa`
   - macOS: Use `brew list` or `system_profiler SPApplicationsDataType`

3. **Find and Display Safari Browser Version**
   - Check version via command: `defaults read /Applications/Safari.app/Contents/Info CFBundleShortVersionString`

4. **WinPwn - Dotnetsearch**
   - Execute PowerShell script to search for .NET assemblies
   - Command: `powershell -exec bypass -c "Import-Module .\DotNetSearch.ps1; Invoke-DotNetSearch"`

5. **WinPwn - DotNet**
   - Use PowerShell command to list all loaded .NET assemblies
   - Command: `Get-Process | Select-Object -ExpandProperty Modules`

6. **WinPwn - powerSQL**
   - Execute SQL Server enumeration script
   - Run: `.\powerSQL.ps1 -ServerInstance <YourInstance>`

## Response

When the alert fires, analysts should:
- Immediately isolate affected systems to prevent further data leakage.
- Conduct a thorough investigation to determine the extent of unauthorized access and discovery activities.
- Review logs and audit trails for additional indicators of compromise (IOCs).
- Update detection rules based on findings to improve future response.

## Additional Resources

- [Detected Windows Software Discovery](https://www.paloaltonetworks.com/cyberpedia/techniques/software-discovery)
- MITRE ATT&CK Technique T1518: [Software Discovery](https://attack.mitre.org/techniques/T1518)

This report provides a comprehensive framework for detecting unauthorized software discovery activities, ensuring proactive security measures are in place to counter potential adversarial threats.