# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring using containers. This involves identifying unauthorized discovery and enumeration activities related to peripheral devices, which can be leveraged by adversaries to gain further access or information about a compromised system.

## Categorization
- **MITRE ATT&CK Mapping:** T1120 - Peripheral Device Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1120)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing data from system logs and hardware inventory queries. Key patterns include unusual or unauthorized access to peripheral device information, such as printers and USB devices. Data sources utilized are event logs (e.g., Windows Event Logs), hardware inventory reports, and command execution traces.

## Technical Context
Adversaries often execute this technique by using built-in tools like `Win32_PnPEntity` on Windows or `system_profiler SPUSBDataType` on macOS to enumerate connected devices. These actions can be part of a broader strategy to map out network resources and identify potential exploitation vectors. 

**Adversary Emulation Details:**
- **Sample Commands:** 
  - Windows: `powershell Get-WmiObject Win32_Printer`
  - macOS: `system_profiler SPUSBDataType`

## Blind Spots and Assumptions
- **Limitations:** Detection may miss low-volume or stealthy enumeration attempts that blend in with normal administrative tasks.
- **Assumptions:** It assumes baseline knowledge of expected device inventory and normal behavior patterns, which can vary significantly across different environments.

## False Positives
Potential benign activities that might trigger false alerts include:
- Routine IT maintenance scripts running scheduled hardware inventories.
- Legitimate software updates requiring access to peripheral information for configuration purposes.

## Priority
**Severity: Medium**

Justification: While this technique is a critical component of adversarial discovery, it often serves as an initial step in broader attack campaigns. The potential impact and likelihood are significant but mitigated by proper baseline settings and context-aware analysis.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

1. **Win32_PnPEntity Hardware Inventory:**
   - Execute the command `Get-WmiObject Win32_PnPEntity` in PowerShell to enumerate connected peripheral devices.
   
2. **WinPwn - printercheck:**
   - Run `printercheck.exe` from WinPwn suite to identify and list all installed printers on a Windows system.

3. **Peripheral Device Discovery via fsutil:**
   - Execute `fsutil fsinfo drives` in Command Prompt to enumerate all logical drives, which can indirectly reveal attached devices.

4. **Get Printer Device List via PowerShell Command:**
   - Use the command `Get-WmiObject Win32_Printer` in PowerShell to list all printers available on a Windows machine.

## Response
When an alert for unauthorized peripheral device discovery is triggered, analysts should:
- Validate whether the activity aligns with known IT maintenance schedules or user roles.
- Investigate the source of the command execution—whether it originated from a legitimate administrative account or an unknown entity.
- Correlate with other alerts to assess if this is part of a larger attack vector.

## Additional Resources
- **Fsutil Drive Enumeration:** Understanding how `fsutil` can be leveraged for drive enumeration provides additional context on indirect device discovery methods. 

---

This report offers a comprehensive overview based on the ADS framework, providing actionable insights for detecting and responding to adversarial peripheral device discovery activities.