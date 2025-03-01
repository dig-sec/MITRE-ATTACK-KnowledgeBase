# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using LSASS Driver

## Goal

This detection strategy aims to identify adversarial attempts to bypass security monitoring by leveraging the Local Security Authority Subsystem Service (LSASS) driver through techniques such as T1547.008, as defined in MITRE ATT&CK.

## Categorization

- **MITRE ATT&CK Mapping:** [T1547.008 - LSASS Driver](https://attack.mitre.org/techniques/T1547/008)
- **Tactic / Kill Chain Phases:**
  - Persistence
  - Privilege Escalation
- **Platforms:** Windows

## Strategy Abstract

The detection strategy involves monitoring and analyzing specific system activities that indicate the modification of LSASS behavior, which is commonly exploited to load arbitrary DLLs. Key data sources include:

- **Windows Event Logs:** Specifically focusing on security-related events (Event ID 4688 for process creation and others related to registry modifications).
- **Registry Monitoring:** Observing changes in registry keys associated with service configurations.
- **File Integrity Checks:** Detecting unauthorized changes to LSASS binaries or configuration files.

Patterns analyzed include:

- Unusual DLL loading by LSASS not typical of standard operations.
- Registry modifications targeting the LSASS key, which could indicate an attempt to load arbitrary code.

## Technical Context

Adversaries often target LSASS due to its elevated privileges and central role in Windows security. By inserting malicious DLLs into LSASS, attackers can potentially execute arbitrary code with system-level permissions while evading traditional detection mechanisms.

### Real-World Execution

In practice, adversaries may modify registry keys under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lsass` to load a custom DLL using the `LoadedModule` or `ImagePath` parameters. This technique can be executed using PowerShell scripts or directly modifying the registry via administrative privileges.

#### Adversary Emulation Details

- **Sample Commands:**
  ```powershell
  reg add HKLM\SYSTEM\CurrentControlSet\Services\lsass /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\System32\lsass.exe -l C:\malicious.dll" /f
  ```
- **Test Scenarios:** 
  - Execute the above command in a controlled environment to observe event logs and registry changes.
  - Validate alert triggers by simulating unusual DLL loading behavior.

## Blind Spots and Assumptions

### Known Limitations:
- Detection may not cover all variations of LSASS exploitation, particularly those using non-standard techniques or obfuscation.
- Reliance on specific event logging configurations; lack of detailed logs can lead to missed detections.

### Assumptions:
- Proper permissions are configured for accessing relevant Windows events and registry keys.
- System integrity tools (e.g., antivirus) do not preclude the malicious DLL loading.

## False Positives

Potential benign activities that could trigger false alerts include:

- Legitimate software updates or patches modifying LSASS settings.
- Misconfigured applications attempting to interact with security services.
- Scheduled tasks performing routine maintenance operations on system processes.

## Priority

**Priority:** High  
**Justification:** The exploitation of LSASS can lead to severe privilege escalation, persistence, and evasion capabilities, significantly impacting the overall security posture. Given the high impact and stealth potential, it is critical to detect and respond promptly to such activities.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Set Up a Controlled Environment:**
   - Use a virtual machine or isolated network segment with Windows OS.
   
2. **Modify Registry for LSASS Driver Loading:**
   ```powershell
   reg add HKLM\SYSTEM\CurrentControlSet\Services\lsass /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\System32\lsass.exe -l C:\malicious.dll" /f
   ```

3. **Monitor Event Logs:**
   - Check for security events related to process creation (Event ID 4688) and registry changes.

4. **Verify Detection Triggers:**
   - Ensure that the alert system captures and flags the unauthorized DLL loading attempt.

## Response

When an alert fires:

1. **Immediate Isolation:** Quarantine the affected machine from the network to prevent lateral movement.
2. **Detailed Investigation:**
   - Review event logs for additional suspicious activities.
   - Examine registry changes and confirm unauthorized modifications.
3. **Remediation Steps:**
   - Revert registry changes and restore LSASS settings to default.
   - Conduct a full system scan using updated antivirus definitions.

## Additional Resources

Additional references and context are not available at this time. However, staying informed about the latest security advisories from Microsoft and industry experts is recommended for ongoing threat intelligence updates.

---

This report provides an overview of detecting attempts to exploit LSASS as per the ADS framework, outlining strategies, technical context, validation steps, and response guidelines to effectively manage associated risks.