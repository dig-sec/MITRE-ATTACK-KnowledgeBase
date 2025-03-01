# Palantir's Alerting & Detection Strategy: Path Interception by Search Order Hijacking

## Goal
The aim of this technique is to detect adversarial attempts to bypass security monitoring using search order hijacking on Windows systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1574.008 - Path Interception by Search Order Hijacking
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation, Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1574/008)

## Strategy Abstract
This detection strategy focuses on identifying manipulation of the search path order to intercept and execute malicious executables. The data sources include system logs (e.g., Event Logs), process execution monitoring, and file integrity checks. Patterns analyzed involve unusual modifications in environment variables that affect program paths (e.g., `PATH`, `PATHEXT`) and unexpected behaviors such as legitimate processes executing from unconventional locations.

## Technical Context
Path Interception by Search Order Hijacking is a technique where adversaries alter the search order of directories to intercept command execution. By modifying environment variables like `PATH` or `PATHEXT`, they can ensure their malicious executables are executed instead of intended ones. This approach is often used in combination with other persistence mechanisms.

### Adversary Emulation Details
Adversaries might execute commands such as:
```powershell
Set-Item Env:\Path "C:\malicious;$(Get-Item Env:\Path)"
```
This command modifies the `PATH` environment variable to prioritize a malicious directory.

## Blind Spots and Assumptions
- **Blind Spots:** Limited visibility into non-standard script execution methods or highly obfuscated commands.
- **Assumptions:** Assumes that changes in critical environment variables are logged accurately by security monitoring tools. Also assumes consistent logging of process initiation paths.

## False Positives
Potential benign activities triggering false alerts include:
- Administrators modifying system `PATH` for legitimate software installation.
- Software deployment scripts altering environment settings temporarily for configuration purposes.
- Legitimate use cases such as development environments where custom directories are added to the `PATH`.

## Priority
**Severity: High**

Justification: This technique allows adversaries to maintain persistence and escalate privileges undetected, severely impacting system integrity and security posture.

## Validation (Adversary Emulation)
To emulate this technique in a test environment using PowerShell for persistence via hijacking default modules:

1. **Set up the Test Environment:** Ensure you have a Windows machine with logging enabled.
2. **Modify PATH Variable:**
   ```powershell
   Set-Item Env:\Path "C:\TestMalicious;$(Get-Item Env:\Path)"
   ```
3. **Create Malicious Executable:**
   Place a benign or dummy executable in `C:\TestMalicious`.
4. **Trigger Execution:**
   Run a commonly used command (e.g., `notepad.exe`) to see if the malicious executable is executed.
5. **Verify Logs:**
   Check system logs for any execution anomalies indicating path hijacking.

## Response
When an alert fires:

1. **Confirm Alert Validity:** Verify whether the environment variable change was authorized and documented.
2. **Isolate Affected Systems:** Disconnect compromised systems from the network to prevent further spread.
3. **Investigate Changes:**
   - Review logs for unauthorized changes in environment variables.
   - Examine affected processes and their execution paths.
4. **Remediate Environment Variables:**
   - Restore original environment variable values.
5. **Enhance Monitoring:** Implement additional monitoring for critical environment variables to detect future attempts promptly.

## Additional Resources
Additional references and context are not available at this time, but further research into related MITRE ATT&CK techniques may provide more insight into advanced adversary tactics.