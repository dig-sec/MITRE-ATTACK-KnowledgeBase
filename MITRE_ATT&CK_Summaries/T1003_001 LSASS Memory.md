# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using LSASS Memory Dumps

## Goal
The technique aims to detect adversarial attempts to bypass security monitoring by extracting credentials from the LSASS (Local Security Authority Subsystem Service) memory on Windows platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1003.001 - LSASS Memory
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1003/001)

## Strategy Abstract
This detection strategy focuses on monitoring processes that attempt to access the memory of the LSASS process. The strategy leverages various data sources including:
- Process creation events
- Memory dump activities
- Command line executions

Patterns analyzed include suspicious execution of tools like Mimikatz, ProcDump, and others known for performing memory dumps or credential extraction from LSASS.

## Technical Context
Adversaries typically execute this technique to extract sensitive information such as passwords stored in the Windows Credential Manager. Common methods include:
- Using third-party tools like Mimikatz, ProcDump, or PowerShell scripts.
- Leveraging native Windows utilities that can perform memory dumps (e.g., Task Manager, Sysinternals Suite).

### Adversary Emulation Details
- **Commands:**
  - `mimikatz # lsadump::dcsync /user:administrator`
  - `procdump.exe -accepteula -ma lsass.exe c:\lsass.dmp`
- **Test Scenarios:**
  - Execute a PowerShell script that mimics downloading and executing Mimikatz.
  - Use Sysinternals tools to generate LSASS memory dumps.

## Blind Spots and Assumptions
- The strategy assumes that all unauthorized attempts to access LSASS memory are malicious, which may not always be the case.
- False negatives might occur if adversaries use novel or unknown methods for accessing LSASS memory.
- Limited visibility into encrypted network traffic can obscure detection of remote command execution.

## False Positives
Potential benign activities include:
- Legitimate administrative tasks requiring LSASS access for troubleshooting.
- Authorized security assessments and penetration testing exercises.
- Misconfigured software that inadvertently accesses LSASS memory.

## Priority
**High.** The severity is justified due to the critical nature of credentials stored in LSASS, which can provide adversaries with extensive system access if compromised.

## Validation (Adversary Emulation)
1. **Dump LSASS.exe Memory using ProcDump:**
   - Execute `procdump.exe -accepteula -ma lsass.exe c:\lsass.dmp`.
2. **Dump LSASS.exe Memory using comsvcs.dll:**
   - Use a PowerShell script that imports and executes the necessary functions from `comsvcs.dll` to dump LSASS.
3. **Dump LSASS.exe Memory using direct system calls and API unhooking:**
   - Develop or use existing tools/scripts that hook into APIs to extract memory directly.
4. **Dump LSASS.exe Memory using NanoDump:**
   - Execute the NanoDump tool with appropriate permissions.
5. **Dump LSASS.exe Memory using Windows Task Manager:**
   - Use Task Manager to create a dump file of the LSASS process.
6. **Offline Credential Theft With Mimikatz:**
   - Run `mimikatz # lsadump::dcsync /user:administrator`.
7. **LSASS read with pypykatz:**
   - Execute `pypykatz.exe --minidump lsass.dmp`.
8. **Dump LSASS.exe Memory using Out-Minidump.ps1:**
   - Run the PowerShell script to create a minidump of LSASS.
9. **Create Mini Dump of LSASS.exe using ProcDump:**
   - Similar to step 1, use ProcDump for creating mini dumps.
10. **Powershell Mimikatz:**
    - Execute Mimikatz commands through PowerShell.
11. **Dump LSASS with createdump.exe from .Net v5:**
    - Use `createdump.exe` to dump the memory of LSASS.
12. **Dump LSASS.exe using imported Microsoft DLLs:**
    - Utilize scripts that leverage Microsoft DLLs for dumping memory.
13. **Dump LSASS.exe using lolbin rdrleakdiag.exe:**
    - Execute `rdrleakdiag.exe` to access and dump LSASS memory.
14. **Dump LSASS.exe Memory through Silent Process Exit:**
    - Use techniques that exit processes silently after dumping memory.

## Response
When an alert fires:
1. Isolate the affected system to prevent further unauthorized access.
2. Initiate a forensic investigation to determine the scope of the breach.
3. Collect and preserve evidence for further analysis.
4. Review logs to identify the source and method of the attack.
5. Update security controls and policies to mitigate similar future attempts.

## Additional Resources
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious Program Names
- Suspicious PowerShell Download and Execute Pattern
- Malicious PowerShell Commandlets - ProcessCreation
- HackTool - Mimikatz Execution
- PowerShell Web Download
- Usage Of Web Request Commands And Cmdlets
- Use Short Name Path in Command Line
- HackTool - XORDump Execution
- Suspicious Script Execution From Temp Folder
- LSASS Dump Keyword In CommandLine
- Potential Execution of Sysinternals Tools
- Procdump Execution
- Process Memory Dump Via Comsvcs.DLL
- PowerShell Get-Process LSASS
- Potentially Suspicious PowerShell Child Processes
- Potentially Suspicious Rundll32 Activity
- Renamed ProcDump Execution
- Potential LSASS Process Dump Via Procdump

This report provides a comprehensive overview of the detection strategy for identifying attempts to access LSASS memory, including technical details, validation steps, and response guidelines.