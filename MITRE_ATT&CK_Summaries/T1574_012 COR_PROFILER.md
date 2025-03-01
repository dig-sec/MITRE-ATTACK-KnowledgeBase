# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts Using COR_PROFILER

## Goal
The objective of this technique is to detect adversarial attempts to bypass security monitoring by leveraging .NET's Common Language Runtime (CLR) profiling API through the use of `COR_PROFILER`. This can be used for persistence, privilege escalation, and defense evasion on Windows platforms.

## Categorization
- **MITRE ATT&CK Mapping:** [T1574.012 - COR_PROFILER](https://attack.mitre.org/techniques/T1574/012)
- **Tactic / Kill Chain Phases:**
  - Persistence
  - Privilege Escalation
  - Defense Evasion
- **Platforms:** Windows

## Strategy Abstract
This detection strategy focuses on identifying the use of `COR_PROFILER` by monitoring relevant data sources and analyzing specific patterns. Key data sources include:

- **Windows Event Logs**: Look for events related to profiler changes.
- **File System Monitoring**: Detect any changes or creations of `.config` files that specify a custom profiler.
- **Process Creation and Execution**: Monitor processes attempting to set `COR_PROFILER`.
- **Registry Monitoring**: Observe modifications in the registry keys associated with `COR_PROFILER`.

Patterns analyzed include unusual process behaviors, unexplained changes in configuration files, and unauthorized changes in Windows Registry settings related to .NET profiling.

## Technical Context
Adversaries may exploit the CLR Profiler API to execute code in the context of legitimate processes, thus evading detection. The technique involves configuring a target application's configuration file or modifying the registry to use a custom profiler DLL. This can be executed via scripts or manual changes by an attacker who has gained some level of access.

### Adversary Emulation Details
- **Sample Command:** Modify a `.config` file to include `<processProfiling enabled="1" path="%SystemRoot%\SysWOW64\profiler.dll"/>`.
- **Registry Modification:** Set the `UseManagedPerfCounterProvider` key under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework`.

## Blind Spots and Assumptions
- Assumes that legitimate .NET applications are not using `COR_PROFILER`. False positives may occur if legitimate profiling is in use.
- Detection might miss attacks if adversaries dynamically load the profiler or if changes are made outside monitored data sources.
- Assumes a typical Windows environment without custom configurations that could obscure detection.

## False Positives
Potential benign activities include:
- Legitimate developers using `COR_PROFILER` for debugging or performance monitoring.
- System updates or software installations that temporarily modify configuration files or registry settings related to .NET profiling.

## Priority
**Priority: High**

Justification:
The ability of adversaries to use `COR_PROFILER` for persistence and evasion poses a significant threat. Its potential to be leveraged by sophisticated attackers makes it critical to monitor closely, despite the risk of false positives from legitimate uses.

## Validation (Adversary Emulation)
### User Scope COR_PROFILER
1. Open Notepad or any text editor.
2. Create a new `.config` file and insert:
   ```xml
   <configuration>
     <runtime>
       <processProfiling enabled="1" path="%SystemRoot%\SysWOW64\profiler.dll"/>
     </runtime>
   </configuration>
   ```
3. Save the file in an application directory.

### System Scope COR_PROFILER
1. Open Registry Editor (`regedit.exe`).
2. Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework`.
3. Create a new DWORD value named `UseManagedPerfCounterProvider` and set it to `1`.

### Registry-free Process Scope COR_PROFILER
1. Run a command prompt as an administrator.
2. Execute:
   ```cmd
   rundll32.exe "%SystemRoot%\SysWOW64\profiler.dll",CreateProfile
   ```

Ensure all actions are performed in a controlled test environment to avoid unintended system changes.

## Response
When the alert fires, analysts should:

1. **Verify Legitimacy**: Confirm if the use of `COR_PROFILER` is legitimate or malicious.
2. **Isolate Affected Systems**: Quarantine affected systems to prevent further spread.
3. **Investigate Changes**: Examine recent changes in configuration files and registry settings.
4. **Review Logs**: Analyze logs for unusual activities related to process creation and execution.
5. **Alert Security Team**: Inform the security team for a coordinated response.

## Additional Resources
- [MITRE ATT&CK Technique: T1574.012 - COR_PROFILER](https://attack.mitre.org/techniques/T1574/012)

---

This report provides a comprehensive guide to detecting and responding to adversarial use of `COR_PROFILER` within the Palantir ADS framework.