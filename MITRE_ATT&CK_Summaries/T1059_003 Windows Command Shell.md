# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## **Goal**
The aim of this detection strategy is to identify adversarial attempts to execute unauthorized commands and scripts on Windows systems via command shells. This includes detecting activities such as script execution, command prompt usage for malicious purposes, and other suspicious behaviors typically associated with tactics like ransomware deployment or lateral movement.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1059.003 - Windows Command Shell
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1059/003)

## **Strategy Abstract**
This detection strategy leverages logs from various data sources, including Windows Event Logs (such as Security and Application), Sysmon logs, and command-line history to detect suspicious command shell activities. The primary patterns analyzed include:
- Execution of unusual or non-standard commands.
- Creation and execution of batch scripts outside typical user workflows.
- Unusual command redirections that indicate potential data exfiltration or manipulation.

## **Technical Context**
Adversaries often use Windows Command Shells for executing malicious scripts, automating tasks like credential dumping, lateral movement within the network, and deploying ransomware. Techniques include:
- Creating batch files to execute malicious commands.
- Using PowerShell or CMD.exe with non-standard flags or redirections.
- Utilizing built-in tools in unexpected ways (e.g., `whoami.exe` for privilege escalation).

**Adversary Emulation Details:**
- Sample Commands: Running scripts like `cmd /c <malicious_command>`, `powershell -exec bypass -windowstyle hidden -command <malicious_script>`
- Test Scenarios: Creating batch files with malicious payloads, simulating ransomware behaviors such as print bombing.

## **Blind Spots and Assumptions**
- Assumes all command shell activities are logged correctly and comprehensively.
- Potential blind spots include encrypted or obfuscated command executions that bypass logging mechanisms.
- Relies on the assumption that deviations from normal behavior patterns are indicative of malicious activity.

## **False Positives**
- Legitimate administrative scripts running during maintenance windows.
- Scheduled tasks using command shells for system management.
- Users executing custom, non-malicious batch files or PowerShell scripts.

## **Priority**
**Severity: High**

Justification:
- Command shell activities are a common vector for initial access and execution of payloads.
- Early detection can prevent escalation and lateral movement within the network.
- The potential impact includes data exfiltration, system compromise, and ransomware deployment.

## **Validation (Adversary Emulation)**
### Step-by-step Instructions to Emulate this Technique in a Test Environment:

1. **Create and Execute Batch Script:**
   - Create a batch file named `test.bat` with the command `echo Hello > output.txt`.
   - Execute using `cmd /c test.bat`.

2. **Suspicious Execution via Windows Command Shell:**
   - Use PowerShell to run a suspicious command: `powershell -exec bypass -windowstyle hidden -command "whoami"`.

3. **Simulate BlackByte Ransomware Print Bombing:**
   - Create a script that mimics ransomware behavior: `for /l %i in (1,1,100) do echo This is a print bomb > \\server\share\printbomb.txt`.

4. **Command Prompt Read Contents from CMD File and Execute:**
   - Write commands to a file `commands.cmd`: `dir C:\ > dir_output.txt`.
   - Execute using `cmd /c @commands.cmd`.

5. **Command Prompt Writing Script to File then Executes it:**
   - Create a script with `echo Set WshShell = WScript.CreateObject("WScript.Shell") >> autoexec.vbs` followed by execution commands.
   - Run the script using `wscript.exe autoexec.vbs`.

## **Response**
When an alert triggers:
- Immediately isolate affected systems to prevent further spread.
- Investigate logs for command history and identify any unusual patterns or behaviors.
- Preserve evidence for forensic analysis, including copies of executed scripts and command outputs.
- Update detection rules based on findings to reduce false positives.

## **Additional Resources**
- [Whoami.EXE Execution With Output Option](https://attack.mitre.org/techniques/T1060/)
- [Read Contents From Stdin Via Cmd.EXE](https://attack.mitre.org/techniques/T1059.001/)
- [Potentially Suspicious CMD Shell Output Redirect](https://attack.mitre.org/techniques/T1071/002/)

This report provides a comprehensive overview of the strategy to detect and respond to adversarial use of Windows Command Shells, leveraging Palantir's ADS framework for effective security monitoring and incident response.