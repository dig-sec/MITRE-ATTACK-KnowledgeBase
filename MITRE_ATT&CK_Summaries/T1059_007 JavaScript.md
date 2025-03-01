# Alerting & Detection Strategy (ADS) Report: Detecting Adversarial JavaScript Execution Attempts

## Goal
This technique aims to detect adversarial attempts to execute malicious JavaScript on Windows, macOS, and Linux platforms using `cscript` and `wscript`. The primary goal is to identify unauthorized use of these scripting engines to perform actions like information gathering or executing further commands.

## Categorization
- **MITRE ATT&CK Mapping:** T1059.007 - JavaScript
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** Windows, macOS, Linux
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1059/007)

## Strategy Abstract
The detection strategy involves monitoring for execution patterns of `cscript` and `wscript`, which are scripting engines used to run JavaScript in a Windows environment. This includes:
- Analyzing logs from process creation events on Windows platforms.
- Monitoring script execution calls within command lines or batch files.
- Detecting unauthorized attempts to execute scripts with elevated permissions.

Data sources include system event logs, network traffic capturing script-related communications, and file integrity monitoring systems to detect changes in executable scripts.

## Technical Context
Adversaries leverage JavaScript execution via `cscript` or `wscript` for tasks such as:
- Information gathering about the local system.
- Executing commands that may lead to privilege escalation or lateral movement within a network.

Common adversarial tactics include obfuscating script contents, using encoded payloads, or executing scripts from temporary files to avoid detection. Commands typically involve leveraging PowerShell to execute `cscript` or `wscript`.

### Adversary Emulation Details
- **Sample Command:** `cscript /nologo "malicious_script.js"`
- **Test Scenarios:**
  - Execution of a JavaScript file using `cscript`.
  - Execution of a script with parameters that gather system information.

## Blind Spots and Assumptions
- Assumes all legitimate use cases of `cscript` and `wscript` are already whitelisted.
- Detection relies heavily on the presence of detailed logging and monitoring systems, which may not be comprehensive across all environments.
- Potential blind spots in non-Windows platforms where scripting is less commonly used.

## False Positives
Potential benign activities that could trigger alerts include:
- Legitimate administrative tasks using `cscript` or `wscript`.
- Scheduled tasks running approved scripts for automation purposes.
- Software installation processes utilizing these engines legitimately.

## Priority
**Severity:** Medium

Justification: While JavaScript execution via `cscript` and `wscript` can be a vector for adversaries, it is not as widely exploited compared to other script-based techniques. However, the potential impact of such actions warrants medium priority due to its ability to perform significant malicious activities if left unchecked.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Setup Test Environment:**
   - Ensure a controlled environment with logging enabled for process creation events.
   - Configure systems to log command executions and script execution attempts.

2. **Execute JScript Using `cscript`:**
   ```shell
   cscript /nologo "info_gather.js"
   ```
   - Observe logs for the execution of `cscript` with parameters pointing to a JavaScript file.

3. **Execute JScript Using `wscript`:**
   ```shell
   wscript "info_gather.js"
   ```
   - Similarly, monitor and record events triggered by `wscript`.

4. **Analyze Log Outputs:**
   - Validate that the system logs capture both command invocations.
   - Ensure any attempts to execute scripts with unusual or unauthorized parameters are flagged.

## Response
When an alert is triggered:
- Immediately review process execution logs for context, such as user initiating the script and source of the command.
- Evaluate if there are indications of compromise based on script contents and behavior.
- If confirmed malicious, initiate incident response protocols including containment, eradication, and recovery processes.

## Additional Resources
- **WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript:** Detailed analysis of file execution methods using Windows Scripting engines.
- **Potentially Suspicious CMD Shell Output Redirect:** Insights on detecting unusual command output redirections indicative of malicious activity.

By understanding and implementing this strategy, organizations can enhance their detection capabilities against the use of `cscript` and `wscript` for malicious purposes.