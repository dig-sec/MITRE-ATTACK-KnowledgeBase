# Alerting & Detection Strategy (ADS) for Detecting Adversarial Use of Compiled HTML Help Files on Windows

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using compiled HTML help (.chm) files. This includes leveraging these files for executing malicious payloads through various methods such as remote execution, script invocation, and exploiting the .chm file format's capabilities to deliver obfuscated code.

## Categorization

- **MITRE ATT&CK Mapping:** T1218.001 - Compiled HTML File
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1218/001)

## Strategy Abstract

The detection strategy involves monitoring and analyzing specific behaviors associated with the use of compiled HTML help files (.chm) that may indicate adversarial activity. Data sources include file access logs, process creation events, network traffic, and registry changes. Key patterns to analyze are:

- Execution of `hh.exe`, which is used to open .chm files.
- Unusual network downloads of .chm files from remote locations.
- Abnormal script execution within a .chm file, such as invoking scripts through the InfoTech Storage Protocol or using alternate data streams.

## Technical Context

Adversaries exploit the functionality of .chm files by embedding malicious code or payloads that execute when the file is opened. They can use `hh.exe` to load these payloads, leveraging shortcuts and protocols (e.g., the ITStorage protocol) to trigger execution via command-line parameters or double-clicking simulated events.

### Adversary Emulation Details
Adversaries might employ techniques such as:

- **Remote CHM Payload Delivery:** Download a .chm file containing malicious scripts from a remote server.
- **Shortcut Command Execution:** Use `hh.exe` with specific arguments to execute payloads directly.
- **InfoTech Storage Protocol Handler:** Invoke script engines (like VBScript or JavaScript) embedded within the .chm file.

## Blind Spots and Assumptions

Known limitations include:

- Legitimate use of .chm files in enterprise environments for documentation, which may generate benign alerts.
- Dependence on accurate logging and monitoring of `hh.exe` execution paths and parameters.
- Difficulty in distinguishing between legitimate and malicious payloads without detailed inspection.

Assumptions:
- The environment maintains comprehensive logs of file access and network activity.
- Organizations have baseline knowledge of typical .chm usage patterns within their infrastructure.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate use of .chm files for software help documentation.
- Routine installation or update processes involving .chm files.
- User actions such as opening or exploring .chm files in a non-malicious context.

## Priority
**High**

Justification: The technique is prioritized highly due to its potential to bypass traditional security controls by leveraging a commonly overlooked vector. Given the increasing sophistication of adversaries, it's crucial to detect and mitigate these evasion tactics promptly.

## Validation (Adversary Emulation)

To validate this detection strategy in a controlled test environment, follow these steps:

1. **Compiled HTML Help Local Payload**
   - Create a .chm file with embedded script that executes upon opening.
   
2. **Compiled HTML Help Remote Payload**
   - Download a remote .chm file known to contain a payload and execute it using `hh.exe`.

3. **Invoke CHM with Default Shortcut Command Execution**
   - Use `hh.exe /i <file.chm>` to test shortcut-based command execution.

4. **Invoke CHM with InfoTech Storage Protocol Handler**
   - Execute a .chm file containing VBScript or JavaScript via ITStorage protocol: 
     ```shell
     rundll32 url.dll,FileProtocolHandler itststorage:<embedded_payload>
     ```

5. **Invoke CHM Simulate Double click**
   - Create a script to simulate double-click events on a .chm file.

6. **Invoke CHM with Script Engine and Help Topic**
   - Use `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write('');close()` to execute scripts within the .chm file.

7. **Invoke CHM Shortcut Command with ITS and Help Topic**
   - Combine InfoTech Storage protocol with specific help topics: 
     ```shell
     hh.exe <file.chm> /i itststorage:<payload>
     ```

8. **Decompile Local CHM File**
   - Use tools like `chmlint` to extract content from a .chm file and inspect for embedded malicious code.

## Response

When an alert fires, analysts should:

1. Isolate the affected system to prevent further spread of potential threats.
2. Analyze logs to confirm the nature of the activity—determine if it was benign or adversarial.
3. Review network traffic associated with .chm file downloads for suspicious activity.
4. Use endpoint detection and response (EDR) tools to identify and contain malicious processes initiated by `hh.exe`.
5. Update security policies to prevent unauthorized .chm file execution where possible.

## Additional Resources

For further context and technical details, consider the following resources:

- HH.EXE Execution
- Suspicious HH.EXE Execution
- Remote CHM File Download/Execution Via HH.EXE

These references provide additional insight into how adversaries might exploit .chm files and offer guidance on enhancing detection capabilities.