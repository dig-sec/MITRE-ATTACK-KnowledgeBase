# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Process Discovery Techniques

## **Goal**
This technique aims to detect adversarial attempts to bypass security monitoring systems by leveraging process discovery methods on host machines.

---

## **Categorization**

- **MITRE ATT&CK Mapping:** T1057 - Process Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows

For more details on the MITRE ATT&CK framework reference:
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1057)

---

## **Strategy Abstract**
The detection strategy focuses on identifying anomalous usage patterns of native process discovery tools and commands across various operating systems. It utilizes logs from system monitoring solutions, network traffic analysis, and endpoint security data to detect unusual or unauthorized attempts at discovering running processes.

Key data sources include:
- Syslog and event logs
- Endpoint Detection and Response (EDR) alerts
- Network flow data

Patterns analyzed for detection involve:
- Uncommon execution of process discovery commands during off-hours
- Elevated privileges associated with command usage
- Execution of multiple or chained process discovery tools in rapid succession

---

## **Technical Context**
Adversaries often use native system utilities to discover running processes on a target machine as part of reconnaissance. This can be an initial step to identify critical services, user accounts, and other potentially exploitable assets.

### Common Adversary Techniques:
- Executing `ps`, `tasklist`, or `Get-Process` commands
- Utilizing WMI queries with `get-wmiObject` or `wmic process`
- Running third-party tools like Process Hacker or PC Hunter

Adversaries might leverage elevated privileges to access detailed information about system processes. They may also employ obfuscation techniques to hide their activities, such as altering command syntax or using encoded strings.

---

## **Blind Spots and Assumptions**
- The strategy assumes all process discovery tool usage is logged accurately across the platforms.
- It does not account for zero-day exploits that might evade logging mechanisms.
- Adversaries with root-level access might manipulate logs to hide their activities.
- Tools or commands not covered in the known detection patterns may go undetected.

---

## **False Positives**
Potential benign activities that could trigger false alerts include:
- Legitimate system administration tasks during scheduled maintenance windows
- Usage of process discovery tools by security personnel for auditing purposes
- Execution of legitimate third-party applications requiring similar permissions or command executions

---

## **Priority**
**Severity: High**

Justification: Process discovery is often an early step in adversarial operations aimed at gaining deeper insights into system architecture and identifying valuable targets. Detecting these attempts promptly can prevent further exploitation.

---

## **Validation (Adversary Emulation)**
To emulate this technique, the following steps can be performed in a controlled test environment:

1. **Process Discovery - ps:**
   ```bash
   ps aux
   ```
2. **Process Discovery - tasklist:**
   ```cmd
   tasklist /v
   ```
3. **Process Discovery - Get-Process (PowerShell):**
   ```powershell
   Get-Process | Select-Object Id, ProcessName, CPU
   ```
4. **Process Discovery - get-wmiObject:**
   ```powershell
   get-wmiobject Win32_Process | Format-Table ProcessId, Name
   ```
5. **Process Discovery - wmic process:**
   ```cmd
   wmic process list brief
   ```
6. **Discover Specific Process - tasklist:**
   ```cmd
   tasklist /fi "imagename eq explorer.exe"
   ```
7. **Process Discovery - Process Hacker:** (Requires installation)
   Open and explore running processes.
8. **Process Discovery - PC Hunter:** (Requires installation)
   Use to search for specific processes.

9. **Launch Taskmgr from cmd to View Running Processes:**
   ```cmd
   start taskmgr
   ```

---

## **Response**
When an alert triggers:
- Immediately investigate the context and user account initiating the command.
- Verify if there is a legitimate reason or scheduled maintenance explaining the activity.
- If malicious intent is suspected, escalate to incident response teams for further action.
- Isolate affected systems if necessary to prevent lateral movement by adversaries.

---

## **Additional Resources**
For further reading and context:
- LSASS Process Reconnaissance Via Findstr.EXE
- Recon Command Output Piped To Findstr.EXE
- Suspicious Tasklist Discovery Command
- Process Reconnaissance Via Wmic.EXE
- Suspicious Tasklist Discovery Command

These resources provide additional examples of how adversaries may use process discovery techniques and should be considered when refining detection capabilities.

---

This report outlines the ADS framework for detecting adversarial process discovery attempts, focusing on strategic alignment with known adversary behaviors while acknowledging potential limitations and false positives.