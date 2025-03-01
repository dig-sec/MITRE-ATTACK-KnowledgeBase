# Alerting & Detection Strategy (ADS) for Credential Access via Web Browsers

## Goal
This technique aims to detect adversarial attempts to access and potentially exfiltrate credentials stored in web browsers on various platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1555.003 - Credentials from Web Browsers
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1555/003)

## Strategy Abstract
The detection strategy involves monitoring multiple data sources, including browser artifacts, process activity logs, and file access patterns. We analyze indicators such as unauthorized access to browser storage files (e.g., `Login Data` in Chrome, cookies in Safari), execution of known credential harvesting tools like LaZagne, and suspicious processes that interact with these files.

Key patterns analyzed include:
- Access or modification of browser data directories.
- Execution of scripts or binaries known for credential extraction.
- Network activity indicating potential exfiltration of sensitive data.

## Technical Context
Adversaries often execute this technique by leveraging tools like LaZagne, WebBrowserPassView, and BrowserStealer to extract credentials stored in web browsers. These tools can access browser storage files directly on the filesystem or through APIs provided by the operating system.

### Adversary Emulation Details:
- **Commands/Sample Scenarios:**
  - Use of `LaZagne` to dump credentials from various browsers.
  - Direct file manipulation using scripts to extract Chrome's `Login Data`.
  - Deployment of tools like `WebBrowserPassView` and `Firepwd.py` for credential extraction.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Encrypted browser storage files that are not decrypted by the adversary.
  - Use of anti-detection mechanisms to avoid triggering alerts.
  
- **Assumptions:**
  - The presence of known tools or scripts in file access logs.
  - Normal user behavior does not include accessing credential storage for malicious purposes.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate use of password management software like LastPass or KeePass, which may interact with browser data.
- System administrators performing maintenance tasks involving browser data.
- Users manually inspecting their own browser settings and credentials.

## Priority
**Severity: High**

Justification: Credentials are a critical asset that can provide adversaries with access to sensitive information and systems. The potential impact of credential theft is significant, making it imperative to detect and respond promptly to such activities.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **Run Chrome-password Collector:**
   - Simulate extraction of credentials from Chrome on Linux/macOS/Windows.

2. **Search macOS Safari Cookies:**
   - Access and list cookies stored by Safari.

3. **LaZagne - Credentials from Browser:**
   - Execute LaZagne to dump credentials from installed browsers.

4. **Simulating access to Chrome Login Data:**
   - Use scripts or tools to access `Login Data` files in Chrome's directory.

5. **Simulating access to Opera, Firefox, and Edge Login Data:**
   - Repeat similar steps for other browsers like Opera, Firefox, and Microsoft Edge.

6. **Decrypt Mozilla Passwords with Firepwd.py:**
   - Use Firepwd.py to decrypt stored Firefox passwords.

7. **LaZagne.py - Dump Credentials from Firefox Browser:**
   - Execute LaZagne to extract credentials specifically from Firefox.

8. **Stage Popular Credential Files for Exfiltration:**
   - Simulate the preparation of browser credential files for exfiltration.

9. **WinPwn Tools:**
   - Use `BrowserPwn`, `Loot local Credentials - mimi-kittenz`, and `PowerSharpPack - Sharpweb` to extract credentials on Windows systems.

10. **Simulating Access to Chrome Login Data - MacOS:**
    - Repeat access simulations for macOS environments.

11. **WebBrowserPassView - Credentials from Browser:**
    - Use WebBrowserPassView to retrieve browser-stored passwords.

12. **Dump Chrome Login Data with esentutl:**
    - Utilize `esentutl` to extract data from Chrome's SQLite database files.

13. **BrowserStealer (Chrome / Firefox / Microsoft Edge):**
    - Deploy BrowserStealer to harvest credentials across multiple browsers.

## Response
When an alert is triggered, analysts should:
- Immediately isolate the affected system to prevent further unauthorized access.
- Conduct a detailed investigation to determine the scope and method of credential access.
- Review logs for additional indicators of compromise or lateral movement within the network.
- Notify relevant stakeholders and initiate incident response protocols if necessary.

## Additional Resources
For further context and detection enhancement, consider reviewing:
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Usage Of Web Request Commands And Cmdlets
- Copying Sensitive Files with Credential Data
- Potential Browser Data Stealing Patterns
- HackTool - LaZagne Execution

These resources provide additional insights into related techniques and tools that adversaries may use in conjunction with credential access from web browsers.