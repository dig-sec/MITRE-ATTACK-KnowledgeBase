# Detection Strategy Report: Detecting Web Shell Deployment

## Goal
The objective of this detection strategy is to identify adversarial attempts to deploy web shells on compromised systems. A web shell allows an attacker to maintain persistent access and control over a target system via the web, often bypassing traditional security monitoring mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1505.003 - Web Shell
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Linux, Windows, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1505/003)

## Strategy Abstract
The detection strategy leverages multiple data sources to identify the presence of web shells. Key data sources include:
- **File Integrity Monitoring (FIM):** Tracks changes in critical directories where web files are stored.
- **Network Traffic Analysis:** Monitors unusual outbound traffic patterns indicating a potential command-and-control (C2) communication.
- **Log Analysis:** Reviews HTTP/S logs for suspicious requests or uploads, particularly in writable directories such as `/var/www`, `wwwroot`, or equivalent locations on Windows systems.

The strategy looks for patterns indicative of web shell activity:
- Creation of unusual files with extensions like `.php`, `.asp`, `.jsp` in web-accessible directories.
- Uncommon user-agent strings and query parameters used during file upload requests.
- Persistent, repetitive network connections to known C2 IP addresses or domains from the server.

## Technical Context
Adversaries typically deploy web shells by exploiting vulnerabilities on a web server or uploading malicious scripts through misconfigured file permissions. Once uploaded, they can execute commands remotely and manipulate the system further.

### Real-world Execution:
1. **Vulnerability Exploitation:** Attackers exploit known software vulnerabilities (e.g., CVEs) to gain initial access.
2. **Upload of Web Shell:** They upload a script designed to be executed via web requests.
3. **Persistence and Control:** The attacker uses the web shell for further actions, such as data exfiltration or lateral movement.

### Emulation Details:
- Use tools like `curl` or `wget` to simulate file uploads:  
  ```bash
  curl -X POST http://victim-server/upload.php --data-binary @webshell.php
  ```

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Encrypted traffic analysis may not be feasible without decryption capabilities.
  - Advanced adversaries may use legitimate or randomized user-agent strings to evade detection.

- **Assumptions:**
  - The baseline of normal behavior is well-defined.
  - File integrity monitoring covers all critical web directories.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate file uploads by system administrators or during software updates, especially in environments where file permissions might be temporarily broadened for maintenance.
- Automated scripts used for legitimate testing purposes within development environments.

## Priority
**Severity: High**
The deployment of a web shell is considered a high-severity threat due to its potential to provide persistent access and facilitate extensive malicious activities. The ability of attackers to execute commands remotely and potentially exfiltrate sensitive data justifies the prioritization.

## Validation (Adversary Emulation)
### Steps to Emulate Web Shell Deployment:
1. **Setup Environment:**
   - Deploy a web server on Linux, Windows, or macOS with writable directories accessible via HTTP.
   
2. **Simulate Vulnerability:**
   - Allow file uploads without proper authentication or validation.

3. **Web Shell Upload:**
   ```bash
   curl -X POST http://test-server/upload.php --data-binary @webshell.php
   ```

4. **Test Execution:**
   - Access the web shell via a browser or command line:
     ```
     http://test-server/webshell.php?cmd=whoami
     ```

5. **Observe Detection Triggers:**
   - Monitor FIM alerts, network traffic anomalies, and suspicious log entries.

## Response
When an alert indicating potential web shell deployment fires, analysts should:
1. **Immediate Isolation:** Disconnect the affected server from the network to prevent further access.
2. **Incident Analysis:** Review logs and file changes to confirm the presence of a web shell.
3. **Forensic Investigation:** Determine the entry point and extent of compromise.
4. **Remediation:** Remove any malicious files, patch vulnerabilities, and restore clean versions of affected systems.

## Additional Resources
- [Understanding Web Shells](https://www.crowdstrike.com/blog/detecting-and-disabling-web-shells/)
- [Suspicious File Activity Monitoring Techniques](https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-suspicious-copy)

This report provides a comprehensive framework for detecting web shell deployment using Palantir's Alerting & Detection Strategy, ensuring robust security monitoring and incident response.