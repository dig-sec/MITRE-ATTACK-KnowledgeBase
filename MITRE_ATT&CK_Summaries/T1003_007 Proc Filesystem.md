# Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by accessing process memory to extract credentials and sensitive information.

---

## Categorization
- **MITRE ATT&CK Mapping:** T1003.007 - Proc Filesystem
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1003/007)

---

## Strategy Abstract
The detection strategy focuses on identifying unauthorized access to the `/proc` filesystem, which is often leveraged by adversaries for credential dumping. Key data sources include system logs (e.g., auditd, syslog), file integrity monitoring, and network traffic analysis.

Patterns analyzed involve:
- Unusual or unexpected reads from the `/proc/[pid]/mem` path.
- Access to sensitive directories like `/proc/<process_id>/task`.
- Abnormal process behavior indicative of credential harvesting tools.

---

## Technical Context
Adversaries typically execute this technique by directly accessing files within the `/proc` directory associated with other processes, such as `password`, `cmdline`, and `environ`. This can be achieved using commands like:
```bash
cat /proc/$(pidof target_process)/mem | grep -a 'target_string'
```
Adversary emulation might involve testing tools such as Mimikatz or custom scripts designed to extract sensitive data.

---

## Blind Spots and Assumptions
- **Blind Spots:**
  - Encrypted traffic may mask certain access attempts.
  - Some legitimate applications might legitimately need to read `/proc` for functionality, complicating detection.
  
- **Assumptions:**
  - The environment is assumed to have adequate logging and monitoring capabilities.
  - Tools or scripts used by adversaries are not entirely new or unknown.

---

## False Positives
Potential benign activities triggering false alerts include:
- Legitimate system utilities performing maintenance tasks (e.g., backup tools).
- Automated scripts running administrative functions that involve `/proc` access.
  
To mitigate false positives, context awareness and behavior baselining should be applied.

---

## Priority
**Severity: High**

Justification: Credential dumping is a critical threat as it can lead directly to privilege escalation or lateral movement within the network. The potential impact on confidentiality and integrity makes prompt detection and response essential.

---

## Validation (Adversary Emulation)
### Step-by-step Instructions:

1. **Dump Individual Process Memory with sh (Local)**
   - Execute: `sh -c 'cat /proc/$(pidof target_process)/mem | grep "password"'`
   
2. **Dump Individual Process Memory with sh on FreeBSD (Local)**
   - Execute: `sh -c 'cat /proc/$$/mem | grep "password"'`

3. **Dump Individual Process Memory with Python (Local)**
   ```python
   import os
   target_pid = int(os.popen('pidof target_process').read().strip())
   with open(f'/proc/{target_pid}/mem', 'rb') as mem:
       data = mem.read()
       # Analyze memory for specific patterns.
   ```

4. **Capture Passwords with Mimikatz**
   - Execute: `mimikatz.exe "privilege::debug sekurlsa::logonpasswords"`

---

## Response
When an alert fires, analysts should:
- Immediately isolate the affected system to prevent further data exfiltration.
- Conduct a detailed investigation to determine the scope and method of the breach.
- Review process access logs for suspicious activities correlating with `/proc` access.
- Assess and patch potential vulnerabilities that allowed unauthorized access.

---

## Additional Resources
- **Execution Of Script Located In Potentially Suspicious Directory:** Analyze scripts in unexpected directories for malicious intent or behavior.
  
Ensure continuous monitoring, regular audits of privileged operations, and implement security controls to limit access to the `/proc` filesystem.