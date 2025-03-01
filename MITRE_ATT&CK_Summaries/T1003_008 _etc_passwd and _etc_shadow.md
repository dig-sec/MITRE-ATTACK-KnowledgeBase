# Alerting & Detection Strategy (ADS) Framework Report

## Goal
The objective of this detection strategy is to identify adversarial attempts to access and manipulate sensitive files such as `/etc/passwd`, `/etc/shadow`, and `/etc/master.passwd` on Linux systems. These files contain critical user account information, and unauthorized access can lead to credential theft or privilege escalation.

## Categorization
- **MITRE ATT&CK Mapping:** T1003.008 - [View Source Code](https://attack.mitre.org/techniques/T1003/008)
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux

## Strategy Abstract
This detection strategy leverages a combination of file integrity monitoring (FIM), audit logs, and user behavior analytics to identify unauthorized access attempts to sensitive files. The primary data sources include system logs (`/var/log/auth.log`, `/var/log/audit/audit.log`), kernel logs, and FIM alerts. Patterns analyzed involve unexpected accesses or modifications by non-administrative users, access from unusual locations (e.g., network shares), or through uncommon methods such as non-standard utilities.

## Technical Context
Adversaries commonly execute this technique by exploiting weak permissions, using rootkits to hide their tracks, or leveraging compromised accounts with elevated privileges. In real-world scenarios, they might use tools like `awk`, `sed`, or custom scripts to parse and modify these files without raising immediate suspicion.

### Adversary Emulation Details
- **Sample Commands:**
  - Reading `/etc/shadow`: `awk -F: '{print $1,$2}' /etc/shadow`
  - Modifying `/etc/passwd` using a script

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection might miss access attempts made through sophisticated obfuscation or rootkits.
  - If an attacker has already gained full control of the system, detection mechanisms may be bypassed.

- **Assumptions:**
  - Assumes standard logging configurations are in place and logs are regularly reviewed.
  - Relies on FIM being configured to monitor these critical files.

## False Positives
Potential false positives include:
- Legitimate administrative tasks that involve accessing or modifying these files, such as system maintenance or user management.
- Automated scripts running with elevated privileges for legitimate purposes (e.g., backup operations).

## Priority
**Severity: High**

Justification: Unauthorized access to `/etc/passwd`, `/etc/shadow`, and `/etc/master.passwd` can lead to severe security breaches, including privilege escalation and credential theft. These files are critical for maintaining system integrity and user account security.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Access `/etc/shadow` (Local)**
   - Use a non-standard utility: `awk -F: '{print $1,$2}' /etc/shadow`

2. **Access `/etc/master.passwd` (Local)**
   - If present, use `less /etc/master.passwd` or similar.

3. **Access `/etc/passwd` (Local)**
   - Use a shell builtin: `head /etc/passwd`

4. **Access with Non-Standard Bin**
   - Example: `sed 's/:x:/:/g' /etc/shadow > temp_shadow.txt`

5. **Access via Shell Builtins**
   - Example: `tail -n 10 /etc/passwd`

## Response
When the alert fires, analysts should:
1. Verify the legitimacy of the access by checking the user's role and recent activities.
2. Review logs to determine the source and method of access.
3. Assess any changes made to the files and reverse them if unauthorized.
4. Update security policies to prevent similar incidents in the future.
5. Conduct a thorough investigation to ensure no further compromise has occurred.

## Additional Resources
- **Execution Of Script Located In Potentially Suspicious Directory:** Investigate scripts or executables in unusual directories that may be used for privilege escalation or data exfiltration.

For more information, refer to [MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/008) and relevant security documentation on file integrity monitoring and audit logging best practices.