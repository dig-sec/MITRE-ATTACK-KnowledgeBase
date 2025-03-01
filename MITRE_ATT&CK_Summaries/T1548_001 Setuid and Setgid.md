# Alerting & Detection Strategy: Detecting Adversarial Use of Setuid/Setgid

## **Goal**
This strategy aims to detect adversarial attempts to exploit setuid and setgid permissions on files for privilege escalation and defense evasion. By monitoring these activities, organizations can identify potential unauthorized access attempts that could compromise system security.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1548.001 - Setuid and Setgid
- **Tactic / Kill Chain Phases:** Privilege Escalation, Defense Evasion
- **Platforms:** Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1548/001)

## **Strategy Abstract**
The detection strategy leverages file integrity monitoring and system logs to identify changes in setuid and setgid permissions. By analyzing patterns such as unexpected permission modifications on binaries or unusual execution of files with elevated privileges, the strategy aims to detect malicious activities. Key data sources include system audit logs, process creation events, and file metadata changes.

## **Technical Context**
Adversaries may exploit setuid and setgid by modifying executable files to run with elevated privileges. This technique is often used in privilege escalation attacks where an adversary gains higher-level access than initially permitted. Common methods include:

- Compromising binaries with setuid/setgid permissions.
- Modifying existing executables or creating new ones with malicious code.

### Adversary Emulation Details
Adversaries might execute commands such as:
```bash
chmod u+s /path/to/binary  # Set the setuid bit on a file
chmod g+s /path/to/binary  # Set the setgid bit on a file
```

## **Blind Spots and Assumptions**
- Assumes baseline knowledge of normal system behavior for accurate detection.
- May not detect sophisticated attacks that mimic legitimate permission changes.
- Limited to environments where audit logging is enabled and properly configured.

## **False Positives**
Potential benign activities include:
- Legitimate administrative tasks requiring setuid/setgid modifications.
- System updates or patches that alter file permissions as part of maintenance.

## **Priority**
**High**: The potential impact of privilege escalation through misuse of setuid/setgid is significant, allowing adversaries to gain unauthorized access and control over critical systems.

## **Validation (Adversary Emulation)**
To validate this detection strategy in a controlled environment:

1. **Make and Modify Binary from C Source:**
   - Write a simple C program.
   - Compile it using `gcc`.
   - Use `chmod` to modify permissions.

2. **Set a SetUID Flag on File:**
   ```bash
   chmod u+s /path/to/binary
   ```

3. **Set a SetGID Flag on File:**
   ```bash
   chmod g+s /path/to/binary
   ```

4. **Make and Modify Binary from C Source (FreeBSD):**
   - Follow similar steps as Linux but ensure compatibility with FreeBSD's tools.

5. **Reconnaissance for Files with Setuid/Setgid Bits:**
   - Use commands like `find / -perm -4000` to locate files with setuid bits.
   - Similarly, use `find / -perm -2000` for setgid bits.

## **Response**
When an alert is triggered:
- Immediately isolate the affected system to prevent further exploitation.
- Review logs and audit trails to understand the scope of changes made.
- Conduct a thorough investigation to determine if unauthorized access occurred.
- Restore any compromised files from backups and apply necessary patches or updates.

## **Additional Resources**
For more information on setuid/setgid:
- [Setuid and Setgid Documentation](https://man7.org/linux/man-pages/man2/setuid.2.html)
- Use `find` command to identify files with specific permissions: 
  - Linux: `find / -perm -4000`
  - FreeBSD: Similar syntax as Linux.

This strategy provides a comprehensive approach to detecting and responding to the misuse of setuid and setgid, enhancing organizational security posture against privilege escalation threats.