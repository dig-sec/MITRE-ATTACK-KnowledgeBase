# Alerting & Detection Strategy: Password Guessing (T1110.001)

## Goal
The primary aim of this detection strategy is to identify and alert on adversarial attempts to guess passwords across multiple platforms, including Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers, and more.

## Categorization

- **MITRE ATT&CK Mapping:** T1110.001 - Password Guessing
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1110/001)

## Strategy Abstract

The detection strategy involves monitoring for patterns indicative of password guessing attempts across various platforms. Key data sources include:

- **Windows Event Logs:** For failed login attempts and account lockout events.
- **Azure AD Sign-in Logs:** To identify repeated failed sign-ins or other anomalies in authentication behavior.
- **Office 365 Audit Logs:** For tracking failed logins to Office 365 services.
- **Linux/Unix Syslogs and Authentication Logs:** Monitoring `/var/log/auth.log` for failed SSH login attempts, etc.
- **Network Traffic Analysis:** Identifying unusual traffic patterns that might indicate brute force attempts over network protocols like SMB or LDAP.

The strategy focuses on detecting anomalies such as repeated failed logins using common credentials, rapid succession of authentication failures, and changes in user behavior indicative of credential guessing. Machine learning algorithms can be leveraged to identify deviations from normal usage patterns.

## Technical Context

Adversaries may execute password guessing through various methods, including:

- **Brute Force Attacks:** Using automated tools or scripts to attempt common passwords against user accounts.
- **Credential Stuffing:** Utilizing previously compromised credentials across different services.
- **Dictionary Attacks:** Testing a pre-defined list of potential passwords.

Real-world execution examples include:
- Running `crackmapexec smb` against Windows systems for SMB brute force attempts.
- Using `ldapsearch -xLLL -D "cn=admin,dc=example,dc=com" -W` with various password guesses against LDAP servers.

Adversaries often use common tools like Hydra, Medusa, or custom scripts to automate these attacks. They may also employ techniques such as using VPNs or Tor for anonymity and distributing attack vectors across multiple IP addresses to avoid detection.

## Blind Spots and Assumptions

- **Assumption of Normal Behavior:** The strategy assumes baseline user behavior is known and deviations are detectable.
- **Limited by User Awareness:** Users with high levels of failed login attempts due to forgetfulness may trigger false positives.
- **Network Complexity:** Distributed attacks might be masked within large organizations where multiple concurrent authentications are common.

## False Positives

Potential benign activities that might result in false alerts include:

- Legitimate users repeatedly entering incorrect passwords, especially if they have forgotten them.
- Automated scripts or applications with hardcoded credentials that periodically fail due to credential rotation policies.
- Network security tools performing authorized penetration tests or vulnerability assessments.

## Priority

The severity of this technique is assessed as **High**. The rationale includes the critical nature of gaining unauthorized access via credential compromise, which can lead to further exploitation such as data exfiltration or lateral movement within a network.

## Validation (Adversary Emulation)

Below are instructions to emulate password guessing attempts in a controlled environment:

1. **Brute Force Credentials of Single Active Directory Domain Users via SMB:**
   - Use tools like `crackmapexec smb` to target Windows systems.
   ```bash
   crackmapexec smb <target-IP> -u 'username' -d 'domain' -D 'password-list.txt'
   ```

2. **Brute Force Credentials of Single Active Directory Domain User via LDAP:**
   - Use `ldapsearch` with different passwords against the domain controller.
   ```bash
   ldapsearch -xLLL -H ldaps://<dc-ip> -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W
   ```

3. **Brute Force Credentials of Single Azure AD User:**
   - Use tools like `PasswordSpray` or custom scripts to automate password guessing.
   ```bash
   PasswordSpray.py --username admin@example.com --passwordfile path/to/passwords.txt --threads 10
   ```

4. **Password Brute Using Kerbrute Tool:**
   - Run against a list of domain users.
   ```bash
   kerbrute bruteuser <domain> path/to/users.txt -dc-ip <dc-ip> -t 50
   ```

5. **SUDO Brute Force - Debian/Redhat/FreeBSD:**
   - Use `John the Ripper` with a custom wordlist for sudo password guessing.
   ```bash
   sudo -l; john --wordlist=path/to/wordlist.txt /etc/sudoers.password
   ```

6. **ESXi - Brute Force Until Account Lockout:**
   - Utilize tools like `Hydra` to attempt multiple logins against an ESXi server.
   ```bash
   hydra -l root -P path/to/passwords.txt <esxi-ip> vpxy
   ```

## Response

Upon detection of a password guessing alert, analysts should:

1. **Verify the Alert:**
   - Confirm whether it is a legitimate attack or false positive by reviewing logs and user behavior.

2. **Containment:**
   - Temporarily lock affected accounts to prevent further unauthorized access attempts.
   - Block suspicious IP addresses at the firewall level if applicable.

3. **Investigation:**
   - Conduct a thorough investigation into the source of the login attempts, including origin IP, device information, and user patterns.
   - Review network traffic for anomalies that may indicate lateral movement or data exfiltration.

4. **User Notification:**
   - Inform affected users about the incident and encourage them to change their passwords immediately.

5. **Incident Reporting:**
   - Document the findings and report to relevant stakeholders, including IT security teams and management.
   - Update threat intelligence feeds with information on attacker tactics, techniques, and procedures (TTPs).

## Additional Resources

- [NIST Guide to Cyber Threat Information Sharing](https://www.nist.gov/publications/guide-cyber-threat-information-sharing)
- [CISA's Password Security Guidelines](https://us-cert.cisa.gov/ncas/tips/ST04-017)
- Tools like *Splunk*, *ELK Stack*, or *Azure Sentinel* for log aggregation and analysis.
- Articles on common password-guessing techniques and mitigation strategies.

---

This report provides a comprehensive framework to detect, analyze, and respond to password guessing attempts across various platforms, leveraging the latest in cybersecurity tools and practices.