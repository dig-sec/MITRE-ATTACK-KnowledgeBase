# Alerting & Detection Strategy: Credential Stuffing

## Goal
This strategy aims to detect credential stuffing attacks across various platforms, including Windows, Azure AD, Office 365, SaaS applications, IaaS environments, and containers on Linux, macOS, and Google Workspace.

## Categorization
- **MITRE ATT&CK Mapping:** T1110.004 - Credential Stuffing
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1110/004)

## Strategy Abstract
The detection strategy involves monitoring for patterns indicative of credential stuffing attacks across various platforms. Key data sources include authentication logs from Windows Active Directory, Azure AD sign-in logs, Office 365 audit logs, and SSH access logs on Linux/macOS systems. The strategy focuses on identifying anomalous login attempts that suggest the use of compromised credentials.

### Data Sources
- **Windows:** Security event logs (e.g., failed logon attempts)
- **Azure AD/Office 365:** Sign-in logs, user activity reports
- **Linux/macOS:** SSH authentication logs
- **Google Workspace:** Admin SDK audit logs

### Patterns Analyzed
- Multiple failed login attempts followed by a successful one from different IP addresses.
- Login attempts using credentials that have previously been compromised.
- Unusual geographic or temporal patterns in login attempts.

## Technical Context
Credential stuffing involves attackers using lists of compromised usernames and passwords to gain unauthorized access. Adversaries often automate this process using bots, making it critical to detect and respond swiftly.

### Real-World Execution
Adversaries typically use automated scripts or tools like Hydra, Medusa, or custom-built solutions to execute credential stuffing attacks. These tools attempt logins across multiple accounts until they find a match.

#### Adversary Emulation Details
- **Tools Used:** Hydra, Kerbrute
- **Sample Commands:**
  - `hydra -L userlist.txt -P passlist.txt ssh://target_ip`
  - `kerbrute userenum userlist.txt domain.com`

## Blind Spots and Assumptions
- **Blind Spots:** Detection may not cover zero-day vulnerabilities in authentication mechanisms.
- **Assumptions:** Assumes that attackers use known compromised credentials, which may not always be the case.

## False Positives
Potential false positives include:
- Legitimate users logging in from new devices or locations.
- Batch user password resets leading to multiple failed attempts.
- Automated scripts for legitimate purposes (e.g., backup systems).

## Priority
**Severity: High**

Justification: Credential stuffing can lead to unauthorized access across multiple accounts and platforms, posing significant risks to data integrity and confidentiality.

## Validation (Adversary Emulation)
### SSH Credential Stuffing From Linux
1. Install Hydra: `sudo apt-get install hydra`
2. Prepare a list of usernames (`userlist.txt`) and passwords (`passlist.txt`).
3. Execute: `hydra -L userlist.txt -P passlist.txt ssh://target_ip`

### SSH Credential Stuffing From MacOS
1. Use Homebrew to install Hydra: `brew install hydra`
2. Prepare lists as above.
3. Execute: `hydra -L userlist.txt -P passlist.txt ssh://target_ip`

### SSH Credential Stuffing From FreeBSD
1. Install Hydra via pkg: `pkg install hydra`
2. Prepare lists as above.
3. Execute: `hydra -L userlist.txt -P passlist.txt ssh://target_ip`

### Brute Force:Credential Stuffing using Kerbrute Tool
1. Download and configure Kerbrute from [Kerbrute GitHub](https://github.com/kerbrute/kerbrute).
2. Prepare a list of usernames.
3. Execute: `./kerbrute userenum userlist.txt domain.com`

## Response
When an alert fires:
- **Verify:** Confirm the legitimacy of the login attempts.
- **Isolate:** Temporarily block IP addresses or accounts showing suspicious activity.
- **Investigate:** Review logs for additional context and potential indicators of compromise.
- **Notify:** Inform affected users to change their passwords if necessary.
- **Remediate:** Implement additional security measures, such as multi-factor authentication.

## Additional Resources
- Execution Of Script Located In Potentially Suspicious Directory: Monitor directories for unauthorized script execution that may facilitate credential stuffing.