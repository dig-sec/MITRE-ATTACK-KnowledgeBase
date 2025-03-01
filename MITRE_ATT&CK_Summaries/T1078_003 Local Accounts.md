# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Use of Local Accounts

## Goal
The goal of this detection strategy is to identify adversarial attempts that exploit local accounts for bypassing security measures and gaining unauthorized access or persistence within a system.

## Categorization
- **MITRE ATT&CK Mapping:** T1078.003 - Local Accounts
- **Tactic / Kill Chain Phases:**
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
- **Platforms:** Linux, macOS, Windows, Containers

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1078/003)

## Strategy Abstract
This detection strategy leverages multiple data sources including system logs, user account management tools, and privilege escalation monitoring to identify patterns indicative of adversaries exploiting local accounts. Key indicators include creation or modification of local admin accounts, unexpected changes in account privileges, activation of dormant/root accounts, and the use of specific utilities that facilitate unauthorized access.

### Data Sources
- **Windows:** Security Event Logs (S-004, S-007), PowerShell logs, Process Monitoring.
- **macOS:** User Account Management logs, System Integrity Protection status, Terminal session logs.
- **Linux/FreeBSD:** Auditd logs, SSH authentication logs, /etc/shadow file changes.

### Patterns Analyzed
- Creation of new local admin accounts.
- Modification or elevation of existing user privileges without proper authorization.
- Activation of root/administrator accounts that are typically disabled.
- Usage of system utilities (`sysadminctl`, `dseditgroup`) for unauthorized account modifications.

## Technical Context
Adversaries often exploit local accounts to execute privileged commands, bypass security controls, and establish persistence. Common methods include:

- **Windows:** Using tools like WinPwn or PowerShell scripts (e.g., PowerSploit's `GetComputerCredentials`), adversaries can extract credentials and escalate privileges.
  
- **macOS:** Utilization of native utilities (`sysadminctl`, `dseditgroup`) to add users to admin groups, enable root access with `dsenableroot`.
  
- **Linux/FreeBSD:** Direct modification of system files (e.g., `/etc/passwd`, `/etc/shadow`), usage of tools like `pwck`, and command-line manipulation to alter user permissions.

### Adversary Emulation Details
Emulate techniques by:
1. Creating local accounts with admin privileges.
2. Enabling root access on macOS using `dsenableroot`.
3. Using `sysadminctl` and `dseditgroup` for account modifications.
4. Employing PowerShell scripts like those from WinPwn to extract credentials.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection might miss stealthy, low-frequency changes made by sophisticated adversaries.
  - Insufficient monitoring of encrypted channels or files could allow undetected privilege escalation.
  
- **Assumptions:**
  - Baseline behavior is well-defined; significant deviations indicate malicious activity.
  - All necessary logging and auditing configurations are enabled.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate system administrators performing routine account management tasks.
- Installation or execution of software requiring temporary privilege elevation.
- Users legitimately modifying their own account settings with proper authorization.

## Priority
**Severity:** High

**Justification:** 
The exploitation of local accounts poses a significant risk to systems, potentially allowing adversaries to gain elevated privileges and access sensitive data. The ability to bypass security controls and establish persistence underscores the need for robust detection mechanisms in this area.

## Validation (Adversary Emulation)
Step-by-step instructions to emulate this technique:

1. **Create Local Account with Admin Privileges:**
   - **Windows:** Use `net user` or PowerShell's `New-LocalUser`.
   - **macOS:** Utilize `sysadminctl --add-user <username> --password <password> --hint <hint> --fullname "<full name>"`.
   - **Linux/FreeBSD:** Use `useradd -m <username>` and add to sudoers.

2. **Enable Root Account (macOS):**
   - Execute: `dsenableroot`.

3. **Add User to Admin Group (macOS):**
   - Command: `dseditgroup -o edit -a <username> -t user admin`.

4. **Extract Credentials (Windows):**
   - Use WinPwn's `SafetyKatz` or PowerSploit scripts.

5. **Utilize PsExec for Privilege Escalation:**
   - Execute: `psexec.exe \\target_machine -u username -p password cmd.exe`

6. **Reactivate Locked/Expired Accounts (Linux):**
   - Use `usermod -e '' <username>` or unlock with `passwd -u <username>`.
  
7. **Login as 'nobody' (Unix-like Systems):**
   - Attempt to gain unauthorized access via default service accounts.

## Response
When the alert fires, analysts should:
1. Verify if any legitimate administrative tasks were scheduled around the alert time.
2. Review associated logs for context and evidence of malicious intent.
3. Isolate affected systems to prevent further unauthorized actions.
4. Update security policies to mitigate similar future attempts.
5. Conduct a thorough investigation to identify potential breach extent and clean compromised accounts.

## Additional Resources
- Psexec Execution: [Microsoft Technet](https://technet.microsoft.com/en-us/library/cc749879.aspx)
- Sysinternals Tools Overview: [Sysinternals Documentation](https://docs.microsoft.com/en-us/sysinternals/)
- User Management in macOS: [Apple Support](https://support.apple.com/guide/mac-help/manage-user-accounts-mchlp1029/mac)

This detailed strategy provides a comprehensive approach to detecting and responding to the exploitation of local accounts across various platforms, aligning with Palantir's ADS framework.