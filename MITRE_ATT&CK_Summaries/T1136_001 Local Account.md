# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Local Accounts

## Goal
The primary goal of this detection strategy is to identify adversarial attempts to bypass security monitoring by creating local accounts with elevated privileges on various operating systems. This technique aims to detect scenarios where adversaries create local user accounts, often with administrative or root-like permissions, which they can use to persist and execute malicious activities while avoiding detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1136.001 - Local Account
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1136/001)

## Strategy Abstract
The detection strategy leverages multiple data sources to identify the creation of local accounts with suspicious permissions. Data sources include:
- System logs (e.g., Event Logs on Windows, syslog on Linux/macOS)
- User account management tools and their logs
- Process monitoring to detect command-line activities related to user account creation

Patterns analyzed include unusual account creations, especially those involving root or administrative privileges, by unauthorized users or processes. The strategy focuses on anomalies in account creation timing (e.g., during off-hours) and the use of privileged commands.

## Technical Context
Adversaries often create local accounts as a means of establishing persistence within a system. This technique is executed through various command-line utilities and scripts that grant them unauthorized access or administrative rights.

### Real-World Execution:
- **Linux:** Use of `useradd`, `sudo adduser`, or direct manipulation of `/etc/passwd` and `/etc/shadow`.
- **macOS:** Similar to Linux, with the addition of AppleScript for certain automation tasks.
- **Windows:** Utilization of `net user`, PowerShell commands like `New-LocalUser`, or leveraging Group Policy.

### Adversary Emulation Details:
- Sample command on Linux: `sudo useradd -m -s /bin/bash new_admin`
- Sample PowerShell command on Windows: `New-LocalUser -Name "newAdmin" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)`

## Blind Spots and Assumptions
### Limitations:
- May not detect account creations that are part of legitimate administrative tasks.
- Relies on the proper configuration and logging of user management activities.

### Assumptions:
- Logs for user account creation are enabled and accessible.
- Analysts have baseline knowledge of normal system behavior to identify anomalies effectively.

## False Positives
Potential benign activities include:
- Legitimate system administration creating new accounts as part of routine maintenance or provisioning.
- Automated scripts executed by IT teams that create temporary user accounts for deployment purposes.

## Priority
**Severity:** High

Justification: The creation of local accounts with elevated privileges can significantly compromise a network's security posture, providing adversaries with extensive control and the ability to evade detection mechanisms. Detecting such activities promptly is crucial for maintaining system integrity and responding effectively to potential breaches.

## Validation (Adversary Emulation)
### Instructions:
1. **Linux System:**
   - Create user: `sudo adduser testuser`
   - Grant sudo privileges: Edit `/etc/sudoers` with `visudo` to add `testuser ALL=(ALL) NOPASSWD:ALL`

2. **FreeBSD System:**
   - Create user: `pw useradd testuser`
   - Add to wheel group for root access

3. **macOS System:**
   - Create user: `sudo dscl . -create /Users/testuser`
   - Set password and other attributes as needed
   - Grant admin privileges by adding to the Admins group

4. **Windows Command Prompt:**
   - Create new user: `net user testuser P@ssw0rd! /add`

5. **PowerShell on Windows:**
   - Create new user: 
     ```powershell
     New-LocalUser "testuser" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
     ```

6. **Linux with `root` UID and GID:**
   - Create user: `sudo useradd -u 0 -g 0 testuser`
   - Set password and modify `/etc/passwd` if necessary

7. **FreeBSD with `root` GID:**
   - Create user: `pw useradd -G wheel testuser`

8. **Windows Admin User Creation via .NET:**
   - Use a PowerShell script or C# program to invoke `System.DirectoryServices.AccountManagement.UserPrincipal`.

## Response
When an alert fires, analysts should:
- Verify the legitimacy of the account creation by checking against change management records and consulting with relevant IT teams.
- Investigate the context (e.g., who initiated it, during what time, from which IP) for any signs of unauthorized activity.
- Review related logs to identify potential lateral movement or privilege escalation activities.
- Isolate affected systems if necessary and initiate a full security review.

## Additional Resources
- [PowerShell Download and Execution Cradles](https://attack.mitre.org/techniques/T1547/002/)
- [Suspicious PowerShell Invocations - Specific - ProcessCreation](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/MordorIndex.json)
- [Usage Of Web Request Commands And Cmdlets](https://attack.mitre.org/techniques/T1105/)

This report provides a comprehensive strategy for detecting and responding to the creation of local accounts by adversaries, ensuring robust security monitoring across diverse platforms.