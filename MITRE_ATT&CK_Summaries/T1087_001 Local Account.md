# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containers. The focus is on identifying suspicious activities that adversaries might use to avoid detection while operating within containerized environments.

## Categorization
- **MITRE ATT&CK Mapping:** T1087.001 - Local Account
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1087/001)

## Strategy Abstract
The detection strategy leverages logs from container orchestration systems (e.g., Kubernetes), host-level monitoring tools, and endpoint detection and response (EDR) solutions. It analyzes patterns such as unusual account creation or modification within containers, abnormal privilege escalations, and deviations in normal user behavior. The focus is on identifying local accounts that may be leveraged to gain unauthorized access or escalate privileges.

## Technical Context
Adversaries often use container environments to execute commands under the guise of legitimate operations. They might create new users with high privileges, modify existing ones, or leverage vulnerabilities within the container orchestration system. This technique involves examining how adversaries attempt to create and manipulate local accounts within containers to bypass security controls.

### Adversary Emulation Details
- **Sample Commands:**
  - Linux/macOS: `useradd`, `passwd`, `sudo`
  - Windows: `net user /add`, `psexec`, PowerShell commands like `New-LocalUser`

### Test Scenarios:
1. Creating a new local user in a running container.
2. Granting the new user sudo privileges.
3. Modifying an existing user’s permissions to gain elevated access.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection may not cover all types of containers or orchestration systems.
  - Dynamic account management by legitimate processes might be misinterpreted as malicious activity.

- **Assumptions:**
  - Container orchestrators are configured to log significant user and privilege changes.
  - Host-level monitoring tools have access to container metadata and logs.

## False Positives
Potential benign activities that might trigger false alerts include:
- Automated scripts or maintenance tasks creating temporary accounts for specific tasks.
- Legitimate administrative actions where permissions are temporarily elevated.
- Misconfigured containers leading to unintended user account creation.

## Priority
**Severity: High**

Justification: Local account manipulation can lead to significant security breaches, including privilege escalation and unauthorized access. Given the increasing adoption of containerized environments in critical infrastructure, detecting such activities is crucial for maintaining security posture.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

1. **Enumerate all accounts (Local)**
   - Linux/macOS: `cat /etc/passwd`
   - Windows: `net users`

2. **View sudoers access**
   - Linux/macOS: `cat /etc/sudoers`, `sudo -l`

3. **View accounts with UID 0**
   - Linux/macOS: `awk -F: '($3 == "0") {print $1}' /etc/passwd`

4. **List opened files by user**
   - Linux/macOS: `lsof -u username`
   - Windows: `Get-Process -Id (whoami) | Select-Object -ExpandProperty Handles`

5. **Show if a user account has ever logged in remotely**
   - Linux/macOS: `last` or `lastlog`
   - Windows: Review Security logs for Remote Desktop Protocol events

6. **Enumerate users and groups**
   - Linux/macOS: `getent group`
   - Windows: `net localgroup`

7. **Enumerate all accounts on Windows (Local)**
   - PowerShell: `Get-LocalUser`

8. **Enumerate all accounts via PowerShell (Local)**
   - PowerShell: `Get-WmiObject Win32_UserAccount`

9. **Enumerate logged-on users via CMD (Local)**
   - CMD: `query user`

10. **ESXi - Local Account Discovery via ESXCLI**
    - Use ESXCLI command to list all accounts.

## Response
When the alert fires, analysts should:
- Verify if the account creation or modification is part of a known scheduled task.
- Assess the privileges granted and whether they align with typical usage patterns.
- Investigate any associated network activity that might indicate data exfiltration or lateral movement.
- Review logs for additional indicators of compromise or suspicious behavior.

## Additional Resources
For further context and reference, consider exploring:
- **Tunneling Tool Execution:** Understanding how adversaries use tunneling tools to maintain persistent access within containerized environments.

This ADS framework provides a structured approach to detecting adversarial activities involving local account manipulation in containerized systems.