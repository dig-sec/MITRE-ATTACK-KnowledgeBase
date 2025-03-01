# Alerting & Detection Strategy Report: Account Access Removal (MITRE ATT&CK T1531)

## **Goal**
The primary goal of this technique is to detect adversarial attempts focused on removing access to user accounts across different platforms—Windows, Linux, and macOS. This includes scenarios where an adversary removes or modifies account details to evade detection or disrupt operations.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1531 - Account Access Removal
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1531)

## **Strategy Abstract**
The detection strategy leverages a combination of endpoint monitoring and log analysis to identify unauthorized changes or deletions to user accounts. The primary data sources include system logs (e.g., Event Logs on Windows, Audit Logs on Linux), security information and event management (SIEM) systems, and directory services logs such as Active Directory and Azure AD.

Key patterns analyzed involve:
- Sudden deletion or modification of user account properties.
- Unusual command-line operations indicating manual account removal.
- Changes in group memberships without legitimate administrative action.

## **Technical Context**
Adversaries employ a variety of methods to execute Account Access Removal:

- On Windows, adversaries may utilize built-in tools like `net.exe` and PowerShell scripts to alter or delete user accounts. Commands such as `net user [username] /delete` are typical.
  
- On Linux, adversaries might use utilities such as `userdel`, `passwd`, or `dscl` on macOS to remove users from the system. These commands often leave traces in system logs.

- In Azure AD environments, PowerShell (`Remove-AzureADUser`) and CLI tools can be employed for account deletion operations.

Adversary emulation involves simulating these actions using:
- Windows: Command Prompt or PowerShell commands like `net user [username] /delete`.
- Linux/macOS: Terminal commands such as `userdel [username]` or `dscl . -delete /Users/[username]`.

## **Blind Spots and Assumptions**
### Blind Spots
- Detection might miss low-frequency manual deletions by legitimate users not accounted for in the baseline.
- In highly dynamic environments, distinguishing between legitimate administrative actions and malicious intent may be challenging.

### Assumptions
- Accounts a user regularly accesses have established baselines of activity.
- Directory services like Active Directory and Azure AD are properly configured to log relevant activities.

## **False Positives**
Potential benign activities triggering false alerts include:
- Legitimate system administrators performing account maintenance, such as removing inactive accounts or altering passwords for security compliance.
- Scheduled tasks that modify user permissions during routine clean-up operations.
- Misconfigured automated scripts that inadvertently target user accounts.

## **Priority**
The priority level is assessed as **High** due to the potential impact on operational continuity and the challenge in regaining access once an account is deleted. Organizations relying heavily on directory services should consider robust monitoring of these activities to mitigate risks promptly.

## **Validation (Adversary Emulation)**
To validate this detection strategy, follow these steps:

### Windows
1. **Change User Password:**
   - Open Command Prompt as Administrator and execute: `net user [username] *`
2. **Delete User:**
   - Use Command Prompt or PowerShell with: `net user [username] /delete` or `Remove-LocalUser -Name [username]`.
3. **Remove Account from Domain Admin Group:**
   - Access Active Directory Users and Computers, manually remove the account from the 'Domain Admins' group.

### macOS
1. **Change User Password:**
   - Use Terminal with: `passwd [username]`
2. **Delete User via dscl utility:**
   - Execute: `sudo dscl . -delete /Users/[username]`

### Azure AD
1. **Delete User via Azure AD PowerShell:**
   - Run: `Remove-AzureADUser -ObjectId [userObjectID]`
2. **Delete User via Azure CLI:**
   - Use: `az ad user delete --id [userPrincipalName]`

## **Response**
When an alert for account access removal is triggered, analysts should:
- Immediately review the logs to confirm the action and determine whether it was legitimate or unauthorized.
- Assess the potential impact on systems and services dependent on the affected accounts.
- Coordinate with IT/security teams to restore deleted accounts if necessary and investigate further to identify any related compromise.

## **Additional Resources**
For further reading and context:
- Investigate new user creation methods such as `net.exe` execution, which may indicate account-related reconnaissance by adversaries.
- Understand how PowerShell scripts can be used for both legitimate administration and malicious activity, including the execution of `net.exe`.

---

This report outlines a comprehensive strategy to detect and respond to account access removal activities across multiple platforms, addressing potential blind spots and false positives while prioritizing high-risk scenarios.