# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to create or manipulate domain accounts to maintain persistence and escalate privileges in an enterprise network.

## Categorization
- **MITRE ATT&CK Mapping:** T1136.002 - Domain Account
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, macOS, Linux  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1136/002)

## Strategy Abstract
The detection strategy focuses on identifying unauthorized creation or modification of domain accounts. The primary data sources include:

- Active Directory logs for account changes
- PowerShell execution history
- Net command usage logs

Patterns analyzed involve unexpected or unauthorized use of tools such as `net.exe` and unusual patterns in PowerShell scripts that suggest the creation or alteration of domain accounts.

## Technical Context
Adversaries often create new domain accounts to maintain access within a network. They might exploit weak credentials, administrative privileges, or flaws in account management processes. Common methods include:

- Using tools like `net.exe` to create user accounts.
- Exploiting PowerShell scripts for advanced account creation without detection.

### Adversary Emulation Details
Sample Commands:
- **Using net.exe:**  
  ```shell
  net user /add username password
  ```
- **PowerShell Command:**
  ```powershell
  New-ADUser -Name "username" -GivenName "User" -Surname "Example"
  ```

Test Scenarios:
1. Create a new Windows domain admin user using `net.exe`.
2. Utilize PowerShell to create an account with unusual permissions.
3. Mimic non-elevated user behavior creating or modifying accounts.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may not cover obfuscated scripts that hide account creation commands.
  - Lack of visibility into remote management tools could miss some unauthorized activities.

- **Assumptions:**
  - Logs are complete and not tampered with by adversaries.
  - Baselines for normal activity have been established and updated regularly.

## False Positives
Potential benign activities include:
- IT administrators performing routine account management tasks.
- Legitimate use of `net.exe` or PowerShell scripts for system maintenance.
- Temporary accounts created during software installation processes that are not properly cleaned up.

## Priority
**Severity: High**

Justification: Unauthorized domain account manipulation can lead to persistent access and privilege escalation, making it a critical threat vector. Effective detection is essential to mitigate these risks promptly.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Create a New Windows Domain Admin User:**
   - Use `net.exe` with administrative privileges.
     ```shell
     net user newadmin password /add
     ```

2. **Create an Account Similar to ANONYMOUS LOGON:**
   - Identify naming patterns and attributes of the ANONYMOUS LOGON account.
   - Create a similar account using PowerShell:
     ```powershell
     New-ADUser -Name "SimilarAccount" -GivenName "AnonLike" -Surname "User"
     ```

3. **Create a New Domain Account Using PowerShell:**
   - Execute the following command to create an account with specific attributes.
     ```powershell
     New-ADUser -Name "testuser" -GivenName "Test" -Surname "Account"
     ```

4. **Active Directory Create Admin Account:**
   - Ensure the user has administrative privileges using PowerShell or ADUC (Active Directory Users and Computers).

5. **Create User Account (Non-elevated):**
   - Attempt account creation without elevated permissions to test for alert triggers:
     ```powershell
     New-ADUser -Name "nonadminuser" -GivenName "Test" -Surname "User"
     ```

## Response
When the alert fires, analysts should:

1. **Verify Account Creation:** Confirm if the new account is authorized and intended.
2. **Assess User Activity:** Review recent activities of the account for any suspicious behavior.
3. **Evaluate Permissions:** Check the permissions assigned to the new account.
4. **Audit Logs:** Cross-reference logs from Active Directory, PowerShell, and other relevant sources.
5. **Containment:** If malicious intent is confirmed, isolate the affected systems and revoke the unauthorized account.

## Additional Resources
- [Understanding `net.exe` Execution](https://example.com/net-exe-execution)
- [PowerShell for Active Directory Management](https://example.com/powershell-ad-management)
- [Best Practices in Account Monitoring](https://example.com/account-monitoring-best-practices)

This report outlines the ADS framework to detect unauthorized domain account activities, providing a comprehensive approach to identifying and mitigating threats related to this vector.