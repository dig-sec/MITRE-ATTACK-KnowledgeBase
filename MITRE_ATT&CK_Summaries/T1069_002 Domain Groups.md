# Alerting & Detection Strategy (ADS) Report: Detecting Domain Group Enumeration Techniques

## Goal
The objective of this technique is to detect adversarial attempts at enumerating domain groups within an enterprise environment. This capability helps identify unauthorized access to sensitive group membership information, which can be leveraged for lateral movement or privilege escalation.

## Categorization
- **MITRE ATT&CK Mapping:** T1069.002 - Domain Groups
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1069/002)

## Strategy Abstract
The detection strategy focuses on identifying anomalous patterns associated with domain group enumeration. Key data sources include:
- Security logs (e.g., audit logs)
- Network traffic analysis
- Process and command execution history

Patterns analyzed involve unexpected use of tools like `PowerView`, `Adfind`, or native commands (`net group`) that are commonly used to enumerate Active Directory groups, especially by unauthorized users.

## Technical Context
Adversaries often execute domain group enumeration as a preliminary step in lateral movement or privilege escalation attacks. Techniques include:
- Using PowerShell scripts with modules like PowerView for detailed enumeration.
- Executing `net group` commands to list group memberships.
- Leveraging tools such as Adfind and LDIFDE for extracting comprehensive AD data.

### Adversary Emulation Details
Adversaries might use the following sample commands or scenarios in a test environment:
- PowerShell: `Get-DomainGroup -Domain <domain>`
- `net group "Domain Admins" /domain`
- Using PowerView: `Invoke-UserHunter`

## Blind Spots and Assumptions
- **Blind Spots:** Detection might miss techniques using custom scripts or encoded commands that evade traditional signature-based detection.
- **Assumptions:** Assumes a baseline understanding of normal group enumeration activities within the network, which can vary significantly across different environments.

## False Positives
Potential benign activities include:
- Legitimate IT administrators performing routine audits or maintenance tasks.
- System health checks and automated scripts running scheduled tasks to verify permissions.
- Security teams conducting penetration tests using similar tools.

## Priority
**Severity:** High  
Justification: Domain group enumeration can provide adversaries with critical information that facilitates further compromise of the network, including lateral movement and privilege escalation. This makes it a high-priority detection target.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **Basic Permission Groups Discovery Windows (Domain)**
   - Use `net group` to list groups: `net group "Domain Admins" /domain`

2. **Permission Groups Discovery PowerShell (Domain)**
   - Run the following PowerShell command:
     ```powershell
     Get-DomainGroup -Domain <domain>
     ```

3. **Elevated Group Enumeration Using Net Group (Domain)**
   - Execute with elevated privileges: `runas /user:<domain>\<admin> net group "Enterprise Admins" /domain`

4. **Find Machines Where User Has Local Admin Access (PowerView)**
   ```powershell
   Invoke-UserHunter -ComputerName <computer> -LocalAdminGroup "Administrators"
   ```

5. **Find Local Admins on All Machines in Domain (PowerView)**
   ```powershell
   Get-DomainComputer | ForEach-Object { Get-DomainComputerMember -Domain $_.domain -Identity $_.name }
   ```

6. **Find Local Admins via Group Policy (PowerView)**
   ```powershell
   Invoke-GPUpdate
   Get-DomainGroupMember -Domain <domain> -GroupName "Administrators"
   ```

7. **Enumerate Users Not Requiring Pre Auth (ASRepRoast)**
   ```bash
   .\AS-REP-Roast.ps1 -Target <username>
   ```

8. **Adfind - Query Active Directory Groups**
   ```bash
   adfind group -b "CN=Users,DC=<domain>,DC=com"
   ```

9. **Enumerate Active Directory Groups with Get-ADGroup**
   ```powershell
   Get-ADGroup -Filter *
   ```

10. **Enumerate Active Directory Groups with ADSISearcher**
    ```csharp
    using (var searcher = new DirectorySearcher())
    {
        searcher.Filter = "(objectCategory=group)";
        foreach (var result in searcher.FindAll()) { /* process result */ }
    }
    ```

11. **Get-ADUser Enumeration Using UserAccountControl Flags (AS-REP Roasting)**
    ```powershell
    Get-ADUser -Filter * | Where-Object { $_.UserAccountControl -band 2 }
    ```

12. **Get-DomainGroupMember with PowerView**
    ```powershell
    Get-DomainGroupMember -Domain <domain> -GroupName "Administrators"
    ```

13. **Get-DomainGroup with PowerView**
    ```powershell
    Get-DomainGroup -Domain <domain>
    ```

14. **Active Directory Enumeration with LDIFDE**
    ```bash
    ldifde -f groups.ldf -d <domain> "(objectCategory=group)"
    ```

15. **Active Directory Domain Search Using LDAP - Linux (Ubuntu)/macOS**
    ```bash
    ldapsearch -x -LLL -H ldap://<domain>/dc=<domain> -b "cn=users,dc=<domain>" "(objectclass=*)"
    ```

## Response
When an alert for domain group enumeration is triggered:
1. **Verify the Source:** Confirm if the activity originated from a known and authorized source.
2. **Review Context:** Assess the context of the command execution—such as time, location, and user account.
3. **Containment:** Temporarily restrict the involved user's permissions to prevent further potential misuse.
4. **Investigation:** Conduct a thorough investigation into why such enumeration was needed or if it indicates malicious activity.
5. **Remediation:** Implement necessary changes in policy or system configurations to mitigate future risks.

## Additional Resources
- [Palantir User Alert: AdFind Suspicious Execution](https://example.com/adfind)
- [Palantir User Alert: AdFind Suspicious Execution](https://example.com/adfind)

This report provides a comprehensive strategy for detecting and responding to domain group enumeration techniques, aligned with Palantir's ADS framework.