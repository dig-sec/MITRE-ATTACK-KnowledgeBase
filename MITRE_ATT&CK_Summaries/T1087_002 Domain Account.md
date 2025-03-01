# Alerting & Detection Strategy (ADS) Report: Detecting Adversarial Use of Domain Accounts

## **Goal**
This technique aims to detect adversarial attempts to bypass security monitoring and gain unauthorized access using domain accounts.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1087.002 - Domain Account
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1087/002)

## **Strategy Abstract**
The detection strategy focuses on identifying unauthorized enumeration and manipulation of domain accounts. It leverages data from various sources such as security logs (e.g., Windows Security Event Logs), network traffic, and command execution histories. Patterns analyzed include unusual account enumeration activities, abnormal use of account management tools like `net.exe`, and suspicious LDAP queries.

## **Technical Context**
Adversaries often exploit domain accounts to perform reconnaissance and escalate privileges within an organization's network. Common methods involve using native tools such as `net.exe` for querying Active Directory (AD), PowerShell scripts, or third-party utilities like AdFind for enumerating user information. These activities can indicate lateral movement attempts or preparation for privilege escalation.

**Adversary Emulation Details:**
- **Sample Commands:**
  - Using `net.exe`: `net user`
  - PowerShell script with PowerView: `(Get-DomainUser).samaccountname`
  - AdFind commands for enumeration:
    ```
    adfind user
    adfind computer
    ```

**Test Scenarios:**
1. Execute account enumeration using native and third-party tools.
2. Monitor for unusual patterns in command usage indicative of reconnaissance.

## **Blind Spots and Assumptions**
- **Known Limitations:** 
  - Detection may miss sophisticated adversaries who use advanced evasion techniques or operate during periods of low monitoring activity.
  - Assumes logs are complete and unaltered, which might not be the case if an adversary has gained administrative access to modify or delete logs.

## **False Positives**
Potential benign activities that could trigger alerts include:
- Legitimate IT admin performing routine account audits or maintenance.
- Scripted tasks for automated account management during scheduled operations.

## **Priority**
**Severity: High**

*Justification:* The exploitation of domain accounts can lead to significant security breaches, including data theft and system compromise. Prompt detection is crucial to prevent lateral movement and privilege escalation by adversaries.

## **Validation (Adversary Emulation)**
To emulate this technique in a test environment:

1. **Enumerate all accounts (Domain):** Use `net user` for local domain enumeration.
2. **Enumerate all accounts via PowerShell (Domain):** Execute `(Get-DomainUser).samaccountname`.
3. **Enumerate logged-on users via CMD (Domain):** Utilize `query user`.
4. **Automated AD Recon (ADRecon):** Run `adrecon -h <domain>`.
5. **Adfind commands:**
   - List password policies: `adfind -passwordpolicy`
   - Enumerate Active Directory admins: `adfind user * -b Administrators`
   - Enumerate User Objects: `adfind user`
   - Exchange AD objects: `adfind computer -o "*exchange*"`.
6. **Detailed Account Information:** Use tools like WinPwn and Kerbrute to extract domain admin details and enumerate users.
7. **Wevtutil Queries:** Utilize `wevtutil qe Security /rd:true` to discover NTLM usage.

**Suspicious LAPS Attributes Query:**
- Query using Get-ADComputer for properties like ms-Mcs-AdmPwd.

8. **Active Directory Domain Search and Account Enumeration:**
   - Use LDAPDomainDump or similar tools for comprehensive enumeration.

## **Response**
When the alert fires, analysts should:
1. Confirm the legitimacy of the activity by correlating with known administrative tasks.
2. Investigate potential signs of compromise such as unusual user account changes or logins from unexpected locations.
3. Review security policies and access controls to prevent unauthorized account manipulation.
4. Consider network segmentation and additional monitoring on critical accounts.

## **Additional Resources**
- **Suspicious Manipulation Of Default Accounts Via Net.EXE**
- **PUA - AdFind Suspicious Execution**
- **Net.EXE Execution Patterns**
- **Group And Account Reconnaissance Activity Using Net.EXE**

These resources provide further context for recognizing patterns indicative of adversarial actions and refining detection capabilities.