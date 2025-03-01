# Detection Strategy for AS-REP Roasting (T1558.004)

## **Goal**
The goal of this detection strategy is to identify and mitigate attempts by adversaries to perform AS-REP Roasting attacks on Active Directory environments running on Windows platforms. This technique aims to detect unauthorized attempts to extract plaintext Kerberos Ticket Granting Tickets (TGTs) for service accounts with weaker permissions, which can be used to authenticate as these services and potentially escalate privileges.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1558.004 - AS-REP Roasting
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1558/004)

## **Strategy Abstract**
The detection strategy focuses on monitoring and analyzing network traffic for Kerberos authentication requests targeting service accounts that do not require pre-authentication. By identifying these specific Kerberos AS-REP (Authentication Service Request) messages, the system can detect potential AS-REP Roasting attempts.

### Data Sources
- Network Traffic: Inspect Kerberos ticket exchange patterns.
- Security Event Logs: Monitor for failed or unusual authentication requests.

### Patterns Analyzed
- Repeated attempts to request TGTs from accounts without pre-authentication (e.g., service accounts).
- Unusual activity on service accounts that typically do not initiate logins.

## **Technical Context**
AS-REP Roasting is a technique used by attackers to exploit the way Kerberos handles authentication requests for service accounts. Attackers identify service accounts configured to allow "null" passwords or no pre-authentication, and then attempt to request TGTs from these accounts over the network. If successful, they can capture plaintext TGTs, which may be cracked offline to obtain valid credentials.

### Adversary Emulation Details
- **Rubeus asreproast:** Utilized for roasting service accounts by sending Kerberos AS-REP requests.
- **Get-DomainUser with PowerView:** Enumerates user accounts and checks their permissions.
- **WinPwn - PowerSharpPack:** Another tool used to execute the roasting process through PowerShell.

## **Blind Spots and Assumptions**
- The strategy assumes that all service account Kerberos requests are monitored, which might not be feasible in very large environments.
- Blind spots include encrypted network channels (e.g., VPNs) where traffic inspection is limited.
- Assumes that service accounts are correctly configured to require pre-authentication.

## **False Positives**
- Legitimate administrative activities involving Kerberos AS-REP requests for service account maintenance.
- Automated processes or scripts designed to interact with service accounts, which may not use pre-authentication due to legacy configurations.

## **Priority**
**Severity: Medium**

Justification:
While the impact of a successful AS-REP Roasting attack can be significant in terms of credential compromise and privilege escalation, it is often used as an initial step in more complex attacks. The risk is mitigated by proper configuration practices (e.g., enforcing pre-authentication on service accounts).

## **Validation (Adversary Emulation)**
To validate this detection strategy, follow these steps in a controlled test environment:

1. **Rubeus asreproast:**
   - Install Rubeus.
   - Execute `rubeus.exe asreproast /user:[ServiceAccount]`.

2. **Get-DomainUser with PowerView:**
   - Load PowerView: `Import-Module .\PowerView.ps1`.
   - Enumerate users: `Get-DomainUser | Where-Object {$_.Name -like "*svc*"} | Select-Object Name, ServicePrincipalName`.

3. **WinPwn - PowerSharpPack:**
   - Install WinPwn.
   - Execute: `WinPwn.exe Kerberoasting -TargetAccount [ServiceAccount]`.

Ensure these actions are performed in an isolated environment to prevent unintended security breaches.

## **Response**
When the alert for AS-REP Roasting is triggered, analysts should:

1. Verify if the affected accounts require pre-authentication and update configurations accordingly.
2. Analyze network traffic logs to identify source IPs of suspicious requests and correlate with other indicators of compromise (IoCs).
3. Initiate incident response protocols including isolating affected systems and reviewing access controls.

## **Additional Resources**
- [PowerShell Download and Execution Cradles](https://example.com)
- [Suspicious PowerShell Invocations - Specific - ProcessCreation](https://example.com)
- [Suspicious PowerShell Download and Execute Pattern](https://example.com)
- [Malicious PowerShell Commandlets - ProcessCreation](https://example.com)
- [PowerShell Web Download](https://example.com)
- [Usage Of Web Request Commands And Cmdlets](https://example.com)

These resources provide further insights into related detection techniques and patterns, aiding in comprehensive security monitoring strategies.