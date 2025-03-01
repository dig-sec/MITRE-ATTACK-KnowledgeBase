# Alerting & Detection Strategy: Kerberoasting (T1558.003)

## **Goal**
The goal of this detection strategy is to identify adversarial attempts to exploit weak service principal names (SPNs) and extract service tickets from a Windows environment using the technique known as Kerberoasting.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1558.003 - Kerberoasting
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1558/003)

## **Strategy Abstract**
This detection strategy focuses on monitoring for suspicious activities related to Kerberoasting within a Windows environment. Key data sources include security event logs, specifically Event ID 4769 (Service Ticket Operations) and Event ID 4771 (Kerberos Service Ticket Request), as well as PowerShell execution logs. The strategy analyzes patterns such as abnormal ticket requests, usage of specific tools like Rubeus or WinPwn, and unusual command-line activities that indicate attempts to extract service tickets.

## **Technical Context**
Adversaries typically execute Kerberoasting by requesting service tickets for accounts with SPNs from the domain controller. They then attempt to decrypt these tickets offline using brute force techniques if weak passwords are used. Common tools used in this attack include Rubeus, PowerSploit, and WinPwn.

### Adversary Emulation Details:
- **Sample Commands:**
  - `Rubeus.exe kerberoast`
  - PowerShell commands like `Get-KerberosTicket` from PowerSharpPack
- **Test Scenarios:** 
  - Use of Rubeus to request service tickets for accounts with SPNs.
  - Monitoring for increased volume of Kerberos ticket requests.

## **Blind Spots and Assumptions**
- Detection may not cover all variations of custom scripts or tools used for Kerberoasting.
- Assumes that logging is configured correctly and covers necessary events (e.g., Event IDs related to Kerberos).
- May miss attacks using highly obfuscated methods to request service tickets.

## **False Positives**
Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks involving SPNs or Kerberos ticket requests.
- Scheduled tasks or services that require frequent access to resources with SPNs.
- Network troubleshooting activities that involve legitimate Kerberos ticket operations.

## **Priority**
**Severity: High**

Justification: Kerberoasting is a potent technique for credential theft, allowing attackers to obtain service account credentials if weak passwords are used. The potential impact on sensitive data and systems justifies a high priority for detection and response efforts.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions:
1. **Request for Service Tickets:**
   - Use Rubeus or PowerShell scripts to request service tickets.
2. **Rubeus Kerberoast:**
   - Execute `Rubeus.exe kerberoast` to extract and save service tickets in hashed format.
3. **Extract Accounts with SPNs:**
   - Use `setspn -T <domain> -Q */*` to list all accounts that have SPNs set.
4. **Request A Single Ticket via PowerShell:**
   - Execute PowerShell scripts like `Get-KerberosTicket`.
5. **Request All Tickets via PowerShell:**
   - Utilize PowerSharpPack or similar tools to automate ticket requests for multiple accounts.
6. **WinPwn Kerberoasting:**
   - Deploy WinPwn and use its Kerberoast feature to extract tickets.
7. **PowerShell Execution with WinPwn:**
   - Leverage PowerShell scripts from PowerSharpPack to perform Kerberoasting.

## **Response**
When the alert fires, analysts should:
- Investigate the source of the ticket request for signs of compromise or malicious intent.
- Analyze related logs and network activity for corroborating evidence.
- Isolate affected systems and review SPNs for weak password configurations.
- Update security policies to enforce stronger passwords and monitor for suspicious activities.

## **Additional Resources**
For further context and detailed information, consider the following resources:
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious PowerShell Download and Execute Pattern
- Malicious PowerShell Commandlets - ProcessCreation
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets

This strategy aims to provide a comprehensive approach to detecting and responding to Kerberoasting attempts, leveraging both event logging and behavior analysis within Windows environments.