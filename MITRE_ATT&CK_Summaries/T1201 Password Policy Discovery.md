# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
This detection strategy aims to identify and alert on adversarial attempts to discover password policies across various platforms. This includes assessing both local and domain-level configurations that may expose critical security vulnerabilities.

## Categorization
- **MITRE ATT&CK Mapping:** T1201 - Password Policy Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, Linux, macOS, IaaS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1201)

## Strategy Abstract
The detection strategy leverages multiple data sources across diverse platforms to identify attempts to query or alter password policies. The analysis focuses on command execution patterns and system queries indicative of password policy discovery, using network traffic monitoring, process logging, and user activity tracking.

### Data Sources:
- **Windows:** Event logs (Security, System), PowerShell, Command Prompt
- **Linux/macOS:** Syslog, Auditd, Process Monitors
- **IaaS Platforms:** Cloud Access Logs

### Patterns Analyzed:
- Use of specific commands or tools that query password policy settings.
- Unusual administrative access attempts to systems where such queries could be executed.

## Technical Context
Adversaries often attempt to discover password policies as part of a broader reconnaissance effort, aiming to understand the security posture and potential weaknesses in authentication mechanisms. Common tactics include using native system utilities or third-party tools that can extract detailed policy information.

### Adversary Emulation Details:
- **Linux Commands:** `chage`, `authconfig --test`, `pam_tally2`
- **Windows Tools:** `secedit.exe /export`, PowerShell commands like `Get-ADDefaultDomainPasswordPolicy`
- **macOS Commands:** `defaults read` for local password policies
- **Cloud Platforms:** AWS CLI queries or IAM Access Analyzer

## Blind Spots and Assumptions
- **Blind Spots:** Detection may not cover all proprietary or obscure tools used by adversaries.
- **Assumptions:** Assumes that standard administrative commands are being monitored, which might miss novel methods of policy discovery.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate system administrators performing routine checks on password policies as part of compliance audits.
- Automated scripts for regular security assessments configured to run at intervals.
  
## Priority
**Severity: Medium**
Justification: While not immediately critical, discovering password policies can significantly aid adversaries in crafting more effective attacks. Timely detection is crucial but does not typically imply an immediate compromise.

## Validation (Adversary Emulation)
Below are step-by-step instructions to emulate this technique in a test environment:

### Examine Password Complexity Policy - Ubuntu
1. Run `authconfig --test` or check `/etc/pam.d/common-password`.

### Examine Password Complexity Policy - FreeBSD
1. Use `sysrc pwquality_enable="YES"` and review the settings.

### Examine Password Complexity Policy - CentOS/RHEL 7.x
1. Check `/etc/security/pwquality.conf` for configuration details.

### Examine Password Complexity Policy - CentOS/RHEL 6.x
1. Review `/etc/sysconfig/init` for `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, etc.

### Examine Password Expiration Policy - All Linux
1. Use `chage -l <username>` to view expiration settings.

### Examine Local Password Policy - Windows
1. Execute `secedit /export /cfg C:\local_policy.cfg` and review the output.

### Examine Domain Password Policy - Windows
1. Run `Get-ADDefaultDomainPasswordPolicy` in PowerShell.

### Use of SecEdit.exe to Export Local Security Policy (Including Password Policy)
1. Execute `secedit.exe /export /areas User_Restrictions`.

### Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy
1. In an elevated PowerShell, run `Get-ADDefaultDomainPasswordPolicy`.

### Use of Net.EXE to Discover Network Configuration
1. Run `net accounts` or `net localgroup administrators`.

### Get-DomainPolicy with PowerView
1. Execute `Get-DomainPolicy -PSPath C:\Windows\System32\GroupPolicy`.

### Examine Password Policy - macOS
1. Check `/etc/pam.d/common-password` for policy configurations.

### Examine AWS Password Policy
1. Use the AWS CLI: `aws iam get-account-password-policy`.

## Response
Upon detection of an alert related to password policy discovery:
- **Immediate Action:** Isolate the session or user account involved in the activity.
- **Investigate:** Determine if the action was authorized by a legitimate administrative task.
- **Review Logs:** Examine relevant logs for additional context and patterns that might indicate malicious intent.
- **Notify Security Team:** Escalate to security analysts for further investigation.

## Additional Resources
For further reading and context, consider exploring:
- [Net.EXE Execution](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/net)
- [Suspicious Group And Account Reconnaissance Activity Using Net.EXE](https://attack.mitre.org/techniques/T1087/)
- [Potential Suspicious Activity Using SeCEdit](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/potential-suspicious-secedit-activity/ba-p/1272456)
- Additional documentation on PowerShell and IAM policies.

This report outlines a comprehensive approach to detecting adversarial attempts at password policy discovery, ensuring organizations can effectively mitigate associated risks.