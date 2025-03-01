# Alerting & Detection Strategy (ADS) Report

## Goal
The primary goal of this strategy is to detect adversarial attempts to bypass security monitoring using cloud services such as containers and infrastructure-as-a-service (IaaS). This includes unauthorized creation and manipulation of cloud accounts, which could lead to persistent threats in environments like Azure AD, Office 365, AWS, and Google Workspace.

## Categorization
- **MITRE ATT&CK Mapping:** T1136.003 - Cloud Account  
- **Tactic / Kill Chain Phases:** Persistence  
- **Platforms:** Azure AD, Office 365, IaaS, Google Workspace  

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1136/003)

## Strategy Abstract
This detection strategy leverages log data from cloud service providers (CSPs) to monitor and analyze activities related to account management. Specifically, it focuses on unauthorized creation, modification, or usage of cloud accounts that could indicate adversarial behavior.

### Data Sources
- **Cloud Provider Logs:** IAM activity logs for AWS, Azure AD audit logs, Office 365 audit logs, and Google Workspace Admin Activity.
- **SIEM Integration:** Aggregating data from various CSPs into a Security Information and Event Management (SIEM) system to correlate events across different platforms.

### Patterns Analyzed
- Unusual account creation patterns, such as high frequency or out-of-hours activity.
- Access modifications not aligned with established security policies.
- Correlation of account activities that coincide with known indicators of compromise (IoCs).

## Technical Context
Adversaries often leverage cloud environments to establish persistence and maintain access. They may create new accounts or modify existing ones without authorization to evade detection by traditional monitoring solutions.

### Adversary Execution
In the real world, adversaries might exploit misconfigurations in cloud services or use stolen credentials to perform actions such as:
- Creating new user accounts with elevated privileges.
- Modifying permissions on critical resources.
- Establishing backdoors using compromised accounts.

### Emulation Details
To emulate adversarial behavior for testing purposes:
1. **AWS:** Use the AWS Management Console or CLI to create a new IAM user and assign unnecessary permissions.
2. **Azure AD:** Utilize Azure Portal or Azure CLI to simulate account creation with elevated roles.
3. **Google Workspace:** Create a test admin account and modify policies that typically wouldn't be altered by standard users.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection might miss sophisticated adversaries who use legitimate credentials for malicious activities.
  - Time synchronization issues between CSPs can lead to delays in correlating events.
  
- **Assumptions:**
  - Organizations have properly configured audit logging on their cloud platforms.
  - Analysts are equipped with the necessary tools and knowledge to interpret log data accurately.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks conducted during off-hours.
- Automated scripts for maintenance or updates.
- New employees being onboarded into cloud services, leading to account creation spikes.

## Priority
**Severity: High**

Justification: Unauthorized access and manipulation of cloud accounts can lead to significant breaches, including data exfiltration, financial loss, and reputational damage. The persistent nature of these threats necessitates robust detection strategies.

## Validation (Adversary Emulation)
### Instructions for Test Environment

#### AWS
1. Log in to the AWS Management Console.
2. Navigate to IAM > Users.
3. Click "Add user" and create a new IAM user with administrative access.

#### Azure AD
1. Log into the Azure Portal.
2. Go to Azure Active Directory > Users.
3. Select "New user" and configure the account as an administrator for testing purposes.

#### Azure CLI
```bash
az ad user create --display-name "Test User" --user-principal-name test@domain.com --password "<Your-Strong-Password>"
az role assignment create --assignee test@domain.com --role Owner
```

## Response
When an alert is triggered:
1. **Immediate Analysis:** Review the suspicious account activity logs to determine if it aligns with known adversary tactics.
2. **Containment:** Temporarily disable or revoke access for accounts involved in unauthorized activities.
3. **Investigation:** Conduct a thorough investigation to understand the scope and origin of the compromise.
4. **Remediation:** Implement corrective actions such as resetting passwords, reviewing permissions, and updating security policies.

## Additional Resources
- None available

This report serves as a foundational guideline for developing effective detection strategies against adversarial cloud account activities within enterprise environments. Further customization and refinement are recommended based on specific organizational needs and threat landscapes.