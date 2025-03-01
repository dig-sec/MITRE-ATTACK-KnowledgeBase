# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containers by identifying the unauthorized acquisition and use of additional cloud credentials.

## Categorization
- **MITRE ATT&CK Mapping:** T1098.001 - Additional Cloud Credentials
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** IaaS, Azure AD

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1098/001)

## Strategy Abstract
The detection strategy focuses on identifying unauthorized access and utilization of additional cloud credentials to maintain persistence within a compromised environment. Key data sources include identity logs from Azure AD, IaaS platform activity logs, and container orchestration system logs (e.g., Kubernetes audit logs). Patterns analyzed involve unusual credential creation or usage patterns, especially those not aligning with the normal operational profiles of users or services.

## Technical Context
Adversaries often attempt to gain persistence by creating new credentials within cloud environments. This allows them continued access even if initial entry points are closed. They may use legitimate administrative tools but for malicious purposes, such as creating service principals in Azure AD without authorization, or generating AWS IAM keys that grant broad permissions.

### Adversary Emulation Details
- **Azure AD Application Hijacking - Service Principal:** 
  - Example command: `New-AzADServicePrincipal -DisplayName "MaliciousSP"`
- **Azure AD Application Hijacking - App Registration:** 
  - Use Azure CLI to register applications without proper authorization.
- **AWS - Create Access Key and Secret Key:** 
  - Example command: `aws iam create-access-key --user-name MaliciousUser`

## Blind Spots and Assumptions
- Assumes detection systems have access to comprehensive logs across all relevant cloud services.
- Relies on predefined thresholds for "unusual" activity, which may need tuning based on specific organizational norms.
- May not detect credential usage that mimics legitimate patterns closely.

## False Positives
Potential false positives include:
- Legitimate use of tools or automation scripts by IT staff to manage cloud resources.
- Scheduled tasks or processes that generate new credentials as part of routine operations.
- Misconfigurations causing unexpected log entries indicative of unauthorized access attempts.

## Priority
**High**: Unauthorized acquisition and utilization of additional cloud credentials pose significant risks. They allow adversaries to maintain control over compromised systems, potentially leading to data exfiltration, further lateral movement, or additional breaches within the organization.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

### Azure AD Application Hijacking - Service Principal
1. Log into your Azure account with administrative privileges.
2. Use PowerShell to create a new service principal:  
   ```powershell
   New-AzADServicePrincipal -DisplayName "MaliciousSP"
   ```
3. Monitor Azure AD activity logs for creation events.

### Azure AD Application Hijacking - App Registration
1. Open the Azure portal.
2. Navigate to “App registrations” and attempt to register a new application without proper authorization.
3. Track any unauthorized registration attempts via Azure monitoring tools.

### AWS - Create Access Key and Secret Key
1. Use an IAM user with administrative privileges in AWS CLI.
2. Execute:  
   ```bash
   aws iam create-access-key --user-name MaliciousUser
   ```
3. Verify the creation of new credentials through CloudTrail logs.

## Response
When this alert fires, analysts should:

- Immediately investigate the source and intent behind the credential acquisition.
- Revoke unauthorized or suspicious credentials to prevent further access.
- Conduct a thorough audit of recent activities associated with the compromised accounts or services.
- Implement additional monitoring and controls for sensitive operations within cloud environments.

## Additional Resources
Additional references and context:
- None available

---

This report provides a structured approach to detecting and responding to adversarial use of containers in bypassing security measures, aligned with Palantir's ADS framework.