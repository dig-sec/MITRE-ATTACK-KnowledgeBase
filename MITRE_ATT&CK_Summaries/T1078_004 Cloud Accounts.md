# Alerting & Detection Strategy (ADS) Report: Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
The primary goal of this detection strategy is to identify and alert on adversarial attempts to bypass security monitoring using container technologies within cloud environments.

## Categorization
- **MITRE ATT&CK Mapping:** T1078.004 - Cloud Accounts
- **Tactic / Kill Chain Phases:**
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
- **Platforms:** 
  - Azure AD
  - Office 365
  - SaaS
  - IaaS
  - Google Workspace

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1078/004)

## Strategy Abstract
This detection strategy leverages various data sources including logs from cloud service providers (Azure, AWS, GCP), network traffic data, and endpoint monitoring tools. The patterns analyzed focus on anomalies related to the creation, modification, or usage of container accounts in unauthorized ways.

Key indicators include:
- Creation of new service accounts with elevated permissions.
- Unusual activity patterns associated with newly created containers.
- Abnormal access from non-standard IP addresses or geolocations.

## Technical Context
Adversaries may bypass security monitoring by exploiting cloud-native features, such as creating service accounts within Google Cloud Platform (GCP) that are used to deploy containers. These containers can then be utilized for malicious activities while evading traditional detection mechanisms.

### Adversary Emulation Details:
- **GCP Service Account Creation:** Attackers might create service accounts with permissions that allow for unrestricted access to cloud resources.
- **Azure Runbook Modifications:** They may modify Azure Automation runbooks to execute unauthorized commands or scripts.
- **Custom IAM Roles in GCP:** By creating custom IAM roles, adversaries can grant themselves excessive privileges without triggering standard monitoring alerts.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Lack of visibility into all configurations for cloud-native services could lead to missed detections.
  - Encrypted communications within containers may obscure malicious activities.
  
- **Assumptions:**
  - Assumes that baseline activity patterns are well-understood and deviations can be detected reliably.
  - Relies on the integrity and completeness of log data from cloud providers.

## False Positives
Potential false positives include:
- Legitimate deployment of new service accounts for business continuity or scaling purposes.
- Authorized use of automation tools by IT personnel that may not follow standard procedures but are benign.
- Access from approved locations during scheduled maintenance windows.

## Priority
**Severity: High**

Justification: The ability to bypass security monitoring using cloud-native features poses a significant threat as it allows adversaries to operate with elevated privileges, potentially leading to data breaches or service disruptions.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

#### Creating GCP Service Account and Service Account Key
1. **Create Service Account:**
   - Use the Google Cloud Console or gcloud CLI.
   - Command: `gcloud iam service-accounts create my-service-account --display-name "My Service Account"`
   
2. **Create a Key for the Service Account:**
   - Command: `gcloud iam service-accounts keys create ~/key.json --iam-account=my-service-account@my-project.iam.gserviceaccount.com`

#### Azure Persistence Automation Runbook Created or Modified
1. **Access Azure Automation:**
   - Use Azure Portal to access your Automation account.
   
2. **Create/Modify a Runbook:**
   - Create a new runbook or modify an existing one using PowerShell, Python, etc.
   - Command Example (PowerShell): 
     ```powershell
     New-AzAutomationRunbook -Name "MyNewRunbook" -ResourceGroupName "myResourceGroup" -Type PowerShellWorkflow -Description "Example Runbook"
     ```

#### GCP - Create Custom IAM Role
1. **Define a Custom Role:**
   - Use the Google Cloud Console or gcloud CLI.
   - Command: 
     ```bash
     gcloud iam roles create custom_role --project=my-project --title="Custom Role" \
       --description="Role for specific tasks" --permissions=compute.instances.start,compute.instances.stop
     ```

## Response
When an alert is triggered:
1. **Immediate Isolation:** Quarantine the affected accounts or containers to prevent further unauthorized actions.
2. **Investigation:**
   - Review logs and identify the source of suspicious activities.
   - Assess whether new service accounts or IAM roles were created without authorization.
3. **Remediation:**
   - Revoke unnecessary permissions from service accounts and custom roles.
   - Update policies to prevent similar future occurrences.

## Additional Resources
- None available

This report provides a comprehensive overview of detecting adversarial attempts using containers within cloud environments, aligned with Palantir's Alerting & Detection Strategy framework.