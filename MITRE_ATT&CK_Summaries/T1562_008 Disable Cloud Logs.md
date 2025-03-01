# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring through disabling cloud logs and other logging mechanisms in cloud environments.

## Categorization
- **MITRE ATT&CK Mapping:** T1562.008 - Disable Cloud Logs
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** IaaS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/008)

## Strategy Abstract
The detection strategy focuses on monitoring changes to logging configurations and activities that could indicate attempts to disable or bypass cloud logs. This includes analyzing data from various sources such as CloudTrail, Event Hub, Exchange Audit Logs, and more. Key patterns analyzed include:
- Unusual modifications to log settings.
- Deletion of log files or disabling of logging services.
- Access anomalies related to logging configurations.

## Technical Context
Adversaries may attempt to evade detection by altering logging mechanisms in cloud environments. Common techniques include:
- Disabling CloudTrail logs in AWS.
- Deleting Azure Event Hubs.
- Turning off Exchange Audit Logs in Office 365.
- Manipulating S3 lifecycle rules or VPC flow logs in AWS.

These actions can prevent security teams from tracking user activity and potential malicious behavior, thereby facilitating undetected data exfiltration or lateral movement within the network.

### Adversary Emulation Details
To understand how these techniques are executed, consider these sample commands:
- **AWS CloudTrail:** `aws cloudtrail update-trail --name <trail-name> --no-enable-log-file-validation`
- **Azure Event Hub:** `az eventhubs delete --resource-group <group> --namespace <namespace> --name <eventhub>`
- **Office 365 Audit Logs:** Using PowerShell to disable logging:
  ```powershell
  Set-OrganizationConfig -AuditLogDisabled $true
  ```

## Blind Spots and Assumptions
- Assumes that log monitoring is already configured across all relevant cloud services.
- May not detect sophisticated adversaries who use alternative methods to bypass detection.
- Relies on timely updates to detection rules as new evasion techniques are discovered.

## False Positives
Potential benign activities include:
- Legitimate administrative changes to logging configurations for maintenance or compliance reasons.
- Temporary disabling of logs during certain operations, such as bulk data migrations.

## Priority
**High**: Disabling logs can severely impact an organization's ability to detect and respond to security incidents. Given the critical role of logs in forensic analysis, any attempt to disable them should be treated with high priority.

## Validation (Adversary Emulation)
To validate this technique in a test environment:

### AWS - CloudTrail Changes
1. Use the AWS CLI: `aws cloudtrail update-trail --name <trail-name> --no-enable-log-file-validation`

### Azure - Eventhub Deletion
2. Execute: `az eventhubs delete --resource-group <group> --namespace <namespace> --name <eventhub>`

### Office 365 - Exchange Audit Log Disabled
3. Run PowerShell command: 
   ```powershell
   Set-OrganizationConfig -AuditLogDisabled $true
   ```

### AWS - Disable CloudTrail Logging Through Event Selectors using Stratus
4. Configure event selectors to exclude necessary data.

### AWS - CloudTrail Logs Impairment Through S3 Lifecycle Rule using Stratus
5. Set lifecycle policies to automatically delete log files in S3 buckets.

### AWS - Remove VPC Flow Logs using Stratus
6. Delete or disable flow logs for specific VPCs.

### AWS CloudWatch Log Group Deletes
7. Use: `aws logs delete-log-group --log-group-name <log-group>`

### AWS CloudWatch Log Stream Deletes
8. Execute: `aws logs delete-export-task --task-id <task-id>`

### Office 365 - Set Audit Bypass For a Mailbox
9. Apply audit bypass settings for specific mailboxes.

### GCP - Delete Activity Event Log
10. Use Google Cloud Console or CLI to remove activity event logs.

## Response
When an alert fires, analysts should:
- Immediately review recent changes to logging configurations.
- Identify the source of the change and assess its legitimacy.
- Restore any disabled logs and reinforce logging policies.
- Investigate related activities for potential security incidents.

## Additional Resources
Additional references and context are currently unavailable. However, organizations can refer to cloud provider documentation and cybersecurity forums for updates on new evasion techniques and detection methods.