# Alerting & Detection Strategy (ADS) Report

## Goal
The aim of this detection technique is to identify adversarial attempts to bypass security monitoring systems by leveraging containerization platforms on Infrastructure as a Service (IaaS). This involves detecting unauthorized access and exfiltration of data through cloud storage objects, which adversaries may use to maintain persistence or evade traditional security measures.

## Categorization

- **MITRE ATT&CK Mapping:** T1530 - Data from Cloud Storage Object
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** IaaS
  - [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1530)

## Strategy Abstract

This detection strategy focuses on monitoring cloud environments, specifically targeting data storage objects. It leverages logs from cloud service providers (CSPs) such as AWS S3 and Azure Blob Storage to identify anomalous access patterns indicative of unauthorized exfiltration or data manipulation.

### Data Sources:
- Cloud provider logs (AWS CloudTrail, Azure Monitor Logs)
- Network traffic captures
- Container orchestration platform logs (e.g., Kubernetes Audit Logs)

### Patterns Analyzed:
- Unusual API calls associated with storage object accesses
- Access from unrecognized IP addresses or geographic locations
- Large data transfers to external endpoints
- Usage of containers for accessing cloud storage objects without proper authentication

## Technical Context

Adversaries may use IaaS platforms to deploy containers that facilitate unauthorized access and exfiltration of sensitive data. This is often achieved by exploiting misconfigured permissions on cloud storage accounts, allowing for anonymous or unauthenticated access.

### Real-World Execution:
1. **Exploiting Misconfigurations:** Adversaries scan cloud environments for publicly accessible storage objects.
2. **Container Deployment:** Containers are used to run scripts that interact with these storage objects, bypassing traditional endpoint monitoring.
3. **Data Exfiltration:** Data is extracted and transferred outside the organization, often through encoded or encrypted channels.

### Adversary Emulation:
- Use tools like MicroBurst for AWS and PowerShell scripts for Azure to simulate unauthorized access.
- Test scenarios include scanning for anonymous permissions on storage accounts and attempting data extraction from misconfigured objects.

## Blind Spots and Assumptions

- **Limitations:** This strategy may not detect exfiltration through encrypted channels if encryption keys are controlled by the adversary.
- **Assumptions:** It assumes that cloud provider logs are comprehensive and accurately configured to capture all relevant API calls.
- **Gaps:** Limited visibility into encrypted traffic within containers can obscure detection of data transfers.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate automated scripts accessing storage objects for backup or maintenance purposes.
- Authorized users from unusual locations conducting business-related tasks.
- Scheduled jobs transferring large volumes of data as part of normal operations.

## Priority
**Severity: High**

Justification: The potential impact includes significant data breaches and persistent access by adversaries. Given the critical nature of cloud environments in modern IT infrastructure, ensuring robust detection mechanisms is imperative to mitigate these risks.

## Validation (Adversary Emulation)

### Azure

1. **Enumerate Azure Blobs with MicroBurst**
   - Install MicroBurst tool.
   - Execute `MicroBurst.exe --list-blobs` to enumerate accessible blobs in the target Azure storage account.

2. **Scan for Anonymous Access to Azure Storage (Powershell)**
   - Use the following PowerShell command:
     ```powershell
     Get-AzStorageAccount | ForEach-Object {Get-AzStorageBlob -Container "$($_.StorageAccountId)"}
     ```

### AWS

1. **Scan for Anonymous Access to S3**
   - Utilize the AWS CLI or a script like `s3checker`:
     ```bash
     aws s3api list-buckets --query 'Buckets[].Name'
     ```
   - Check each bucket's permissions using:
     ```bash
     aws s3api get-bucket-policy --bucket <bucket-name>
     ```

## Response

When an alert is triggered, analysts should:

1. **Verify the Alert:** Confirm if the access was authorized or part of a scheduled task.
2. **Investigate Anomalies:** Examine logs for unusual patterns or repeated unauthorized attempts.
3. **Contain the Threat:** Revoke permissions and isolate affected accounts or containers.
4. **Notify Stakeholders:** Inform relevant teams about the breach and ongoing mitigation efforts.

## Additional Resources

- None available

This report provides a comprehensive framework to detect adversarial activities involving cloud storage objects within IaaS environments, ensuring robust security monitoring and response capabilities.