# Alerting & Detection Strategy (ADS) Report

## Goal
The primary objective of this detection strategy is to identify adversarial attempts to bypass security monitoring using container technologies on IaaS platforms. This technique aims to detect unauthorized discovery and enumeration activities within cloud infrastructure, focusing specifically on adversarial actions that seek to exploit or gather information about hosted services.

## Categorization
- **MITRE ATT&CK Mapping:** T1580 - Cloud Infrastructure Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** IaaS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1580)

## Strategy Abstract
The detection strategy leverages multiple data sources, including cloud access logs (e.g., API calls to AWS services), container management platform logs, and network traffic analysis. The patterns analyzed involve unusual enumeration of resources or security groups that are not typical for regular administrative tasks. Key indicators include anomalous spikes in API call frequencies targeting specific cloud resources, unexpected cross-region or cross-account requests, and abnormal access patterns by non-administrative accounts.

## Technical Context
Adversaries often attempt to enumerate cloud infrastructure to identify potential attack vectors. This may involve using publicly available APIs to list EC2 instances, security groups, IAM roles, and VPC details. In the real world, adversaries might execute scripts or use tools like AWS CLI or Boto3 (a Python SDK for AWS) to automate these enumeration activities.

### Adversary Emulation Details:
- **AWS - EC2 Enumeration from Cloud Instance:**
  ```bash
  aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value[],State.Name]'
  ```
  
- **AWS - EC2 Security Group Enumeration:**
  ```bash
  aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]'
  ```

## Blind Spots and Assumptions
- Assumes that legitimate administrative activities follow a recognizable pattern and frequency.
- May not detect sophisticated adversaries who carefully mimic normal behavior to evade detection.
- Limited visibility into encrypted or obfuscated API calls could prevent accurate detection.

## False Positives
Potential benign activities that might trigger false alerts include:
- Regular maintenance tasks by system administrators performing inventory checks on EC2 instances or security groups.
- Automated scripts scheduled for routine audits of cloud resources.
- Legitimate third-party tools accessing the environment as part of their service offering.

## Priority
**Severity: High**

The potential impact of undetected adversarial enumeration is significant, given that it can lead to further exploitation, data exfiltration, or lateral movement within a cloud environment. Detecting these activities early in the kill chain is crucial for preventing more severe security breaches.

## Validation (Adversary Emulation)
### AWS - EC2 Enumeration from Cloud Instance
1. Set up an IAM role with permissions to describe instances and attach it to an EC2 instance.
2. Install AWS CLI on the EC2 instance.
3. Execute the enumeration command:
   ```bash
   aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value[],State.Name]'
   ```
4. Monitor CloudTrail logs to capture API activity and verify alert generation.

### AWS - EC2 Security Group Enumeration
1. Ensure IAM permissions include `ec2:DescribeSecurityGroups`.
2. Use the CLI command:
   ```bash
   aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]'
   ```
3. Check CloudTrail logs for the API call and confirm if an alert is triggered.

## Response
When an alert fires indicating potential adversarial enumeration activities:
1. **Immediate Containment:** Temporarily restrict permissions on suspicious IAM roles or instances to prevent further unauthorized access.
2. **Investigation:** Examine related logs in detail, focusing on recent changes in permissions and activity patterns of the involved accounts.
3. **Correlation:** Correlate with other alerts to determine if this is part of a larger attack pattern.
4. **Remediation:** Update security policies to mitigate similar risks in the future, including tightening IAM roles and monitoring scripts.

## Additional Resources
- [AWS Security Best Practices](https://aws.amazon.com/security/)
- [CloudTrail User Guide](https://docs.aws.amazon.com/cloudtrail/)

This report outlines a structured approach to detecting adversarial enumeration activities within cloud environments using IaaS platforms, emphasizing proactive measures and timely responses.