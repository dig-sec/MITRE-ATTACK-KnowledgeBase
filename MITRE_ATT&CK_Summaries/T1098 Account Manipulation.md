# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring using containers. It focuses on identifying suspicious activities that indicate the use of container technologies as a means to evade detection mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1098 - Account Manipulation
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, Azure AD, Office 365, IaaS, Linux, macOS, Google Workspace
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1098)

## Strategy Abstract
The detection strategy leverages multiple data sources including logs from container orchestration platforms (e.g., Kubernetes), network traffic analysis, and user behavior analytics. Key patterns analyzed include unusual creation of containers, abnormal access patterns to sensitive resources, and deviations from normal operational baselines.

## Technical Context
Adversaries often use containers to create isolated environments that can operate under the radar of traditional security systems. They may deploy malicious workloads within these containers or exploit container orchestration vulnerabilities to maintain persistence. Common tactics include creating unauthorized containers, modifying container images, and using container escape techniques.

### Adversary Emulation Details
- **Sample Commands:**
  - Docker: `docker run -d --name evil-container my-malicious-image`
  - Kubernetes: `kubectl run malicious-pod --image=malicious-image`

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection might miss zero-day vulnerabilities in container technologies.
  - Limited visibility into encrypted or obfuscated traffic within containers.

- **Assumptions:**
  - Assumes baseline behavior models are accurately defined for normal operations.
  - Relies on the availability and integrity of log data from all relevant sources.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate deployment of new containerized applications during development or testing phases.
- Routine updates to container images by authorized personnel.
- Scheduled maintenance tasks involving container orchestration systems.

## Priority
**Severity: High**

Justification: The use of containers for adversarial purposes poses a significant risk due to their ability to bypass traditional security controls and facilitate persistent access to sensitive resources. Early detection is crucial to mitigate potential breaches.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Admin Account Manipulate**
   - Gain administrative privileges on the container orchestration platform.
   - Modify permissions or roles to allow unauthorized actions.

2. **Domain Account and Group Manipulate**
   - Create new service accounts with elevated privileges within domain environments.
   - Add these accounts to privileged groups.

3. **AWS - Create a group and add a user to that group**
   ```bash
   aws iam create-group --group-name EvilGroup
   aws iam add-user-to-group --user-name EvilUser --group-name EvilGroup
   ```

4. **Azure AD - adding user to Azure AD role**
   ```powershell
   New-AzureADDirectoryRoleMember -ObjectId <role-object-id> -RefObjectId <user-object-id>
   ```

5. **Azure AD - adding service principal to Azure AD role**
   ```powershell
   New-AzureADServiceAppRoleAssignment -ObjectId <service-principal-object-id> -Id <app-role-id> -PrincipalId <principal-object-id> -ResourceId <resource-object-id>
   ```

6. **Azure - adding user to Azure role in subscription**
   ```bash
   az role assignment create --assignee <user-email-or-object-id> --role Contributor --scope /subscriptions/<subscription-id>
   ```

7. **Azure - adding service principal to Azure role in subscription**
   ```bash
   az ad sp create-for-rbac --name EvilSP
   az role assignment create --assignee <service-principal-appid> --role Contributor --scope /subscriptions/<subscription-id>
   ```

8. **Azure AD - adding permission to application**
   - Grant additional permissions to an application within Azure AD.

9. **Password Change on Directory Service Restore Mode (DSRM) Account**
   - Attempt password changes while in DSRM to gain unauthorized access.

10. **Domain Password Policy Check: Short Password**
    - Enforce or bypass policies that require complex passwords.

11. **Domain Password Policy Check: No Number in Password**
    - Create accounts with simple passwords lacking numeric characters.

12. **Domain Password Policy Check: No Special Character in Password**
    - Similar to the above, but without special characters.

13. **Domain Password Policy Check: No Uppercase Character in Password**
    - Enforce policies allowing only lowercase passwords.

14. **Domain Password Policy Check: No Lowercase Character in Password**
    - Create accounts with only uppercase passwords.

15. **Domain Password Policy Check: Only Two Character Classes**
    - Utilize passwords that meet the minimum complexity but are otherwise simple.

16. **Domain Password Policy Check: Common Password Use**
    - Use common or default passwords to bypass security measures.

17. **GCP - Delete Service Account Key**
    ```bash
    gcloud iam service-accounts keys delete <key-file> --iam-account <service-account-email>
    ```

## Response
When an alert fires, analysts should:
1. Immediately isolate affected containers and hosts.
2. Review logs to identify the scope of unauthorized activities.
3. Revoke any compromised credentials or permissions.
4. Conduct a thorough investigation to determine the root cause and extent of the breach.
5. Update detection rules and baselines based on findings.

## Additional Resources
- None available

This report provides a comprehensive framework for detecting and responding to adversarial attempts to use containers as a means to bypass security monitoring. Continuous refinement and validation are essential to maintain effective defense mechanisms.