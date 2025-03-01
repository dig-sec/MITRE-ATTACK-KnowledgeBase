# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal

The objective of this technique is to detect adversarial attempts to modify domain trust settings within Azure Active Directory (Azure AD), thereby potentially bypassing security monitoring and gaining unauthorized access.

## Categorization

- **MITRE ATT&CK Mapping:** T1484.002 - Domain Trust Modification
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Windows, Azure AD

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1484/002)

## Strategy Abstract

The detection strategy involves monitoring changes to domain trust configurations within Azure AD. Data sources include Azure AD audit logs and security event logs from Windows environments. The analysis focuses on identifying unauthorized modifications to trusted domains or changes in domain trust relationships, which could indicate attempts to elevate privileges or evade defenses.

Patterns analyzed include:

- Unexpected creation or modification of cross-domain trusts.
- Changes in domain authentication settings without prior authorization.
- Unusual administrative activities related to domain trust configurations.

## Technical Context

Adversaries may execute this technique by leveraging compromised credentials to modify the trusted domains list within Azure AD. This can facilitate lateral movement and privilege escalation by allowing unauthorized access across linked domains.

### Adversary Emulation Details

To emulate this technique in a test environment:

1. **Add Federation to Azure AD:**
   - Use the Azure portal or PowerShell to configure domain federation settings.
   - Example command:
     ```powershell
     New-AzureADDomainFederationSettings -domainName "example.com" -domainAlternativeNames @("alt.example.com") -trustType Federated
     ```

## Blind Spots and Assumptions

- **Assumption:** Alerts are generated based on predefined thresholds for abnormal activity, assuming baseline behavior is well-established.
- **Blind Spot:** Legitimate administrative changes may not be captured if they fall outside expected patterns or occur during scheduled maintenance windows.

## False Positives

Potential benign activities that might trigger false alerts include:

- Scheduled domain trust updates as part of routine IT operations.
- Misconfigurations by administrators unfamiliar with security policies.
- Legitimate federation setup for new business integrations.

## Priority

**Severity: High**

Justification: Domain trust modifications can lead to significant unauthorized access and privilege escalation, compromising the entire network's integrity. The potential impact on organizational security makes this a high-priority detection target.

## Validation (Adversary Emulation)

### Step-by-Step Instructions:

1. **Set Up Test Environment:**
   - Create a separate Azure AD tenant for testing.
   - Ensure minimal permissions are assigned to test accounts.

2. **Add Federation to Azure AD:**
   - Use the PowerShell command provided above to configure domain federation settings in the test environment.

3. **Monitor and Validate:**
   - Enable detailed logging and monitoring on both Azure AD and Windows security events.
   - Verify that alerts trigger upon changes to domain trust configurations.

## Response

When an alert fires, analysts should:

1. **Verify Activity:** Confirm whether the detected change was authorized by checking with relevant IT departments or using change management logs.
2. **Contain Threat:**
   - Revert unauthorized changes if confirmed malicious.
   - Adjust access controls and permissions to prevent further exploitation.
3. **Investigate Further:**
   - Analyze associated logs for indicators of compromise (IoCs).
   - Determine the scope of potential lateral movement or privilege escalation.

## Additional Resources

Additional references and context are not available at this time. Analysts should consult Azure AD documentation and security best practices for further guidance on managing domain trust settings securely.