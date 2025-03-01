# Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by leveraging SAML Tokens (T1606.002). Specifically, it focuses on identifying and mitigating unauthorized access through manipulated SAML tokens that can be used in various platforms like Azure AD, SaaS, Windows, Office 365, Google Workspace, and IaaS.

## Categorization
- **MITRE ATT&CK Mapping:** T1606.002 - SAML Tokens
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Azure AD, SaaS, Windows, Office 365, Google Workspace, IaaS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1606/002)

## Strategy Abstract
The detection strategy focuses on monitoring and analyzing authentication logs from various platforms that utilize SAML tokens for Single Sign-On (SSO) capabilities. By integrating logs from Azure AD, Office 365, Google Workspace, and other relevant services, the strategy aims to identify unusual patterns or anomalies associated with token generation and usage. Key indicators include:
- Unusual login locations or IP addresses.
- Anomalies in token issuance frequency.
- Abnormal user behavior following authentication.

Data sources used for this detection include:
- Authentication logs
- Audit logs from Azure AD, Office 365, Google Workspace
- Network traffic monitoring data

## Technical Context
Adversaries may exploit SAML tokens to gain unauthorized access by manipulating or forging these tokens. This often involves intercepting and altering the token during transmission or leveraging weaknesses in the identity provider's configuration.

In practice, adversaries execute this technique by:
1. Intercepting a valid SAML assertion.
2. Modifying claims such as user roles or permissions within the token.
3. Using the forged token to authenticate with elevated privileges.

Adversary emulation might involve creating test scenarios where an attacker intercepts and modifies a SAML token during transmission, then uses it to gain unauthorized access.

### Sample Commands for Emulation:
```shell
# Example of using tools like Burp Suite or Wireshark to intercept traffic
# Note: This is purely for testing in a controlled environment.
wireshark -k -i <interface> -f "tcp port 80"

# Simulate token modification (hypothetical)
sed 's/role=standard/role=admin/' intercepted-saml-token.xml > modified-saml-token.xml

# Use the modified token to authenticate
curl --location --request POST 'https://identityprovider.example.com/sso' \
--header 'Authorization: Bearer <modified-token>'
```

## Blind Spots and Assumptions
- **Blind Spots:** Detection may miss attacks if SAML tokens are entirely forged offline without interaction with the identity provider.
- **Assumptions:** It assumes that logs from all relevant platforms are accurately collected, synchronized in time, and have complete coverage of authentication events.

## False Positives
Potential false positives might include:
- Legitimate changes to user roles or permissions following organizational policy updates.
- Access from new geographical locations for legitimate users who travel frequently.
- Increased token issuance during known periods of high activity (e.g., end-of-quarter reports).

## Priority
**Severity:** High  
This technique represents a significant threat due to its potential to allow adversaries to gain elevated privileges and access sensitive data. The impact could be extensive, especially in environments heavily reliant on cloud services and SSO mechanisms.

## Validation (Adversary Emulation)
### Golden SAML Emulation Steps:
1. **Setup Test Environment:** Configure a test environment with Azure AD or a similar identity provider supporting SAML.
2. **Generate Valid Token:** Use the identity provider to generate a valid SAML token for a test user.
3. **Intercept and Modify Token:**
   - Utilize network interception tools (e.g., Burp Suite) to capture a legitimate SAML token.
   - Modify claims in the token, such as changing user roles or permissions.
4. **Use Modified Token:** Attempt authentication using the modified token against the test environment's service endpoint.

## Response
When an alert for this technique fires:
1. **Verify Alert Validity:** Confirm whether the detected activity is legitimate by cross-referencing with HR records and recent role changes.
2. **Investigate Anomalies:** Analyze the context around the anomaly, such as login locations, time of access, and associated IP addresses.
3. **Contain Potential Breach:**
   - Revoke suspicious SAML tokens immediately.
   - Temporarily disable affected user accounts if necessary.
4. **Notify Stakeholders:** Inform relevant teams (e.g., security operations, compliance) about the incident for further action.

## Additional Resources
- [MITRE ATT&CK Technique T1606.002](https://attack.mitre.org/techniques/T1606/002)

This ADS report provides a structured approach to detecting and mitigating adversarial attempts using SAML tokens across various platforms, ensuring robust security monitoring and response capabilities.