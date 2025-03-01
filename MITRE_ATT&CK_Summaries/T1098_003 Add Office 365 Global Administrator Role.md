# Palantir Alerting & Detection Strategy (ADS) Report

## Goal
This detection strategy aims to identify adversarial attempts to gain elevated privileges by adding a user to the Office 365 Global Administrator role, which could enable persistent access and control over an organization's resources.

## Categorization
- **MITRE ATT&CK Mapping:** T1098.003 - Add Office 365 Global Administrator Role
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Office 365

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1098/003)

## Strategy Abstract
The detection strategy leverages data from Azure Active Directory (Azure AD) audit logs and Office 365 management activities. It analyzes patterns indicating unauthorized or suspicious changes in user roles, particularly the addition of users to high-privilege roles such as Global Administrator.

### Data Sources:
- **Azure AD Audit Logs:** Track role assignments, logins, and permission modifications.
- **Office 365 Management Activity Logs:** Monitor administrative actions within Office 365 environments.

### Patterns Analyzed:
- Sudden changes in user roles without prior authorization or documentation.
- Role changes initiated from unrecognized IP addresses or geolocations.
- Unusual patterns of multiple role assignments to a single account over short periods.

## Technical Context
Adversaries often seek to elevate their privileges within corporate environments by manipulating administrative roles. By adding themselves or an accomplice as Office 365 Global Administrators, they can bypass standard security controls and access sensitive data.

### Real-World Execution:
1. **Reconnaissance:** Identify targets with high-level permissions.
2. **Credential Compromise:** Gain initial access through phishing, brute force, or other methods to acquire credentials of an existing administrator.
3. **Role Escalation:** Use the compromised account to assign themselves the Global Administrator role.

### Adversary Emulation:
To emulate this technique, perform these steps in a controlled environment:

1. **Azure AD Role Assignment:**
   - Log into Azure Portal with administrative privileges.
   - Navigate to Azure Active Directory -> Roles and administrators.
   - Assign a test user account the Global Administrator role.

2. **Simulated Persistence Scenario:**
   - Conduct a Business Email Compromise (BEC) attack simulation by initiating a password reset for an internal user.
   - Once access is regained, add this compromised user to the Company Administrator role in Office 365.

## Blind Spots and Assumptions
- Assumes that all administrative changes are properly logged and accessible in Azure AD and Office 365 audit logs.
- May not detect manual processes or off-the-record changes bypassing logging mechanisms.
- Assumes network security controls do not obscure unauthorized access attempts by disguising them as legitimate traffic.

## False Positives
Potential false positives include:
- Authorized IT personnel performing routine role assignments during maintenance windows.
- Changes initiated from corporate VPNs or known trusted IP addresses that are later compromised.
- Users with legitimate reasons for temporary elevated privileges, such as during onboarding processes.

## Priority
**High:** The elevation to a Global Administrator role provides extensive control over an organization's Office 365 environment. Unauthorized changes can lead to significant data breaches and loss of sensitive information.

## Response
When the alert fires:
1. **Immediate Isolation:** Temporarily suspend the affected user account from elevated roles.
2. **Investigation:**
   - Review Azure AD and Office 365 audit logs for recent role assignments.
   - Verify the legitimacy of the initiating IP addresses and geolocations.
3. **Notification:**
   - Inform relevant stakeholders, including security teams and impacted users.
4. **Remediation:**
   - Revoke unauthorized roles and reset compromised passwords.
5. **Post-Incident Analysis:**
   - Assess potential data exposure and implement additional monitoring measures.

## Additional Resources
Additional references and context are not available for this specific technique beyond the MITRE ATT&CK framework link provided.

---

This report outlines a structured approach to detecting and responding to attempts at privilege escalation within Office 365 environments. By understanding adversary tactics and maintaining vigilant monitoring, organizations can better protect their critical assets from unauthorized access.