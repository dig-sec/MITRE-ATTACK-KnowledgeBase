# Alerting & Detection Strategy: Remote Service Session Hijacking (T1563)

## Goal
The goal of this technique is to detect adversarial attempts at remote service session hijacking. This involves identifying when an adversary attempts to take over a legitimate user's session on a remote system, which allows them to move laterally within the network and gain unauthorized access.

## Categorization

- **MITRE ATT&CK Mapping:** [T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563)
- **Tactic / Kill Chain Phases:** Lateral Movement
- **Platforms:** Linux, macOS, Windows

## Strategy Abstract

The detection strategy for T1563 focuses on identifying unauthorized session takeovers. This involves monitoring and analyzing various data sources such as:

- **Network Traffic:** Analyze anomalies in network traffic patterns that might indicate hijacking attempts.
- **Authentication Logs:** Monitor logs for unusual or repeated authentication events that suggest session hijacking.
- **Process Monitoring:** Track processes starting unexpectedly with credentials of a legitimate user.

Patterns analyzed include:
- Unusual login locations or times.
- Multiple failed login attempts followed by a successful one from the same IP address.
- Processes running under user accounts without explicit user initiation.

## Technical Context

Adversaries typically execute remote service session hijacking using techniques such as credential dumping, exploiting weak authentication mechanisms, or leveraging stolen credentials. In real-world scenarios, attackers might use tools like Mimikatz to extract plaintext passwords and then log in remotely using these credentials.

### Adversary Emulation Details
- **Sample Commands:** 
  - On Windows: `mimikatz.exe "sekurlsa::logonpasswords"`
  - On Linux: Use of `ssh` with stolen credentials.
  
- **Test Scenarios:**
  - Simulate credential theft using Mimikatz or similar tools and attempt to authenticate on a remote service.

## Blind Spots and Assumptions

### Known Limitations:
- Detection may not cover all methods of session hijacking, especially novel or highly customized techniques.
- Assumes that the network infrastructure supports comprehensive logging and monitoring capabilities.

### Assumptions:
- The network has robust security controls in place to detect anomalies effectively.
- Analysts are trained to interpret alerts related to session hijacking accurately.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate remote access by users who frequently log in from multiple locations or devices.
- Scheduled maintenance tasks running under user credentials without explicit initiation.
- Network configurations causing unusual traffic patterns, such as VPNs or proxies.

## Priority
**Severity:** High

**Justification:** Remote service session hijacking poses a significant threat as it allows adversaries to move laterally within the network, potentially accessing sensitive data and systems. The impact of successful hijacking can be severe, making it imperative to prioritize detection and response strategies for this technique.

## Validation (Adversary Emulation)

### Step-by-Step Instructions:

1. **Environment Setup:**
   - Prepare a controlled test environment with Windows/Linux machines.
   - Ensure logging is enabled on all devices.

2. **Simulate Credential Theft:**
   - On a target machine, use tools like Mimikatz (Windows) to extract credentials.
   
3. **Attempt Remote Authentication:**
   - Use stolen credentials to log in remotely via SSH or RDP from another machine within the network.

4. **Monitor and Analyze Logs:**
   - Check authentication logs for unusual patterns such as multiple failed attempts followed by a success.
   - Review network traffic for anomalies indicating unauthorized access.

## Response

When an alert for T1563 fires, analysts should:

1. **Verify Alert Validity:** Confirm whether the activity is legitimate or malicious by reviewing user behavior and context.
2. **Contain Threat:**
   - Temporarily disable the affected account to prevent further unauthorized access.
   - Isolate compromised systems from the network if necessary.
   
3. **Investigate Further:**
   - Analyze logs for additional indicators of compromise.
   - Determine the scope of the breach, including potential lateral movement.

4. **Remediate and Recover:**
   - Reset credentials for affected accounts.
   - Implement additional security controls to prevent future incidents.

5. **Document Incident:**
   - Record findings, actions taken, and lessons learned for future reference and improvement.

## Additional Resources

- [MITRE ATT&CK Technique T1563](https://attack.mitre.org/techniques/T1563)
- [Understanding Session Hijacking](https://owasp.org/www-community/attacks/Session_hijacking)

This report provides a comprehensive overview of the detection strategy for Remote Service Session Hijacking, aligning with Palantir's ADS framework.