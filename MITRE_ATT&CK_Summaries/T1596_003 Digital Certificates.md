# Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts to use digital certificates maliciously to bypass security monitoring.

## Categorization
- **MITRE ATT&CK Mapping:** T1596.003 - Digital Certificates
- **Tactic / Kill Chain Phases:** Reconnaissance
- **Platforms:** PRE
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1596/003)

## Strategy Abstract
The detection strategy leverages endpoint detection and response (EDR) data, network traffic logs, and certificate transparency logs to identify unusual patterns involving digital certificates. By analyzing anomalies in certificate generation or usage, such as certificates issued for internal domains but used externally, the system can flag potentially malicious activities.

### Data Sources
- Endpoint Detection & Response (EDR)
- Network Traffic Logs
- Certificate Transparency Logs

### Patterns Analyzed
- Issuance of certificates with unusual attributes.
- Internal domain names in public certificates.
- Uncommon certificate authority usage for internal domains.

## Technical Context
Adversaries might use digital certificates to impersonate legitimate services, facilitating data exfiltration or command and control (C2) communication. They may exploit trusted internal Certificate Authorities (CAs) to issue certificates that appear benign to security monitoring tools but are used maliciously in external contexts.

### Real-World Execution
Adversaries often employ these techniques during reconnaissance phases to gather information without detection, enabling subsequent attack stages such as lateral movement or data exfiltration. They may use compromised internal CAs or create unauthorized sub-CAs for certificate issuance.

## Blind Spots and Assumptions
- Assumes all legitimate certificates are registered in transparency logs.
- Relies on the accuracy of EDR tools in logging certificate usage and generation.
- May not detect zero-day exploits that bypass current detection mechanisms.
- Limited by the visibility into encrypted network traffic where anomalies might occur.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate penetration testing or incident response activities involving certificates.
- Misconfigurations in internal CAs leading to unusual certificate issuance patterns.
- Development and testing environments using non-standard domains.

## Priority
**Priority: High**

Justification: The potential impact of adversaries bypassing security controls using digital certificates is significant. Such techniques can facilitate undetected data exfiltration or establish covert C2 channels, compromising sensitive information and organizational integrity.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Setup Environment**
   - Prepare a test network with EDR tools deployed.
   - Configure Certificate Transparency Logs for monitoring.

2. **Simulate Adversarial Behavior**
   - Use `openssl` to generate a self-signed certificate for an internal domain:
     ```bash
     openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout test.key -out test.crt \
       -subj "/CN=internal.testdomain.com"
     ```

3. **Use Certificate in Network**
   - Configure a testing server to use the generated certificate.
   - Attempt to access this server from an external environment.

4. **Monitor and Analyze Alerts**
   - Observe alerts triggered by EDR, network logs, and transparency logs.
   - Validate whether the detection mechanisms correctly identify and flag the activity as suspicious.

## Response
When the alert fires:
- Verify the legitimacy of certificate issuance and usage through incident response protocols.
- Isolate affected systems to prevent potential lateral movement or data exfiltration.
- Conduct a thorough investigation to determine if internal CAs were compromised.
- Update security policies to tighten control over certificate issuance and monitoring.

## Additional Resources
Additional references and context:
- None available

---

This report provides a comprehensive overview of the strategy for detecting malicious use of digital certificates within an organization, considering potential adversarial tactics, detection methods, and response guidelines.