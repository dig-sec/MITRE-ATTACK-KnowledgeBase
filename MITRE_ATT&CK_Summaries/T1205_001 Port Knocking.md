# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring systems using port knocking techniques.

## Categorization
- **MITRE ATT&CK Mapping:** T1205.001 - Port Knocking
- **Tactic / Kill Chain Phases:** Defense Evasion, Persistence, Command and Control
- **Platforms:** Linux, macOS, Windows, Network

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1205/001)

## Strategy Abstract
The detection strategy focuses on identifying port knocking sequences used by adversaries to bypass security measures. This involves monitoring network traffic for unusual patterns that signify a sequence of closed ports being accessed in a specific order, revealing an open port afterward.

**Data Sources:**
- Network Traffic Logs
- Firewall Access Logs

**Patterns Analyzed:**
- Repeated access attempts to closed ports from the same source within a short time frame.
- Sudden opening of a previously closed port following these access patterns.

## Technical Context
Port knocking is a method by which a client can gain remote network access to a server without having to open unnecessary firewall ports. The technique involves sending connection attempts (knocks) to a pre-defined sequence of closed TCP or UDP ports on the target host, and upon receiving this exact sequence, a firewall rule is triggered to temporarily allow incoming connections.

**Adversary Execution:**
- Adversaries utilize scripts that automate the port knocking process to access secure systems undetected.
- They may employ tools like `knockd` (Linux) or custom-built solutions for specific environments.

**Example Commands:**
```bash
# Example using knock command-line tool
knock -v 192.168.1.10 7000 8000 9000
```

## Blind Spots and Assumptions
- **Blind Spots:** Detection may not capture custom or complex port knocking sequences with no prior knowledge of potential patterns.
- **Assumptions:** Assumes that network traffic logs are comprehensive and correctly time-stamped. It also assumes the firewall is configured to log access attempts to closed ports.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate security testing or penetration testing by authorized personnel.
- Misconfigured applications that inadvertently attempt connections to various ports in a sequence.
- Network scanning tools used for maintenance or diagnostics within an organization.

## Priority
**Priority Level: High**

**Justification:** Port knocking is often used by sophisticated adversaries seeking to evade traditional detection mechanisms, making it critical to detect and mitigate such activities promptly. The potential impact on security posture warrants high priority due to the stealth nature of the technique.

## Validation (Adversary Emulation)
### Step-by-step Instructions
1. **Setup Test Environment:**
   - Configure a server with firewall rules that block all incoming connections by default.
   - Install and configure `knockd` or an equivalent port knocking service on the server.

2. **Define Port Sequence:**
   - Set up a test sequence of closed ports (e.g., 7000, 8000, 9000) in the firewall configuration that triggers access to a specific service upon receiving correct knock attempts.

3. **Simulate Adversarial Action:**
   - Use a tool like `knock` on another machine within the network to simulate an adversary knocking the defined sequence of ports.
   
4. **Monitor Logs and Alerts:**
   - Verify that firewall logs capture the sequence of access attempts.
   - Check if any alerts are triggered based on predefined detection criteria.

## Response
### Guidelines for Analysts
1. **Verify Alert Validity:**
   - Cross-reference alert details with known test scenarios to rule out false positives.
   - Review network traffic logs for unusual patterns that align with port knocking sequences.

2. **Immediate Actions:**
   - Temporarily block the source IP associated with suspicious activity.
   - Increase monitoring on affected systems and network segments.

3. **Investigation:**
   - Conduct a thorough investigation to determine if the port knocking is part of a broader attack attempt.
   - Assess potential entry points and compromised assets.

4. **Reporting and Remediation:**
   - Document findings and share with relevant stakeholders.
   - Implement necessary firewall rule changes to prevent similar attempts in the future.

## Additional Resources
- None available

This report outlines a comprehensive strategy for detecting port knocking activities, providing technical context, potential limitations, and response guidelines. It is crucial to continuously refine detection mechanisms to adapt to evolving adversarial techniques.