# Alerting & Detection Strategy: Domain Fronting (T1090.004)

## Goal
The primary objective of this detection technique is to identify adversarial attempts to bypass security monitoring and obfuscate their command-and-control communications using domain fronting. This strategy helps in uncovering malicious activities hidden behind legitimate-looking domains, which can be used for data exfiltration or remote control by threat actors.

## Categorization
- **MITRE ATT&CK Mapping:** T1090.004 - Domain Fronting
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1090/004)

## Strategy Abstract
The detection strategy focuses on identifying unusual patterns in network traffic that are indicative of domain fronting. Key data sources include DNS logs, HTTP/S headers, and network flow data.

1. **Data Sources:**
   - DNS Logs: Look for discrepancies between the requested domain name (e.g., Google) and the actual IP address being communicated with.
   - HTTP/S Headers: Analyze `Host` header requests that do not match the target IP address or expected destination domains.
   - Network Flow Data: Identify unexpected traffic patterns, such as data routed through a public CDN to reach an unusual endpoint.

2. **Patterns Analyzed:**
   - Mismatches between domain names in DNS requests and host IPs in network flows.
   - Uncommon `Host` header values that do not correspond with the target server's IP address.
   - Traffic volumes from legitimate domains unexpectedly routing to suspicious IPs.

## Technical Context
Domain fronting is a technique where an application sends requests through a major, trusted domain (e.g., Google or Amazon) while actually communicating with another hidden endpoint. This can be used to evade network defenses by masking the true destination of traffic.

**Adversary Execution:**
- Adversaries typically set up their own server behind a large content delivery network (CDN) service.
- The client application uses legitimate domain names for initial DNS resolution but redirects traffic through these domains to reach the actual malicious endpoint.
  
Example Commands:
```bash
# Sample command that might be used in an adversarial script to initiate domain fronting
curl -H "Host: hidden-service.example.com" https://trusted-domain.com/special-endpoint
```

**Test Scenarios:**
- Simulate DNS requests where the `A` record for a known public service points to a suspicious IP.
- Create HTTP/S traffic that uses legitimate domains in headers but targets an unrelated endpoint.

## Blind Spots and Assumptions
- **Blind Spots:** The detection may not capture all instances of domain fronting, especially if adversaries use advanced techniques or alternate communication methods like encrypted DNS queries.
- **Assumptions:** Assumes that network monitoring tools can accurately differentiate between legitimate and malicious traffic patterns. Also assumes a baseline understanding of normal traffic behavior for each organization.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate services using domain fronting to bypass geo-restrictions, such as VPNs or certain privacy-focused applications.
- Misconfigured web applications that inadvertently use different domains in headers and target IP addresses.

## Priority
**Severity: High**

Justification: Domain fronting can be used by advanced threat actors to bypass security controls and facilitate sophisticated cyber attacks. Detecting this technique is crucial for maintaining robust network defenses against well-resourced adversaries.

## Validation (Adversary Emulation)
Currently, none available. However, organizations can conduct controlled testing in isolated environments using emulation frameworks to simulate domain fronting behavior safely.

## Response
When an alert indicating potential domain fronting is triggered:
1. **Immediate Actions:**
   - Isolate the affected network segment and terminate suspicious connections.
   - Gather detailed logs from DNS, HTTP/S headers, and network flows for further analysis.

2. **Investigation:**
   - Confirm whether the traffic pattern aligns with known malicious behavior.
   - Identify the ultimate destination of the fronted domain to assess potential impact.

3. **Remediation:**
   - Update firewall rules or intrusion detection systems to block identified threat patterns.
   - Increase monitoring on domains and services used for legitimate domain fronting by trusted applications, ensuring proper configuration.

## Additional Resources
Currently, no additional resources are available beyond the MITRE ATT&CK framework and related cybersecurity literature. Organizations may benefit from consulting with security vendors specializing in network traffic analysis to enhance detection capabilities further.