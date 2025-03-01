# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using non-standard encoding methods in network traffic.

## Categorization
- **MITRE ATT&CK Mapping:** T1132.002 - Non-Standard Encoding
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1132/002)

## Strategy Abstract
The detection strategy focuses on identifying patterns of non-standard encoding in network traffic that may indicate an attempt to evade security monitoring. Data sources include network logs (e.g., firewall and proxy logs), endpoint telemetry, and DNS query logs. The strategy analyzes for unusual encoding schemes such as Base64 variations or custom encodings applied to command-and-control communications.

## Technical Context
Adversaries use non-standard encoding techniques to disguise malicious payloads or C2 traffic, making it harder for traditional detection systems to identify them. These methods involve altering the appearance of network data using uncommon or custom encoding algorithms. 

### Adversary Emulation Details
- **Sample Commands:**
  - Adversaries might encode URLs in Base64 but with additional obfuscation layers.
  - Custom scripts that apply XOR-based encoding to C2 traffic.

- **Test Scenarios:**
  - Simulate an attack by transmitting data encoded in a non-standard scheme across the network.
  - Use tools like `base64` with custom modifications or scripting languages (e.g., Python) to encode payloads.

## Blind Spots and Assumptions
- **Blind Spots:** Detection might miss entirely novel encoding techniques not yet observed in real-world scenarios.
- **Assumptions:** Assumes that non-standard encoding is a deliberate attempt at evasion, which may not always be the case (e.g., misconfigured legitimate applications).

## False Positives
Potential benign activities include:
- Legitimate use of uncommon encoding schemes for data compression or encryption by software developers.
- Misconfigured applications generating unexpected encoded traffic.

## Priority
**Severity: High**

Justification: Non-standard encoding can significantly hinder detection efforts, allowing adversaries to maintain persistence and control within a network undetected. The ability to evade security controls is critical in the context of Command and Control activities.

## Response
When an alert for non-standard encoding triggers:
1. **Investigate the Source:** Identify the originating device or application responsible for the encoded traffic.
2. **Analyze Patterns:** Examine whether similar patterns are observed across other endpoints or network segments.
3. **Containment:** Isolate affected systems to prevent further spread of potential malicious activity.
4. **Incident Response:** Initiate a broader incident response process if indicators suggest an active breach.

## Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Technical whitepapers on non-standard encoding and evasion techniques

---

This report provides a structured approach to understanding and detecting the use of non-standard encoding by adversaries, aligning with Palantir's Alerting & Detection Strategy framework.