# Alerting & Detection Strategy (ADS) Report: ARP Cache Poisoning

## Goal
The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring through ARP cache poisoning. Specifically, it aims at detecting unauthorized alterations in the Address Resolution Protocol (ARP) tables on a network, which adversaries use to intercept or redirect traffic between devices.

## Categorization

- **MITRE ATT&CK Mapping:** T1557.002 - ARP Cache Poisoning
- **Tactic / Kill Chain Phases:** Credential Access, Collection
- **Platforms:** Linux, Windows, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1557/002)

## Strategy Abstract

This detection strategy focuses on monitoring ARP traffic and changes in ARP tables across supported platforms (Linux, Windows, macOS). The data sources utilized include network packet captures, host-based logs, and intrusion detection system alerts. Patterns analyzed involve anomalies in ARP responses such as frequent updates to the ARP table, inconsistent MAC-IP address mappings, and unusual ARP broadcast patterns.

Key indicators of compromise (IOCs) are derived from deviations from normal network behavior, including:
- Unexpected changes in MAC-to-IP address bindings.
- Unusual volume or frequency of ARP requests/responses.
- Detection of spoofed ARP packets.

The strategy leverages tools such as Wireshark for packet analysis and Snort/Zeek (formerly Bro) for intrusion detection.

## Technical Context

Adversaries execute ARP cache poisoning by sending forged ARP messages to link devices' MAC addresses with incorrect IP addresses. This allows them to intercept or modify data meant for other devices on the network, enabling man-in-the-middle attacks.

Common methods used include:
- **Packet Forging:** Crafting and injecting fake ARP packets into the network.
- **ARP Poisoning Tools:** Utilizing tools like `arpspoof`, `dsniff`, or `ettercap` to automate the poisoning process.

**Example Command:**
```bash
sudo arpspoof -i eth0 -t <target_ip> <gateway_ip>
```
This command sends forged ARP packets to a target IP address, associating it with the attacker's MAC address as if they were the gateway.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection may not cover all variations of ARP spoofing tools or custom scripts.
  - High network traffic environments might obscure malicious patterns.
  
- **Assumptions:**
  - The network baseline for normal ARP behavior is accurately defined.
  - Network devices are configured to log and report ARP changes.

## False Positives

Potential benign activities that could trigger false alerts include:
- Legitimate network administration tools or scripts updating ARP tables.
- DHCP-assigned IP address changes resulting in legitimate ARP updates.
- Misconfigured devices repeatedly sending ARP requests/updates.

False positives can be minimized by correlating ARP anomalies with other indicators of compromise and contextualizing alerts within the broader security environment.

## Priority

**Severity: High**

Justification:
ARP cache poisoning poses a significant threat as it enables adversaries to intercept sensitive information, disrupt communications, or gain unauthorized access. The impact on network integrity and confidentiality can be severe, warranting high priority in detection efforts.

## Response

When an alert for ARP cache poisoning fires, analysts should:

1. **Verify the Alert:**
   - Cross-reference with other security alerts and logs to confirm suspicious activity.
   - Analyze packet captures to identify patterns consistent with spoofing.

2. **Contain the Threat:**
   - Isolate affected devices from the network if feasible.
   - Disable unauthorized access points or interfaces used for ARP poisoning.

3. **Mitigate Risks:**
   - Update and patch vulnerable systems to prevent exploitation.
   - Implement static ARP entries for critical hosts to mitigate spoofing.

4. **Investigate Further:**
   - Determine the scope of compromised devices and data affected.
   - Identify potential entry points and strengthen network defenses.

5. **Report and Document:**
   - Document findings, actions taken, and lessons learned from the incident.
   - Report as necessary in accordance with organizational policies and regulatory requirements.

## Additional Resources

- [ARP Spoofing Detection Techniques](https://www.sans.org/blog/arp-spoofing-detection/)
- [Network Security Monitoring: Tools and Techniques for Defending Networks and Analyzing Network Attacks (NIST SP 800-94)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-94r2.pdf)

This report outlines a comprehensive strategy for detecting ARP cache poisoning, emphasizing the importance of robust monitoring, verification, and response mechanisms to mitigate associated risks effectively.