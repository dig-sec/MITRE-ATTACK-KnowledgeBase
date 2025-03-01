# Alerting & Detection Strategy Report: Traffic Duplication (T1020.001)

## Goal

The primary aim of this detection technique is to identify adversarial attempts to bypass security monitoring through the use of traffic duplication. Specifically, it seeks to detect when attackers duplicate network traffic to obfuscate their activities and potentially exfiltrate data without raising alarms.

## Categorization

- **MITRE ATT&CK Mapping:** T1020.001 - Traffic Duplication
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Network
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1020/001)

## Strategy Abstract

This detection strategy leverages network traffic data to identify anomalies indicative of duplicated traffic. By analyzing patterns such as unusual spikes in bandwidth usage, repeated sessions with identical payloads, or discrepancies between expected and observed traffic flows, it aims to flag potential adversarial behavior.

The primary data sources include:

- **Network Flow Data:** Captured via NetFlow, sFlow, or IPFIX protocols.
- **Packet Capture (PCAP) Files:** For deep inspection of network packets.
- **Log Files:** From firewalls and intrusion detection systems for corroborative evidence.

Patterns analyzed involve the frequency of identical traffic patterns from disparate sources within a short time frame, unexpected duplication in payload data across different sessions, and discrepancies between traffic volumes expected versus observed.

## Technical Context

Adversaries often execute traffic duplication by intercepting legitimate network communication and creating copies with slight modifications to evade detection. This technique can be particularly effective when attackers need to exfiltrate large datasets or bypass anomaly-based detection systems that monitor for deviations in typical user behavior.

### Adversary Emulation Details

In a test scenario, an adversary might use tools like `tcpdump` or `Wireshark` to capture and replicate network traffic. For instance:

- **Sample Command:**
  ```bash
  tcpdump -i eth0 -w duplicate_traffic.pcap 'port 80'
  ```

This command captures HTTP traffic on interface `eth0`, saving it to a file named `duplicate_traffic.pcap`. The captured data can be replayed using tools like `tcpreplay`:

- **Replaying Command:**
  ```bash
  tcprewrite --mtu=1500 -i duplicate_traffic.pcap -o modified_traffic.pcap
  tcpprefix -t 100 -p 80 -a 192.168.1.10 modified_traffic.pcap
  ```

These commands modify and replay the captured traffic, potentially adding slight alterations to evade detection.

## Blind Spots and Assumptions

- **Assumption:** The system assumes that duplicated traffic will manifest as anomalies in network flow data.
- **Blind Spot:** Legitimate applications or services may inadvertently generate duplicate traffic due to redundancy mechanisms like load balancing or fault tolerance, leading to potential false positives.

## False Positives

Potential benign activities that might trigger false alerts include:

- Redundant systems using load balancers which can appear as duplicated traffic from multiple sources.
- Backup solutions where data is transferred across different network paths.
- High-volume data replication in distributed databases.

## Priority

**Severity: Medium**

Justification: While traffic duplication is a sophisticated technique that poses significant risks, its detection requires careful balancing to avoid false positives. Given the potential for both legitimate and malicious uses of duplicated traffic, medium priority allows for focused attention without overwhelming security teams with alerts.

## Response

When an alert for duplicated traffic fires, analysts should:

1. **Verify Anomalies:** Confirm whether the detected patterns align with known benign activities (e.g., load balancing).
2. **Investigate Context:** Check logs and network flow data to understand the context of the duplication.
3. **Correlate Alerts:** Use additional indicators from IDS/IPS systems to corroborate findings.
4. **Containment:** If malicious intent is confirmed, consider isolating affected segments or devices.
5. **Documentation:** Record findings and response actions for future reference and improvement of detection strategies.

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Special Publication 800-83: Guide to Malware Incident Prevention and Handling for Desktops and Laptops](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-83r2.pdf)

This report provides a comprehensive overview of the detection strategy for traffic duplication, emphasizing both its technical aspects and operational implications in securing network environments against sophisticated threats.