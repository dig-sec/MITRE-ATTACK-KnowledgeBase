# Alerting & Detection Strategy: Exfiltration Over SMB over QUIC

## Goal
The primary aim of this detection strategy is to identify adversarial attempts to exfiltrate data using Server Message Block (SMB) protocol in conjunction with Quick UDP Internet Connections (QUIC). This technique leverages the encrypted nature of QUIC to bypass traditional security monitoring and evade detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1574.004 - Exfiltration Over Web Service: Exfiltration over SMB over QUIC
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1574/004)

## Strategy Abstract
This detection strategy focuses on monitoring network traffic for unusual patterns associated with SMB over QUIC. Key data sources include network flow data and application logs that capture encrypted protocol usage. By analyzing these patterns, such as unexpected connections to non-standard ports or anomalies in data volume and timing, we can detect potential exfiltration attempts.

## Technical Context
Adversaries may use SMB over QUIC for data exfiltration due to its encrypted nature, which helps evade traditional network monitoring tools that are less effective against encrypted traffic. In practice, attackers establish a connection using the SMB protocol encapsulated within QUIC packets, often targeting non-standard ports or unusual IP addresses.

### Adversary Emulation Details
- **Sample Commands:**
  - Use `New-SmbMapping` to create a network share over QUIC.
  - Utilize `NET USE` command to map and access the share for data transfer.
  
- **Test Scenarios:**
  - Configure a test environment with SMB server capabilities.
  - Establish QUIC transport using tools that support encrypted tunneling.
  - Monitor traffic for anomalies in port usage and data patterns.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Encrypted payloads make it challenging to inspect content, potentially missing sophisticated exfiltration tactics.
  - Detection relies on anomaly detection which may not catch well-disguised malicious activities.

- **Assumptions:**
  - Network traffic analysis can identify deviations from normal behavior.
  - Organizations have baseline data for typical SMB and QUIC usage patterns.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate use of QUIC by applications such as HTTP/3 clients or VPNs.
- Routine network maintenance or configuration changes involving non-standard ports.
- Temporary spikes in encrypted traffic due to legitimate business operations.

## Priority
**Priority Level: High**

Justification: The use of SMB over QUIC for data exfiltration represents a sophisticated method that can effectively bypass traditional security measures. The high priority is due to the potential impact on sensitive data loss and the difficulty in detecting such activities with conventional monitoring tools.

## Validation (Adversary Emulation)
To emulate this technique, follow these steps in a controlled test environment:

1. **Set Up Environment:**
   - Ensure an SMB server is configured.
   - Enable QUIC support using compatible network tools or software.

2. **Create Network Share Over QUIC:**
   - Use `New-SmbMapping` command to map a share over a network location utilizing QUIC:
     ```shell
     New-SmbMapping -LocalPath Z: -RemotePath \\server\share -Credential (Get-Credential)
     ```

3. **Map and Access Share:**
   - Utilize `NET USE` to access the mapped share:
     ```shell
     NET USE Z: \\\\server\\share /PERSISTENT:YES
     ```

4. **Monitor Network Traffic:**
   - Observe network flow data for connections on non-standard ports.
   - Analyze logs for unusual patterns in data volume or timing.

## Response
When an alert fires indicating potential SMB over QUIC exfiltration:
- **Immediate Actions:**
  - Isolate the affected systems from the network to prevent further data loss.
  - Capture and analyze network traffic logs for detailed investigation.

- **Investigation Steps:**
  - Identify the source of the connection and validate if it aligns with known business operations.
  - Review user activity logs to detect unauthorized access or anomalies.

- **Remediation:**
  - Update firewall rules to block suspicious ports and IP addresses.
  - Enhance encryption inspection capabilities where feasible, such as implementing SSL/TLS decryption at network boundaries.

## Additional Resources
Currently, no additional resources are available. Organizations should refer to internal security policies and external threat intelligence feeds for further context on SMB over QUIC usage trends.