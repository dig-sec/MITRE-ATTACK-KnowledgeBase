# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Use of External Proxies

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring using external proxies, specifically focusing on the MITRE ATT&CK tactic T1090.002 - External Proxy. This involves identifying when an attacker uses a third-party proxy server for command and control (C2) activities to obscure their presence and origin.

## Categorization

- **MITRE ATT&CK Mapping:**  
  - [T1090.002 - External Proxy](https://attack.mitre.org/techniques/T1090/002)
  
- **Tactic / Kill Chain Phases:**  
  - Command and Control
  
- **Platforms:**  
  - Linux, macOS, Windows

## Strategy Abstract
This detection strategy leverages network traffic analysis to identify anomalous patterns indicative of the use of external proxies. Key data sources include:

- Network flow data (e.g., NetFlow, sFlow)
- DNS logs
- Proxy logs
- Endpoint telemetry

Patterns analyzed involve unusual outbound connections to known proxy servers or unexpected changes in network routes that suggest a redirection through an intermediary server.

## Technical Context
Adversaries commonly use external proxies to conceal their activities and evade detection. They may configure compromised systems to route traffic through these proxies, making it difficult for defenders to trace the original source of malicious activity. Adversary emulation might involve configuring a system to connect to a proxy using tools like `curl` or `wget`, often with non-standard ports.

### Emulation Scenario
- **Command Example:**  
  ```bash
  curl -x http://proxyserver.com:8080 http://malicious-site.com
  ```
- **Configuration File Example (Linux):**  
  Edit `/etc/environment` to include proxy settings:
  ```plaintext
  http_proxy="http://proxyserver.com:8080"
  https_proxy="https://proxyserver.com:8080"
  ```

## Blind Spots and Assumptions

- Detection relies heavily on the availability and accuracy of network traffic data.
- Assumes that known external proxies are cataloged in threat intelligence feeds.
- May not detect newly emerged or custom proxy services.

## False Positives
Potential benign activities include:

- Legitimate use of corporate-approved proxy servers for privacy or bypassing geolocation restrictions.
- VPN connections, which can mimic proxy usage patterns.
- Software updates that route through proxy servers to reduce bandwidth usage on the main network.

## Priority
**Severity: High**

Justification:
The ability to detect external proxies is critical as it directly impacts an organization's capacity to trace C2 activities. Bypassing security monitoring tools undermines defensive measures and can lead to prolonged undetected adversarial presence within a network.

## Response
When an alert for potential use of an external proxy triggers, analysts should:

1. **Verify the Alert:**
   - Cross-reference with known threat intelligence databases for any matches with listed proxies.
   
2. **Investigate Traffic Patterns:**
   - Examine the volume and destination of traffic routed through the suspected proxy.

3. **Endpoint Analysis:**
   - Check affected endpoints for signs of compromise, such as unusual processes or configurations.

4. **Containment Measures:**
   - Isolate affected systems to prevent further data exfiltration or lateral movement.

5. **Communication with Stakeholders:**
   - Notify relevant teams (e.g., SOC, IT operations) and stakeholders about potential breaches.

## Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Network traffic analysis tools documentation for configuration and best practices.
- Organization-specific proxy server lists and policies. 

This ADS framework aims to provide a structured approach to detecting and responding to adversarial use of external proxies, enhancing the security posture against such sophisticated threats.