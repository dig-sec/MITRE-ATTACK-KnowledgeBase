# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this technique is to detect adversarial attempts to bypass security monitoring using containers and tunneling protocols, specifically focusing on DNS over HTTPS (DoH) and tools like ngrok.

## Categorization
- **MITRE ATT&CK Mapping:** T1572 - Protocol Tunneling
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1572)

## Strategy Abstract
This detection strategy leverages network traffic analysis to identify unusual DNS over HTTPS (DoH) queries that may indicate adversarial activity. By monitoring large volumes of DoH requests and analyzing beaconing patterns, the strategy aims to detect command and control channels established via protocol tunneling.

**Data Sources:**
- Network traffic logs
- DNS query records
- Container orchestration system logs

**Patterns Analyzed:**
- Sudden spikes in DoH query volume
- Regularly timed intervals of DoH requests suggesting beaconing
- Unusually long domain queries within DoH traffic

## Technical Context
Adversaries often use containerized environments to obfuscate their command and control (C2) activities. Protocol tunneling techniques, such as DNS over HTTPS, allow them to bypass traditional network security measures by encrypting DNS queries.

**Execution in Real World:**
- Adversaries deploy containers with embedded C2 logic.
- Utilize DoH for encrypted communications to external servers.
- Tools like ngrok create secure tunnels that can evade detection.

**Adversary Emulation Details:**
- Sample command for setting up a DoH server:
  ```bash
  certbot --preferred-challenges http -d example.com
  ```
- Example of setting up an ngrok tunnel:
  ```bash
  ./ngrok http 80
  ```

## Blind Spots and Assumptions
- Detection may not catch novel or highly obfuscated DoH traffic.
- Assumes that baseline network activity is well-understood to distinguish anomalies.
- Relies on the availability of detailed DNS query logs.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate services using DoH for privacy reasons.
- Misconfigured applications generating large volumes of DoH requests.
- Network troubleshooting activities involving long domain queries.

## Priority
**Severity: High**

Justification: Protocol tunneling can effectively bypass traditional security controls, allowing adversaries to maintain persistent access and exfiltrate data without detection. The use of containers adds an additional layer of obfuscation, increasing the risk and impact of such attacks.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **DNS over HTTPS Large Query Volume:**
   - Set up a DoH server using `certbot`.
   - Generate high volumes of DNS queries to simulate adversarial behavior.
   
2. **DNS over HTTPS Regular Beaconing:**
   - Schedule regular intervals for sending DoH requests to mimic beaconing patterns.

3. **DNS over HTTPS Long Domain Query:**
   - Construct and send unusually long domain names within DoH traffic to test detection thresholds.

4. **Run ngrok:**
   - Deploy `ngrok` to create a secure tunnel, simulating an adversarial C2 channel.
   - Monitor network logs for tunnel establishment and usage patterns.

## Response
When the alert fires:
- Investigate the source of unusual DoH traffic to determine legitimacy.
- Correlate with other indicators of compromise (IOCs) in your environment.
- Consider isolating affected containers or endpoints to prevent further unauthorized access.
- Update firewall rules to block suspicious DNS query patterns if deemed necessary.

## Additional Resources
Additional references and context:
- None available

This report outlines a comprehensive strategy for detecting adversarial use of protocol tunneling within containerized environments, focusing on DNS over HTTPS as a key vector. By understanding the technical context and potential blind spots, security teams can better prepare to identify and mitigate these threats.