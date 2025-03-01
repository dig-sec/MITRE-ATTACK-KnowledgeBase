# Alerting & Detection Strategy (ADS) Report

## Goal

The goal of this strategy is to detect adversarial attempts to bypass security monitoring using containers for exfiltration over symmetric encrypted non-C2 protocols.

## Categorization

- **MITRE ATT&CK Mapping:** T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1048/001)

## Strategy Abstract

The detection strategy focuses on identifying unusual network traffic patterns indicative of data exfiltration via symmetrically encrypted channels that do not involve command and control (C2) servers. The primary data sources used include:

- **Network Traffic Logs:** Monitoring for outbound connections that utilize non-standard ports or protocols.
- **Container Activity Logs:** Observing the deployment, runtime behavior, and termination of containers.
- **File Integrity Monitoring (FIM):** Detecting changes in configuration files related to container orchestration tools.

Patterns analyzed involve:

- Sudden spikes in data transfer volumes through encrypted channels that deviate from established baselines.
- Usage of non-standard ports or protocols for outbound traffic, especially those typically associated with file transfers or encryption libraries.
- Anomalies in the creation and termination of containers that coincide with suspicious network activity.

## Technical Context

Adversaries execute this technique by deploying containers to encapsulate sensitive data extraction scripts. These scripts often use symmetric encryption (e.g., AES) to encode data before exfiltrating it over common protocols like HTTPS, DNS, or WebSockets. Containers provide a layer of abstraction that can obscure the activity from traditional monitoring solutions.

### Adversary Emulation Details

- **Sample Commands:**
  - `docker run --rm -v /data:/mnt/data my-exfil-container`
  - Use of encryption tools like OpenSSL for data encoding.
  
- **Test Scenarios:**
  - Set up a containerized environment to simulate data extraction and transfer.
  - Monitor network traffic for encrypted payloads leaving the host.

## Blind Spots and Assumptions

- **Blind Spots:** 
  - Detection might miss well-concealed encryption keys within legitimate applications.
  - Encrypted traffic without significant volume changes may go unnoticed.

- **Assumptions:**
  - Adversaries will use recognizable encryption libraries or protocols that can be identified through signature-based detection.
  - Baseline network behavior is well-established and monitored for deviations.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate usage of containers for data backup services that utilize encryption.
- Normal fluctuations in encrypted traffic due to scheduled backups or updates.
- Use of non-standard ports by legitimate applications not typically associated with exfiltration.

## Priority

**Priority Level: High**

Justification: The use of symmetrically encrypted channels for exfiltration can significantly hinder detection efforts, allowing adversaries to stealthily move sensitive data out of the network. This technique represents a sophisticated evasion method that poses a substantial risk if undetected.

## Validation (Adversary Emulation)

Step-by-step instructions to emulate this technique in a test environment:

1. **Set Up Environment:**
   - Deploy a container orchestration platform like Docker.
   - Configure monitoring tools to capture network traffic and container logs.

2. **Simulate Exfiltration:**
   - Create a container with an encryption tool (e.g., OpenSSL).
   - Use the command `docker run --rm -v /data:/mnt/data my-exfil-container` to simulate data extraction.
   - Encrypt a sample file and initiate transfer over HTTPS using tools like `curl`.

3. **Monitor and Analyze:**
   - Observe network logs for encrypted traffic patterns.
   - Check container logs for unusual activity during the exfiltration process.

## Response

When an alert fires:

1. **Immediate Containment:**
   - Isolate affected containers and hosts to prevent further data leakage.

2. **Investigation:**
   - Analyze network traffic to confirm the nature of encrypted data being transferred.
   - Review container logs for indicators of compromise (IOCs).

3. **Remediation:**
   - Update firewall rules to block suspicious outbound connections.
   - Enhance monitoring configurations to better detect similar patterns in the future.

## Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

This report provides a comprehensive overview of detecting adversarial container-based exfiltration techniques, emphasizing detection strategies and response guidelines to mitigate potential threats.