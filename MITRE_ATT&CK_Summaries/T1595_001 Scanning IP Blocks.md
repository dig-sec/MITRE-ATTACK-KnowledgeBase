# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containers by identifying unauthorized scanning activities within a network environment.

## Categorization
- **MITRE ATT&CK Mapping:** T1595.001 - Scanning IP Blocks
- **Tactic / Kill Chain Phases:** Reconnaissance
- **Platforms:** PRE (Physical, Reconnaissance, Execution)

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1595/001)

## Strategy Abstract
The detection strategy involves monitoring network traffic for patterns indicative of scanning IP blocks. Key data sources include network flow logs, firewall logs, and container orchestration platform logs (e.g., Kubernetes audit logs). The strategy analyzes unusual or repeated connection attempts to multiple IPs within short time frames, especially those originating from newly deployed containers.

## Technical Context
Adversaries often employ scanning techniques to identify active IP addresses within a target network. This reconnaissance is crucial for mapping the network topology and identifying potential entry points. In containerized environments, adversaries might deploy malicious containers to scan internal networks. These scans can be executed using tools like `nmap` or custom scripts that attempt connections to various IP addresses.

### Adversary Emulation Details
- **Tools:** `nmap`, custom Python/Go scripts for scanning.
- **Sample Commands:**
  ```bash
  nmap -sn 192.168.1.0/24
  ```
  This command performs a ping scan on the specified IP range to identify active hosts.

### Test Scenario
Deploy a container within a controlled environment and execute an internal network scan using `nmap`. Monitor logs for unusual traffic patterns and ensure detection mechanisms trigger alerts upon identification of scanning activities.

## Blind Spots and Assumptions
- **Blind Spots:** Detection may not capture scans conducted over encrypted channels or those using advanced evasion techniques.
- **Assumptions:** It is assumed that network monitoring tools have visibility into all relevant traffic, including encrypted protocols when decrypted by proxies or firewalls.

## False Positives
Potential benign activities include:
- Network discovery processes initiated during legitimate infrastructure updates.
- Automated security scans conducted by internal IT teams for vulnerability assessments.

## Priority
**Severity: Medium**

Justification: While scanning is a common precursor to more severe attacks, its detection in isolation may not always indicate an imminent threat. However, it provides valuable reconnaissance insights that adversaries could exploit if left unchecked.

## Validation (Adversary Emulation)
No specific step-by-step instructions are available for emulation within this report context. However, setting up a controlled environment with network monitoring tools and executing scan commands from containerized workloads can serve as a practical validation approach.

## Response
Upon alert activation:
1. **Immediate Investigation:** Analyze the source of the scanning activity to determine if it originates from an authorized or compromised container.
2. **Containment:** Isolate the container involved in suspicious activities to prevent further network probing.
3. **Remediation:** Remove any identified malicious containers and patch vulnerabilities that may have been exploited.
4. **Forensics:** Conduct a thorough investigation to understand the scope and intent of the scanning activity.

## Additional Resources
No additional references are currently available. Future updates will include links to relevant research papers, tool documentation, and community discussions on best practices for detecting and mitigating container-based reconnaissance activities.