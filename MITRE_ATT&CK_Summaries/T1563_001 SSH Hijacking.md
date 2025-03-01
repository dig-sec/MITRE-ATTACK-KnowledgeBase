# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring by leveraging container technologies. Specifically, it targets scenarios where attackers exploit containers for evasion or obfuscation of malicious activities within enterprise environments.

## Categorization
- **MITRE ATT&CK Mapping:** T1563.001 - SSH Hijacking
- **Tactic / Kill Chain Phases:** Lateral Movement
- **Platforms:** Linux, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1563/001)

## Strategy Abstract
The detection strategy leverages multiple data sources to monitor and analyze container-related activities. Key data sources include:
- Container orchestration logs (e.g., Kubernetes audit logs)
- Network traffic associated with container communications
- System call traces from containers

Patterns analyzed involve unusual or unauthorized changes in container configurations, unexpected SSH connections initiated by containers, and anomalies in network traffic patterns that deviate from established baselines.

## Technical Context
Adversaries use containers to bypass traditional security monitoring due to their isolated nature and dynamic deployment capabilities. Common tactics include:
- Deploying malicious containers with modified images to avoid detection.
- Using container orchestration platforms to scale out malicious activities quickly.
- Hijacking SSH sessions within a container to facilitate lateral movement.

### Adversary Emulation Details
An adversary might execute the following steps in real-world scenarios:
1. **Container Deployment:** Create and deploy a container using an image that includes hidden backdoors or tools for persistence.
2. **SSH Configuration Manipulation:** Modify the SSH configuration inside the container to allow unauthorized access.
3. **Network Evasion:** Use network namespaces within containers to route traffic through non-standard ports.

### Sample Commands
- `docker run -d --name malicious_container -p 2222:22 compromised_image`
- Inside the container: `echo "Port 2222" >> /etc/ssh/sshd_config`

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may not cover new or zero-day evasion techniques.
  - Encrypted traffic within containers that bypasses inspection.

- **Assumptions:**
  - Containers are managed by standard orchestration tools with accessible logs.
  - Baselines for normal network and container behavior have been established.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate SSH configuration changes made during maintenance.
- Authorized use of containers for dynamic application scaling or testing environments.

## Priority
**Severity:** High

Justification: The technique allows adversaries to bypass security controls, facilitating lateral movement and potentially leading to data exfiltration or further compromise. Given the increasing adoption of containerized environments, this threat poses a significant risk.

## Validation (Adversary Emulation)
Currently, no step-by-step instructions are available for emulating this technique in a test environment. Further development of controlled emulation scenarios is recommended to enhance validation efforts.

## Response
When an alert triggers:
1. **Immediate Isolation:** Disconnect the suspicious container from the network to prevent further unauthorized activity.
2. **Log Analysis:** Review logs from the orchestration platform and network traffic for signs of malicious behavior.
3. **Forensic Investigation:** Conduct a detailed forensic analysis of the affected container, including file system inspection and memory dumps.
4. **Incident Reporting:** Document findings and report them to relevant stakeholders for further action.

## Additional Resources
Additional references and context are currently unavailable. Further research into specific adversary techniques and container security best practices is recommended to enhance understanding and detection capabilities.