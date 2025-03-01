# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containers.

## Categorization
- **MITRE ATT&CK Mapping:** T1499 - Endpoint Denial of Service
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1499)

## Strategy Abstract
The detection strategy focuses on identifying unusual behaviors and patterns associated with the use of containers that may indicate attempts to bypass security monitoring. Key data sources include logs from container orchestration platforms (such as Kubernetes), endpoint detection systems, network traffic analysis tools, and host-based intrusion detection systems. The patterns analyzed involve sudden spikes in resource usage, abnormal communication between containers, and the presence of unauthorized or unexpected containers on the system.

## Technical Context
Adversaries may use containers to create isolated environments for malicious activities while attempting to evade traditional security controls that are not optimized for containerized workloads. They might execute techniques such as launching resource-intensive applications within containers to degrade performance (Denial of Service) or using containers to hide command and control communications. 

### Adversary Emulation Details
- **Sample Commands:**
  - Deploying a CPU-intensive application in a container: `docker run --rm busybox yes > /dev/null`
  - Creating unexpected network traffic between containers: Use custom scripts that simulate abnormal inter-container communication.
  
- **Test Scenarios:**
  - Overloading system resources by spinning up multiple high-CPU or high-memory containers.
  - Establishing unauthorized connections to external networks from within a container.

## Blind Spots and Assumptions
- Detection relies heavily on the accuracy of resource usage logs and network traffic data, which may not always be comprehensive or timely.
- Assumes that all relevant systems are configured to capture detailed telemetry from container environments.
- May not detect sophisticated evasion techniques where adversaries mimic legitimate container behaviors closely.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate spikes in resource usage due to scheduled batch jobs or updates running within containers.
- Authorized inter-container communication for microservices-based applications.
- Automated deployment processes involving container orchestration tools like Kubernetes or Docker Swarm.

## Priority
**Severity:** High

**Justification:**
The technique poses a significant threat as it can be used to bypass security monitoring and facilitate other malicious activities. The impact on system performance and the potential for unnoticed data exfiltration make this a high-priority detection objective.

## Response
When an alert fires:
1. **Initial Assessment:** Quickly verify if the detected activity is related to known legitimate operations or scheduled maintenance tasks.
2. **Investigate Anomalies:** Examine logs for unusual patterns in resource usage and network traffic that deviate from normal behavior.
3. **Containment:** Isolate affected containers or nodes to prevent potential spread or escalation of malicious activities.
4. **Eradication:** Identify the root cause, remove unauthorized containers, and apply necessary patches or configuration changes.
5. **Recovery:** Restore affected systems to their normal state, ensuring that all security measures are re-enabled and functioning as expected.
6. **Post-Incident Review:** Conduct a thorough analysis to improve detection capabilities and refine response strategies.

## Additional Resources
Additional references and context are currently not available for this strategy. Further research and collaboration with industry partners may provide more insights into effective detection and mitigation techniques for container-based bypass attempts.