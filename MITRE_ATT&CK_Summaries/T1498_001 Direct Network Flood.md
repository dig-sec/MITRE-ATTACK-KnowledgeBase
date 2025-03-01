# Alerting & Detection Strategy (ADS) Framework Report

## Goal
The goal of this detection strategy is to detect adversarial attempts to bypass security monitoring using containers.

## Categorization
- **MITRE ATT&CK Mapping:** T1498.001 - Direct Network Flood
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1498/001)

## Strategy Abstract
This detection strategy focuses on identifying network floods originating from containerized environments, which adversaries use to evade traditional security monitoring. Data sources include network traffic logs, container orchestration platforms like Kubernetes and Docker, and application logs. The strategy analyzes patterns such as unusual spikes in outbound traffic from containers, anomalous container behaviors, and uncharacteristic network requests that exceed typical thresholds.

## Technical Context
Adversaries exploit container technologies to disguise malicious activities by generating high volumes of legitimate-looking traffic or using container sprawl to obfuscate their operations. They may leverage commands like `kubectl exec` for executing shell scripts within containers to initiate network floods, or use Docker's built-in networking capabilities to reroute traffic.

Example Commands:
- `kubectl run --generator=run-pod/v1 my-container --image=my-image --restart Never --command -- /bin/sh -c 'while true; do wget http://target.com/; done'`
- `docker exec <container_id> bash -c "while :; do echo > /dev/tcp/target_ip/target_port; sleep 0.5; done"`

Test Scenarios:
1. Deploy a container that continuously sends HTTP requests to an external target.
2. Monitor network traffic for unusual patterns such as high request rates from specific containers.

## Blind Spots and Assumptions
- **Blind Spots:** This strategy may not detect low-volume, slow-rate floods designed to remain under the radar of typical threshold-based alerts.
- **Assumptions:** The detection assumes that normal container operations are well-understood and baseline thresholds for network traffic have been established.

## False Positives
Potential false positives include:
- Legitimate application updates or patches generating high volumes of network traffic from containers.
- Scheduled tasks within containers leading to periodic spikes in outbound traffic.

## Priority
**Severity:** High  
Justification: The ability to bypass security monitoring can lead to significant data exfiltration and disruption of services, necessitating prompt detection and response.

## Response
When an alert fires:
1. Verify the alert by examining network logs for unusual patterns or container activities.
2. Isolate affected containers to prevent potential spread or further impact.
3. Conduct a thorough investigation to determine if the activity is malicious.
4. Update monitoring thresholds and baselines based on findings to reduce false positives.

## Additional Resources
- [MITRE ATT&CK Technique T1498.001](https://attack.mitre.org/techniques/T1498/001)
- [Kubernetes Documentation](https://kubernetes.io/docs/home/)
- [Docker Networking Guide](https://docs.docker.com/network/)

---

This report provides a comprehensive overview of the detection strategy for adversarial attempts to bypass security monitoring using containers, aligned with Palantir's ADS framework.