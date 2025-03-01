# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal

This technique aims to detect adversarial attempts to bypass security monitoring using containers. As adversaries increasingly leverage container technologies to evade detection and maintain persistence, it is crucial to identify and mitigate these efforts effectively.

## Categorization

- **MITRE ATT&CK Mapping:** T1587 - Develop Capabilities
- **Tactic / Kill Chain Phases:** Resource Development
- **Platforms:** PRE (Privileged Remote Execution)
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1587)

## Strategy Abstract

The detection strategy leverages various data sources to monitor and analyze container activities. Key data sources include:

- Container orchestration logs (e.g., Kubernetes audit logs, Docker daemon logs)
- Network traffic analysis for inter-container communication
- System-level process monitoring

Patterns analyzed involve unusual behavior such as unexpected container deployments, unauthorized image pulls/pushes, or anomalous inter-process communications that suggest attempts to evade security controls.

## Technical Context

Adversaries may use containers to execute malicious payloads in isolated environments, thus evading traditional endpoint detection systems. Techniques include:

- Creating custom container images with embedded malware
- Leveraging sidecar containers for unauthorized data exfiltration
- Using ephemeral containers to perform tasks and delete traces

### Adversary Emulation Details

Sample commands or test scenarios could involve:

1. Deploying a container using a non-standard image pull policy.
2. Configuring network policies that bypass standard firewalls.
3. Executing privileged operations within containers to access host resources.

## Blind Spots and Assumptions

- **Blind Spot:** Detection mechanisms may not fully capture sophisticated obfuscation techniques within container payloads.
- **Assumption:** Assumes consistent logging practices across all container orchestration platforms.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate deployment of containers for testing or development purposes
- Routine updates or maintenance tasks involving container images
- Authorized use of privileged operations for administrative functions

## Priority

**Priority: High**

Justification: The ability to bypass security monitoring poses a significant risk, potentially allowing adversaries to operate undetected within an environment. Early detection is crucial to mitigate these threats.

## Response

When the alert fires, analysts should:

1. Verify if the container deployment or activity aligns with expected business operations.
2. Investigate network traffic associated with the suspicious containers for signs of data exfiltration.
3. Review system logs to identify any unauthorized access attempts or changes in configuration.
4. Isolate and analyze affected containers to understand the nature and scope of potential threats.

## Additional Resources

Currently, no additional references or context are available beyond the MITRE ATT&CK framework documentation. Analysts should stay informed about emerging container security practices and incorporate insights from industry forums and threat intelligence sources.

This report provides a comprehensive overview for implementing detection strategies against adversarial use of containers to bypass security monitoring.