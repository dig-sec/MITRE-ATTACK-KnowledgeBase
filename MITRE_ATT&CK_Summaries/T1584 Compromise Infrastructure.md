# Palantir's Alerting & Detection Strategy (ADS) Report: Compromise Infrastructure Using Containers

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring by using containers. The focus is on detecting the exploitation of container environments as a means to compromise infrastructure, often used for deploying malicious payloads or evading traditional security controls.

## Categorization

- **MITRE ATT&CK Mapping:** T1584 - Compromise Infrastructure
- **Tactic / Kill Chain Phases:** Resource Development
- **Platforms:** PRE (Privileged Remote Environment)
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1584)

## Strategy Abstract

The detection strategy leverages a variety of data sources including network traffic logs, container orchestration platform logs (e.g., Kubernetes audit logs), system event logs, and endpoint security tools. Key patterns analyzed include:

- Unexpected or unauthorized creation/deployment of containers
- Network communications to known malicious domains from within containers
- Anomalies in resource utilization indicative of malicious activity
- Deviations from established baselines for container behavior

The approach involves correlating these indicators with known adversarial tactics associated with the T1584 technique, ensuring timely detection and response.

## Technical Context

Adversaries often use containers to deploy their payloads due to their lightweight nature and ease of scaling. This can allow malicious actors to quickly establish footholds in a target environment or move laterally undetected by traditional security measures.

### Adversary Emulation Details
In practice, adversaries might execute commands like:

- `docker run -d --name <malicious_container> --net host <image>`
- Use of orchestration tools: e.g., `kubectl create deployment <deployment_name> --image=<malicious_image>`

Test scenarios could involve deploying a benign container mimicking typical adversary behavior to validate detection mechanisms.

## Blind Spots and Assumptions

- **Blind Spots:** Detection may not capture all sophisticated evasion techniques, such as those using legitimate applications repurposed for malicious intent.
- **Assumptions:** It assumes that baseline behaviors are well-understood and anomalies are correctly identified. The strategy also presumes robust logging and monitoring capabilities.

## False Positives

Potential benign activities that could trigger false alerts include:

- Legitimate development or testing environments where container creation/deployment is frequent
- Authorized use of containers for legitimate applications, leading to network communications that mimic adversary behavior
- High resource utilization from well-known applications during peak times

## Priority

**Priority: High**

The severity is high due to the potential impact on infrastructure security and data integrity. Containers offer adversaries a powerful tool to bypass defenses, making it crucial to detect and mitigate such attempts promptly.

## Validation (Adversary Emulation)

Currently, no specific emulation steps are available for this technique in a test environment. Future development should focus on creating controlled scenarios where benign containers exhibit adversarial-like behaviors without causing harm.

## Response

When an alert fires, analysts should:

1. Immediately isolate the container and its associated resources.
2. Conduct a forensic analysis to determine if any data exfiltration or lateral movement has occurred.
3. Review recent changes in container deployments for unauthorized activities.
4. Update security policies to prevent similar occurrences, including tightening access controls and enhancing monitoring capabilities.

## Additional Resources

Additional references and context are currently unavailable. Future reports should include insights from industry case studies and threat intelligence feeds that highlight evolving adversary tactics related to container exploitation.

---

This report provides a comprehensive framework for detecting adversarial use of containers within infrastructure environments, aligned with Palantir's ADS methodology.