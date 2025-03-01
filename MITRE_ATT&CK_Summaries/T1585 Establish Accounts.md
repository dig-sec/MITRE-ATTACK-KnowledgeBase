# Alerting & Detection Strategy (ADS) Report: Establish Accounts Using Containers

## Goal
The goal of this detection strategy is to identify adversarial attempts to establish accounts using containers as a method to bypass security monitoring systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1585 - Establish Accounts
- **Tactic / Kill Chain Phases:** Resource Development
- **Platforms:** PRE (Privileged Remote Execution)
  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1585)

## Strategy Abstract
This detection strategy leverages data sources such as container orchestration logs, network traffic analysis, and system audit trails to identify anomalous patterns indicative of adversaries attempting to establish accounts using containers. By analyzing these patterns, the strategy aims to detect unauthorized creation or manipulation of user accounts within containerized environments.

Key data sources:
- Container orchestration platform logs (e.g., Kubernetes, Docker Swarm)
- Network traffic related to container communication
- System audit logs for account and permission changes

The strategy focuses on identifying unusual behaviors such as frequent creation/deletion of containers, unexpected access patterns in container networks, or unauthorized modifications to user permissions.

## Technical Context
Adversaries may exploit container environments to establish accounts by leveraging the ephemeral nature and isolation properties of containers. They might create new containers with elevated privileges or modify existing ones to introduce malicious users without detection. Common tactics include:

- Creating containers that operate outside normal operational hours.
- Modifying container images to include unauthorized user credentials.
- Exploiting vulnerabilities in container orchestration platforms to elevate privileges.

Adversary emulation can involve commands such as:
```bash
docker run -d --name malicious_container --user root <malicious_image>
```

## Blind Spots and Assumptions
- Assumes comprehensive logging and monitoring of all container activities.
- Detection might miss sophisticated evasion techniques that mask unauthorized activity.
- Relies on predefined baselines for "normal" container behavior, which may not account for legitimate but unusual use cases.

## False Positives
Potential false positives include:
- Legitimate DevOps activities involving frequent creation/deletion of containers for testing purposes.
- Scheduled tasks or automation scripts that modify container configurations during off-hours.
- Authorized users executing maintenance tasks that involve privilege escalation within containers.

## Priority
**High.** Establishing unauthorized accounts is a critical step in gaining persistent access and escalating privileges, making it imperative to detect and respond promptly to such activities.

## Validation (Adversary Emulation)
None available

## Response
When an alert for establishing accounts using containers fires, analysts should:
1. Verify the legitimacy of container activities by cross-referencing with known operational schedules and user permissions.
2. Investigate any unauthorized account creation or privilege escalation attempts within the affected containers.
3. Review recent changes to container images and configurations for signs of tampering.
4. Collaborate with DevOps teams to ensure that legitimate workflows are not disrupted while addressing potential threats.

## Additional Resources
None available

This report outlines a comprehensive approach to detecting adversarial use of containers for account establishment, providing critical insights into potential threats and response strategies.