# Palantir's Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by leveraging containers as Command and Control (C2) mechanisms. This includes using non-standard protocols that might evade traditional detection systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1095 - Non-Application Layer Protocol
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Windows, Linux, macOS, Network

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1095)

## Strategy Abstract
The detection strategy involves monitoring network traffic for anomalies associated with container-based C2 communications. Key data sources include:

- Container orchestration logs (e.g., Kubernetes audit logs)
- Network traffic metadata
- Container runtime activity

Patterns analyzed include unusual protocol usage, unexpected inter-container communication patterns, and deviations in typical application behavior.

## Technical Context
Adversaries may use containers to host C2 servers or payloads due to their ephemeral nature and the potential for obfuscation. Common methods include:

- **ICMP C2:** Using ICMP packets to communicate commands.
- **Netcat C2:** Executing covert communications via Netcat over non-standard ports.
- **Powercat C2:** Utilizing Powercat on Windows environments for similar purposes.
- **Linux ICMP Reverse Shell:** Deploying reverse shells through ICMP, often with tools like `icmp-cnc`.

Adversaries exploit the flexibility and isolation features of containers to hide malicious activities from traditional security controls.

## Blind Spots and Assumptions
Known limitations include:

- Difficulty in distinguishing between legitimate container orchestration traffic and C2 communications.
- Assumption that all containerized environments are monitored equally, which may not be true for heterogeneous IT infrastructures.
- Limited visibility into encrypted inter-container communication without decryption capabilities.

## False Positives
Potential benign activities that might trigger false alerts include:

- Legitimate use of ICMP or Netcat for debugging purposes.
- Normal orchestration activities in microservices architectures.
- DevOps teams using containerized tools for rapid deployment and testing.

## Priority
**High**: Given the increasing adoption of containers and the sophistication of adversaries exploiting this technology, detecting such attempts is critical to maintaining security integrity. Containers provide a high degree of abstraction that can be leveraged to bypass traditional monitoring systems if left unchecked.

## Validation (Adversary Emulation)
### ICMP C2
1. Set up a containerized environment with network access.
2. Configure an ICMP server within the container to receive commands.
3. Use an external device or script to send ICMP echo requests as command triggers.

### Netcat C2
1. Deploy a Netcat listener inside a container on a non-standard port.
2. From another host, connect using Netcat to simulate control communication.

### Powercat C2
1. Install and configure Powercat in a Windows-based container.
2. Set up a corresponding server script to interact with the Powercat client.

### Linux ICMP Reverse Shell using `icmp-cnc`
1. Deploy a reverse shell payload within a Linux container using `icmp-cnc`.
2. Establish a listener on an external host to receive the incoming connection.

## Response
When an alert fires, analysts should:

1. Immediately isolate affected containers and networks.
2. Conduct a thorough investigation of logs from the orchestration platform and network traffic metadata.
3. Identify any unusual patterns or deviations in container behavior.
4. Collaborate with security operations teams to assess potential impact and remediate identified threats.

## Additional Resources
- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious Program Names
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets

By understanding these resources, analysts can gain deeper insights into potential adversarial tactics and enhance their detection strategies.