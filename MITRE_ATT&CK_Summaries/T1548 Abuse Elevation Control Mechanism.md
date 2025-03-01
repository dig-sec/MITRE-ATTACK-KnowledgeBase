# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
The aim of this detection strategy is to identify attempts by adversaries to use container technologies as a means to evade security monitoring systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1548 - Abuse Elevation Control Mechanism
- **Tactic / Kill Chain Phases:** Privilege Escalation, Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1548)

## Strategy Abstract
This detection strategy utilizes data from container orchestration platforms (such as Kubernetes and Docker), host-based intrusion detection systems (HIDS), and network traffic analysis. The key patterns analyzed include:

- Unusual creation of containers with elevated privileges.
- Containers attempting to modify or bypass security policies.
- Network anomalies indicating unauthorized communication between containers.

## Technical Context
Adversaries may use containerization tools such as Docker or Kubernetes to launch processes that have the same permissions as root, effectively evading traditional endpoint detection mechanisms. For instance, adversaries might exploit vulnerabilities in a host OS or misconfigured container settings to escalate privileges and move laterally within an environment. 

In practice:
- Adversaries create containers with elevated privileges using commands like `docker run --privileged`.
- They may use Kubernetes' Role-Based Access Control (RBAC) features improperly to gain access beyond intended permissions.
  
Sample command for adversary emulation might be:
```bash
docker run --rm -it --net=host --pid=host --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ubuntu bash
```

## Blind Spots and Assumptions
- The detection assumes that container orchestration platforms are configured with security monitoring enabled.
- It may not detect privilege escalation attempts in environments where containers are managed without these systems.
- Assumes a baseline understanding of normal behavior within the network to identify anomalies.

## False Positives
Potential benign activities include:
- Legitimate development and testing environments using elevated privileges for container creation.
- Automated processes for software deployment that temporarily require higher permissions.
  
## Priority
**Severity:** High

Justification: The ability to bypass security controls using containers can significantly compromise an environment, allowing adversaries undetected access to critical systems.

## Validation (Adversary Emulation)
Currently, there are no specific step-by-step instructions available for emulating this technique in a test environment. 

## Response
When the alert fires:
1. Immediately isolate affected container instances and networks.
2. Investigate logs for signs of unauthorized access or privilege escalation.
3. Review configurations of container orchestration platforms to identify misconfigurations.
4. Coordinate with security teams to patch any discovered vulnerabilities.

## Additional Resources
- None available

This strategy provides a framework to enhance the detection of adversarial use of containers, ensuring that potential evasion tactics are identified and mitigated promptly.