# Alerting & Detection Strategy (ADS) Framework: Container Resource Discovery

## Goal
The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring through the use and discovery of containers within a network environment.

## Categorization
- **MITRE ATT&CK Mapping:** T1613 - Container and Resource Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Containers

For more information, refer to [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1613).

## Strategy Abstract
This detection strategy leverages various data sources including container runtime logs, host system monitoring tools (e.g., Prometheus, ELK stack), and network traffic analysis to identify patterns indicative of adversaries attempting to discover or misuse containers. Key patterns include unusual spikes in resource allocation, unexpected changes in container configurations, unauthorized access attempts, and anomalous network communications between containers.

## Technical Context
Adversaries often employ container technologies for their flexibility, scalability, and ease of deployment when conducting malicious activities. By leveraging techniques like T1613, adversaries aim to discover available resources within a host system that can be exploited or repurposed for further penetration. Common adversary methods include:

- Enumeration of running containers using commands such as `docker ps` or `crictl ps`.
- Accessing container logs and configurations to find potential vulnerabilities.
- Modifying network settings or resource limits to create covert channels.

### Adversary Emulation
To emulate this technique in a test environment, adversaries might execute the following sample commands:

#### Docker Container and Resource Discovery
```bash
docker ps -a  # Lists all containers on the host
docker inspect <container_id>  # Retrieves detailed configuration of a specified container
```

#### Podman Container and Resource Discovery
```bash
podman ps -a  # Lists all containers managed by Podman
podman inspect <container_name>  # Retrieves detailed information about a specific container
```

## Blind Spots and Assumptions
- **Blind Spots:** The detection strategy may not capture all unauthorized discovery attempts if adversaries use sophisticated obfuscation techniques or operate within highly segmented network zones.
- **Assumptions:** It assumes that monitoring tools are correctly configured to capture relevant data, and there is a baseline understanding of normal container activity patterns.

## False Positives
Potential benign activities that might trigger false alerts include:
- Routine administrative tasks performed by system administrators using discovery commands for maintenance or troubleshooting.
- Legitimate application updates or scaling operations within cloud-native environments where containers are frequently started and stopped.

## Priority
**Priority: High**

Justification: The potential impact of adversaries successfully discovering and exploiting container resources is significant, leading to data breaches, resource hijacking, or further lateral movement within the network. Therefore, robust detection mechanisms should be prioritized.

## Validation (Adversary Emulation)
### Docker Container and Resource Discovery
1. **Setup Environment**: Deploy a test environment with Docker installed.
2. **Run Containers**: Start multiple containers using varied configurations.
3. **Execute Commands**:
   - Use `docker ps -a` to list all containers.
   - Use `docker inspect <container_id>` to gather detailed information about each container.

### Podman Container and Resource Discovery
1. **Setup Environment**: Deploy a test environment with Podman installed.
2. **Run Containers**: Start multiple containers using varied configurations.
3. **Execute Commands**:
   - Use `podman ps -a` to list all containers.
   - Use `podman inspect <container_name>` to gather detailed information about each container.

## Response
When an alert fires, analysts should:

1. **Verify the Alert**: Confirm whether the detected activity is indeed malicious or a false positive by reviewing logs and contextual data.
2. **Contain the Threat**: Isolate suspicious containers from the network to prevent further unauthorized access or lateral movement.
3. **Investigate**: Perform a detailed investigation to understand the scope of the discovery attempt, including checking for any alterations made to container configurations or resource allocations.
4. **Remediate**: Implement necessary security patches and configuration changes to mitigate vulnerabilities exploited by the adversary.
5. **Report**: Document findings and update incident response plans accordingly.

## Additional Resources
- None available

This report outlines a comprehensive approach to detecting adversarial attempts at container resource discovery, ensuring that potential threats are identified promptly while minimizing false positives through careful validation and context analysis.