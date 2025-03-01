# Detection Strategy: Resource Hijacking via Container Exploitation

## Goal
The primary goal of this detection strategy is to identify adversarial attempts to leverage container environments in bypassing security monitoring systems, ultimately leading to resource hijacking.

## Categorization
- **MITRE ATT&CK Mapping:** T1496 - Resource Hijacking
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Windows, IaaS, Linux, macOS, Containers

For more details on MITRE ATT&CK's technique, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1496).

## Strategy Abstract
This detection strategy focuses on monitoring containerized environments for signs of resource hijacking. The key data sources include:
- Container runtime logs
- System performance metrics
- Network traffic patterns

Patterns to analyze involve unusual CPU, memory, or disk usage indicative of a compromised container attempting to consume excessive resources, thereby impacting legitimate applications.

## Technical Context
Adversaries may execute this technique by exploiting vulnerabilities within the host operating system or the container orchestration platform. Common methods include:
- Overloading the host's CPU or memory via malicious containers.
- Using containers to mask command-and-control (C2) communications.

Sample adversary emulation command for testing:
```bash
yes > /dev/null &
```
This command simulates high CPU load in a test environment, allowing analysts to observe resource consumption patterns typical of hijacking attempts.

## Blind Spots and Assumptions
- **Blind Spots:** Detection might miss sophisticated attacks that mimic legitimate application behavior or those leveraging zero-day vulnerabilities.
- **Assumptions:** It is assumed that the baseline performance metrics for containers are well-established, allowing anomalies to be detected accurately.

## False Positives
Potential false positives include:
- Legitimate applications experiencing unexpected spikes in resource usage due to workload changes or bugs.
- Scheduled maintenance tasks causing temporary resource surges.

## Priority
**Severity: High**

Justification:
Resource hijacking can lead to severe disruptions by degrading service availability and performance, making it critical to detect and mitigate promptly.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **FreeBSD/macOS/Linux - Simulate CPU Load with Yes**
   ```bash
   yes > /dev/null &
   ```
   This command creates a background process that continuously outputs 'yes', consuming significant CPU resources and mimicking resource hijacking behavior.

2. Monitor the system's response using:
   - Top/htop for CPU/memory usage.
   - Container orchestration logs (e.g., Kubernetes events).

3. Validate detection by checking if alerts are triggered based on predefined anomaly thresholds.

## Response
When an alert fires, analysts should:

1. **Verify the Alert:** Confirm that the observed resource consumption is abnormal compared to historical data and current operational context.
2. **Containment:**
   - Isolate the suspicious container from the network or host resources if necessary.
   - Investigate running processes within the container for any malicious activity.

3. **Investigation:**
   - Examine logs for unauthorized access attempts or unusual behavior patterns.
   - Check for known vulnerabilities in container images and runtime environments.

4. **Mitigation:**
   - Apply patches to address any identified vulnerabilities.
   - Strengthen security policies around container deployment and resource limits.

5. **Documentation:** Record the incident details, response actions taken, and lessons learned to improve future detection strategies.

## Additional Resources
- None available

This report serves as a guideline for implementing an effective detection strategy against adversarial resource hijacking attempts within container environments, helping to safeguard organizational assets and maintain service integrity.