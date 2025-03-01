# Alerting & Detection Strategy: Detecting Active Scanning Attempts Using Containers

## Goal
The goal of this detection strategy is to identify adversarial attempts to conduct active scanning activities within a network using containerized environments. The primary objective is to detect and alert on the use of containers for reconnaissance purposes, such as port or vulnerability scanning.

## Categorization
- **MITRE ATT&CK Mapping:** T1595 - Active Scanning
- **Tactic / Kill Chain Phases:** Reconnaissance
- **Platforms:** PRE (Pre-Execution)
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1595)

## Strategy Abstract
This detection strategy leverages container activity logs and network traffic data to identify patterns indicative of active scanning. By monitoring for unusual container behaviors, such as atypical port scans or repeated access attempts to known vulnerable services, we can detect potential reconnaissance efforts. The strategy involves analyzing:
- Container orchestration logs (e.g., Kubernetes events)
- Network flow data for irregular outbound/inbound traffic
- Known malicious signatures associated with scanning tools

## Technical Context
Adversaries often use containers due to their ability to quickly deploy and dispose of scanning tools without leaving obvious traces on the host system. This approach allows them to perform reconnaissance while minimizing detection risk. Commonly used containerized scanning tools include `masscan`, `nmap`, and custom scripts designed for specific network targets.

### Adversary Emulation Details
- **Commands Used:** 
  - `docker run --rm masscan <target>`: Runs a one-off scan using the Masscan tool.
  - `kubectl exec <pod> -- nmap -sT <target>`: Executes an Nmap scan within a Kubernetes pod.

- **Test Scenarios:**
  - Deploy a container with a known scanning tool and attempt to perform port scans against internal network targets.
  - Observe the container lifecycle events for unusual behavior patterns, such as rapid creation/deletion cycles.

## Blind Spots and Assumptions
- **Blind Spots:** 
  - Detection may not cover highly obfuscated or encrypted traffic that mimics benign container activities.
  - Zero-day scanning tools or techniques not yet cataloged in signature databases could evade detection.

- **Assumptions:**
  - Network flow data is available and accurately captures all relevant traffic.
  - Container orchestration platforms log sufficient detail to identify suspicious activity patterns.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate network scanning conducted by IT teams for vulnerability assessments or audits.
- Use of containerized applications with built-in health check mechanisms that involve scanning services.
- Development environments where frequent container creation and destruction is normal behavior.

## Priority
**Severity: High**

Justification: Active scanning represents a critical reconnaissance step in adversarial operations, often preceding more destructive activities. The ability to detect such scans early can significantly mitigate the risk of further compromise by allowing for timely response measures.

## Response
When an alert triggers indicating potential active scanning via containers:
1. **Immediate Containment:** Isolate affected network segments or specific containers identified in the alert.
2. **Investigate Logs:** Review container orchestration and network logs to confirm suspicious activity patterns.
3. **Enhance Monitoring:** Temporarily increase monitoring sensitivity for similar activities across other network nodes.
4. **Alert Security Teams:** Notify relevant security personnel to conduct a thorough investigation and implement additional defenses if necessary.

## Additional Resources
- No specific resources available; refer to general best practices on container security and active scanning detection methodologies.
- Continuous review of the MITRE ATT&CK framework for updates on new techniques or tools used by adversaries. 

This strategy provides a robust framework for detecting adversarial reconnaissance efforts using containers, helping organizations proactively defend against potential threats.