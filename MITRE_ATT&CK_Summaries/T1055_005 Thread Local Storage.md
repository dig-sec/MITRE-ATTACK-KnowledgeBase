# Palantir's Alerting & Detection Strategy (ADS) Framework: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## **Goal**

The goal of this technique is to detect adversarial attempts to bypass security monitoring by leveraging containerization technologies, particularly on Windows platforms.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1055.005 - Thread Local Storage
- **Tactic / Kill Chain Phases:** Defense Evasion, Privilege Escalation
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1055/005)

## **Strategy Abstract**

The detection strategy involves monitoring container activities and utilizing Windows Event Logs to identify suspicious behavior that may indicate attempts at evasion. Key data sources include:

- Container runtime logs
- Windows Security Event Logs (e.g., process creation, network connections)
- System call traces

Patterns analyzed for anomalies include unusual process spawning within containers, unexpected access to sensitive system resources, and abnormal inter-container communications.

## **Technical Context**

Adversaries often use containers as a method to evade detection by traditional security tools that might not be container-aware. On Windows systems, they may leverage Thread Local Storage (TLS) to maintain state information across different execution contexts within a container, effectively hiding their activities from standard monitoring solutions.

### Adversary Emulation Details

- **Sample Commands:** 
  - Creating containers with elevated privileges using `docker run --privileged`
  - Modifying TLS keys and data structures for process persistence
- **Test Scenarios:**
  - Running malicious code inside a container without detection by endpoint protection tools
  - Establishing covert communications between containers to exfiltrate data

## **Blind Spots and Assumptions**

- Assumes that all containers are subject to the same level of scrutiny as traditional processes.
- Limited visibility into advanced obfuscation techniques within TLS that adversaries might employ.
- Relies on accurate logging by container runtimes, which may be tampered with or disabled.

## **False Positives**

Potential benign activities that could trigger false alerts include:

- Legitimate use of containers for development and testing environments
- Standard administrative tasks that involve process creation or modification within containers

## **Priority**

**Severity: High**

Justification: Given the increasing adoption of container technologies in enterprise environments, adversaries are more likely to exploit them as a means of evasion. The potential impact includes bypassing security controls, gaining unauthorized access, and exfiltrating sensitive data.

## **Validation (Adversary Emulation)**

Currently, no specific step-by-step instructions for emulation are available. However, the following general steps can be considered:

1. Set up a Windows environment with Docker installed.
2. Execute containers with elevated privileges.
3. Modify TLS keys to persist processes across container restarts.
4. Observe whether existing security monitoring tools detect these activities.

## **Response**

When an alert fires indicating potential adversarial activity within containers, analysts should:

- Immediately isolate the affected container(s) and prevent further execution or communication.
- Review logs for any anomalous behavior patterns.
- Conduct a thorough forensic analysis to determine if there has been a breach or data exfiltration.
- Update detection rules based on findings to improve future identification of similar threats.

## **Additional Resources**

Currently, no additional resources are available. Future updates may include case studies and more detailed adversary emulation scenarios for enhanced understanding and validation.