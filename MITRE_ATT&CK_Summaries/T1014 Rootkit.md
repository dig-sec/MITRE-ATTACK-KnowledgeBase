# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring through the misuse of container technologies. This includes adversaries leveraging containers as a means to execute and hide malicious activities, thereby evading detection by traditional endpoint security solutions.

## Categorization
- **MITRE ATT&CK Mapping:** T1014 - Rootkit
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1014)

## Strategy Abstract
This detection strategy focuses on identifying anomalous behaviors associated with container usage that could indicate malicious intent. Key data sources include container runtime logs, network traffic patterns, and system-level events. Patterns analyzed involve:

- Unusual spikes in resource utilization specific to certain containers.
- Containers running processes typically reserved for root or privileged operations without proper authorization.
- Unexpected network communications between containers and external endpoints.

The strategy also leverages behavioral analytics to identify deviations from the normal operational baseline of containerized environments.

## Technical Context
Adversaries exploit container technologies due to their inherent isolation capabilities, which can be subverted to hide malicious activities. Common methods include:

- **Loadable Kernel Module (LKM) based Rootkits:** Adversaries may deploy kernel modules within a host or container environment to gain unauthorized access and conceal processes.
  
  Example command:
  ```bash
  insmod /path/to/rootkit.ko
  ```

- **Dynamic-linker based rootkits:** Techniques like `libprocesshider` can manipulate the dynamic linker to hide processes from process listings.

  Sample execution:
  ```bash
  LD_PRELOAD=/path/to/libprocesshider.so command-to-hide
  ```

These methods enable adversaries to execute and persist malicious activities undetected within containerized environments, often bypassing traditional endpoint security measures.

## Blind Spots and Assumptions
- **Assumption:** Containers are deployed in a well-monitored environment where baseline behaviors are known.
- **Blind Spot:** The strategy may not detect rootkits that use sophisticated evasion techniques to disguise their presence entirely.
- **Limitation:** High false positive rates in environments with dynamic or non-standard container usage patterns.

## False Positives
Potential benign activities that might trigger alerts include:

- Legitimate administrative processes using elevated privileges within containers.
- Development and testing phases involving high resource utilization and network traffic.
- Misconfigurations leading to temporary spikes in resource usage or unexpected process executions.

## Priority
**Severity: High**

Justification: Containers are increasingly used in production environments, making them a lucrative target for adversaries. The ability of rootkits to bypass detection mechanisms poses a significant threat, potentially compromising the entire container ecosystem and associated data integrity.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Loadable Kernel Module based Rootkit:**
   - Deploy a non-malicious kernel module on a test host.
   - Monitor for successful loading and execution using:
     ```bash
     lsmod | grep rootkit
     ```

2. **Dynamic-linker based rootkit (libprocesshider):**
   - Use `LD_PRELOAD` to load `libprocesshider.so` in a benign process.
   - Verify the process is hidden from standard listings:
     ```bash
     ps aux | grep command-to-hide
     ```

3. **Loadable Kernel Module based Rootkit (Diamorphine):**
   - Install and execute Diamorphine on a test system, observing its ability to hide processes.
   - Confirm evasion by checking for hidden processes:
     ```bash
     sudo ./diamorphine
     ps aux | grep hidden_process
     ```

These steps should be conducted in a controlled environment with proper security measures to prevent accidental spread or detection of real malicious activities.

## Response
When an alert fires, analysts should:

1. **Immediate Containment:**
   - Isolate affected containers and hosts to prevent further potential compromise.
   
2. **Investigation:**
   - Analyze logs from container runtimes (e.g., Docker, Kubernetes) for suspicious activity.
   - Examine network traffic for unusual patterns or destinations.

3. **Remediation:**
   - Remove any unauthorized kernel modules or binaries found within the environment.
   - Update security policies to prevent similar incidents and enhance monitoring capabilities.

4. **Reporting:**
   - Document findings and actions taken, informing stakeholders of potential risks and required improvements.

## Additional Resources
Currently, no additional resources are available beyond those cited in this report. Future updates may include case studies or threat intelligence reports related to container security challenges.