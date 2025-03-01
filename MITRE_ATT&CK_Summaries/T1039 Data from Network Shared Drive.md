# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by leveraging containers as a means of concealment and execution for malicious activities.

## Categorization
- **MITRE ATT&CK Mapping:** T1039 - Data from Network Shared Drive
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1039)

## Strategy Abstract
The detection strategy involves monitoring data movement and interactions with network shared drives across multiple platforms (Linux, macOS, Windows) to identify unauthorized or suspicious activities. Key data sources include file system logs, network traffic analysis, container orchestration events, and host-based security monitoring tools. The patterns analyzed focus on anomalous access to administrative shares, abnormal file operations within containers, and unexpected data transfers that might indicate attempts at bypassing traditional monitoring mechanisms.

## Technical Context
Adversaries often use containers to execute scripts or applications covertly because containers can isolate processes from the host environment. This isolation can help adversaries hide their activities from conventional security tools not designed to monitor containerized environments. Real-world execution may involve mounting network drives inside containers and transferring sensitive data unnoticed by leveraging administrative shares.

### Adversary Emulation Details
- **Sample Commands:**
  - On Windows, adversaries might use PowerShell commands such as `Copy-Item` to transfer files over shared network locations.
  - On Linux or macOS, similar operations can be performed using `cp` with SSH mounted drives or through container orchestration tools like Kubernetes.

### Test Scenarios
- Set up a test environment with Docker/Kubernetes and configure containers that have access to administrative shares.
- Execute commands from within these containers to simulate data transfer activities over network shared drives.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection might miss highly sophisticated adversaries who use advanced obfuscation techniques or low-and-slow attacks.
  - Containers that are only briefly active may evade detection if logs are not continuously monitored.
  
- **Assumptions:**
  - Assumes that network shares and administrative shares have been properly configured and are being actively monitored.
  - Relies on the assumption that all containers are subject to logging and monitoring policies.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks involving file copying over network drives by authorized personnel.
- Scheduled backup processes or maintenance scripts running within containerized environments.
- Development operations using containers for testing purposes without malicious intent.

## Priority
**Severity:** High

**Justification:** The ability to bypass security monitoring represents a significant threat as it allows adversaries to operate undetected, potentially leading to data exfiltration and other malicious activities. The use of containers adds complexity to detection efforts, making this technique particularly concerning in environments with extensive containerized applications.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Set Up Environment:**
   - Configure a network with shared drives accessible over the network.
   - Deploy a container orchestration platform like Docker or Kubernetes.

2. **Create Test Containers:**
   - Build containers that have access to administrative shares (e.g., `//admin/share` on Windows).

3. **Emulate Adversarial Activity:**

   - **Copy Using Command Line:**
     ```shell
     # On Windows container
     cmd.exe /c copy C:\sensitivefile.txt \\admin\share\sensitivefile.txt
     
     # On Linux/MacOS container using SSH mounted drive
     cp /path/to/sensitivefile.txt /mnt/admin/share/sensitivefile.txt
     ```

   - **Copy Using PowerShell:**
     ```powershell
     # Inside a Windows container
     Copy-Item C:\sensitivefile.txt \\admin\share\sensitivefile.txt
     ```

4. **Monitor Logs and Alerts:**
   - Check file system logs, network traffic captures, and container orchestration events for signs of the above activities.

## Response
When an alert is triggered:
1. **Immediate Investigation:**
   - Verify if the activity originated from a legitimate source or an unauthorized entity.
   - Assess the context and frequency of the data transfer to determine if it aligns with normal operations.

2. **Containment:**
   - Isolate the affected containers and network shares to prevent further unauthorized access.
   - Review and adjust container security policies to enhance monitoring capabilities.

3. **Root Cause Analysis:**
   - Conduct a thorough analysis to understand how the adversary bypassed existing defenses.
   - Identify any configuration weaknesses or gaps in current detection strategies.

4. **Remediation:**
   - Implement additional controls such as enhanced logging, network segmentation, and stricter access policies for containers interacting with administrative shares.

5. **Post-Incident Review:**
   - Document findings and update security protocols to prevent similar incidents.
   - Conduct training sessions to raise awareness of new detection strategies among the security team.

## Additional Resources
- Suspicious Script Execution From Temp Folder
- Suspicious Copy From or To System Directory
- Copy From Or To Admin Share Or Sysvol Folder
- Review existing documentation and best practices for securing containerized environments against unauthorized data access.