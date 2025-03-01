# Alerting & Detection Strategy (ADS) Report: Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containerization technologies, such as Docker and Kubernetes, which can be exploited to execute malicious activities while evading traditional detection mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1204.002 - Malicious File
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1204/002)

## Strategy Abstract
The detection strategy involves monitoring and analyzing container activity data from various sources such as Docker logs, Kubernetes audit logs, host system logs, network traffic, and process execution events. Key patterns include unexpected or unauthorized creation of containers, unusual image pulls, anomalous network connections initiated by containers, and execution of suspicious binaries within containers.

## Technical Context
Adversaries use containerization to isolate malicious processes from the host operating environment, making detection harder for traditional security tools. They may inject malware into images before pushing them to registries or create runtime scripts that exploit container privileges. Common techniques include:
- **Command Injection:** Using shell commands in container orchestration files to execute unauthorized code.
- **Image Tampering:** Modifying base images with malicious content.

### Adversary Emulation Details
Example of adversary actions:
1. Pull a compromised image from a public registry.
2. Run the image with elevated privileges.
3. Execute arbitrary code within the container to perform lateral movement or data exfiltration.

Sample commands used in emulation tests:
- `docker pull maliciousimage:latest`
- `docker run --privileged -d maliciousimage`

## Blind Spots and Assumptions
- **Blind Spots:** Limited visibility into deeply nested container activities, potential for encrypted network traffic to conceal communication.
- **Assumptions:** Assumes that all containers are running within a monitored environment with complete access to logs and process monitoring.

## False Positives
Potential benign activities include:
- Legitimate use of containers for testing or development purposes.
- Standard administrative operations involving image pulls and container management by authorized users.

## Priority
**Priority: High**

Justification: Containers can significantly obscure malicious activities, providing attackers with a robust mechanism to bypass detection systems. The growing adoption of containerized environments in critical infrastructures increases the risk and potential impact of such attacks.

## Validation (Adversary Emulation)
To emulate this technique, follow these steps:

### OSTap Style Macro Execution
- Create a document embedding a macro that downloads an OSTap payload when executed.

### OSTap Payload Download
- Use macros to fetch payloads from external sources using `URLDownloadToFile`.

### Maldoc Choice Flags Command Execution
- Embed choice flags within the malicious document to execute different commands based on user interaction.

### OSTAP JS Version
- Execute JavaScript-based downloads and executions similar to VBA scripts for cross-platform compatibility.

### Office Launching .bat File from AppData
- Create a batch file that launches in the context of an Office application, executing further commands.

### Excel 4 Macro
- Use legacy Excel macros to trigger payloads when interacting with spreadsheets.

### Headless Chrome Code Execution via VBA
- Invoke headless Chrome instances through VBA scripts for covert web-based operations.

### Potentially Unwanted Applications (PUA)
- Detect and evaluate applications marked as PUA within container environments.

### Office Generic Payload Download
- Utilize generic Office templates to pull in payloads when documents are opened.

### LNK Payload Download
- Leverage shortcut (.lnk) files to download malicious content upon access.

### Mirror Blast Emulation
- Simulate simultaneous downloads from multiple sources to test detection capabilities.

## Response
When an alert fires, analysts should:
1. **Isolate the Container:** Immediately stop and isolate the suspected container.
2. **Analyze Logs:** Review Docker/Kubernetes logs for unauthorized commands or image pulls.
3. **Inspect Network Traffic:** Monitor outbound connections for suspicious activity.
4. **Forensic Examination:** Conduct a forensic analysis of the container's filesystem and processes.
5. **Revise Policies:** Update security policies to prevent similar incidents.

## Additional Resources
- **Usage Of Web Request Commands And Cmdlets**
  - Monitor PowerShell scripts using `Invoke-WebRequest` or web requests in general for signs of data exfiltration or command & control communication.

- **PowerShell Web Download**
  - Track and analyze web downloads initiated through PowerShell to identify unauthorized external communications.

- **Suspicious Invoke-WebRequest Execution**
  - Validate the legitimacy of `Invoke-WebRequest` operations based on source, destination, and payload analysis.

- **Potentially Suspicious CMD Shell Output Redirect**
  - Observe command shell output redirects as they may indicate attempts to obfuscate malicious activity within logs or files. 

This strategy provides a comprehensive approach to detecting and mitigating the risks posed by adversaries exploiting containers for malicious purposes.