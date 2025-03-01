# Alerting & Detection Strategy Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal

This technique aims to detect adversarial attempts to bypass security monitoring by leveraging container technology. Specifically, it focuses on identifying unauthorized access and manipulation of credentials within containers across multiple platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1552.001 - Credentials In Files
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows, IaaS, Linux, macOS, Containers
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1552/001)

## Strategy Abstract

The detection strategy involves monitoring container environments for suspicious activities that indicate credential access attempts. Key data sources include:

- Container logs and metadata
- File system access patterns
- Network traffic between containers
- Host-level system logs

Patterns analyzed include unusual file access, unexpected network connections, and anomalies in process execution within containers.

## Technical Context

Adversaries may execute this technique by deploying malicious containers that search for credential files or attempt to exfiltrate sensitive data. Common methods include:

- Using tools like LaZagne to extract browser and system credentials.
- Scanning file systems with commands such as `grep` or `findstr` for known credential patterns.
- Accessing configuration files like `unattend.xml` for embedded credentials.

Adversaries may also use custom scripts or leverage container orchestration platforms to scale their attacks across multiple nodes.

## Blind Spots and Assumptions

- **Blind Spots:** 
  - Encrypted containers that are not decrypted in transit or at rest.
  - Use of advanced obfuscation techniques to hide credential access patterns.
  
- **Assumptions:**
  - Containers have logging enabled and logs are accessible for analysis.
  - Host systems are configured to capture relevant network traffic.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate administrative tasks involving file searches or system maintenance.
- Development environments where credential files are used for testing purposes.
- Misconfigured containers that inadvertently access sensitive data without malicious intent.

## Priority

**Severity: High**

Justification: Unauthorized access to credentials can lead to significant security breaches, allowing adversaries to move laterally within networks and compromise additional systems. The use of containers adds complexity and scalability to attacks, increasing the potential impact.

## Validation (Adversary Emulation)

To emulate this technique in a test environment, follow these steps:

1. **Find AWS Credentials:**
   - Search for `.aws` directories or files containing access keys.
   
2. **Extract Browser and System Credentials with LaZagne:**
   - Run LaZagne to extract stored credentials from browsers and system applications.

3. **Extract Passwords with grep:**
   - Use `grep` to search for known password patterns in text files.

4. **Extracting Passwords with findstr:**
   - Utilize `findstr` on Windows systems to locate credential-related keywords.

5. **Access unattend.xml:**
   - Locate and review `unattend.xml` files for embedded credentials.

6. **Find and Access GitHub Credentials:**
   - Search for `.gitconfig` or other configuration files containing GitHub tokens.

7. **WinPwn Tools:**
   - Use WinPwn tools (`sensitivefiles`, `Snaffler`, `powershellsensitive`, `passhunt`, `SessionGopher`) to identify and extract sensitive data from Windows systems.

8. **Loot Local Credentials:**
   - Identify AWS, Microsoft Azure, and Google Compute credentials using WinPwn's credential hunting features.

9. **List Credential Files via PowerShell:**
   - Execute PowerShell scripts to enumerate files containing potential credentials.

10. **List Credential Files via Command Prompt:**
    - Use command-line tools to search for known credential file patterns.

11. **Find Azure Credentials:**
    - Search for `.azure` directories or configuration files with access keys.

12. **Find GCP Credentials:**
    - Locate Google Cloud Platform credential files and service account keys.

13. **Find OCI Credentials:**
    - Identify Oracle Cloud Infrastructure credentials within system files.

## Response

When the alert fires, analysts should:

1. Isolate affected containers to prevent further unauthorized access.
2. Conduct a thorough investigation of logs and network traffic for signs of lateral movement or data exfiltration.
3. Verify if any credentials have been compromised and initiate credential rotation procedures.
4. Update security policies and configurations to mitigate similar future attempts.

## Additional Resources

Additional references and context are currently unavailable but should be compiled as further insights into container-based attacks become available.