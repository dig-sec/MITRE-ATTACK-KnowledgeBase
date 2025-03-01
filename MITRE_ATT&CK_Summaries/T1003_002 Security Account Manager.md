# Alerting & Detection Strategy (ADS) Report for Security Account Manager T1003.002

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring by accessing sensitive account information using Windows' Security Account Manager (SAM). Specifically, it focuses on detecting unauthorized access or extraction of credentials and secrets from the SAM database.

## Categorization
- **MITRE ATT&CK Mapping:** T1003.002 - Security Account Manager
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1003/002)

## Strategy Abstract
The detection strategy leverages multiple data sources including system logs, registry changes, and process monitoring. It analyzes patterns indicative of unauthorized SAM access or extraction attempts. Key activities include the use of tools like `pypykatz`, `esentutl.exe`, `PowerDump`, and others that can interact with the SAM database to extract credentials.

### Data Sources
- System Event Logs
- Registry Access Logs
- Process Monitoring Logs

### Patterns Analyzed
- Use of known credential dumping tools
- Access to specific registry keys related to SAM (e.g., HKLM\SYSTEM)
- Unusual process activity around system files associated with user account management
- Execution of commands or scripts that modify or access sensitive registry hives

## Technical Context
Adversaries often use various techniques and tools to extract credentials from the SAM database. Common methods include:

- **Registry Dumps:** Accessing the SAM hive directly via tools like `esentutl.exe` to export or parse it.
- **Volume Shadow Copy Exploits:** Using tools such as `certutil` to access and dump shadow copies of registry hives.
- **Credential Dumping Tools:** Utilizing tools like `pypykatz`, `PowerDump`, or custom scripts to extract credentials.

### Adversary Emulation Details
Adversaries might execute the following commands in a test environment:
- Use `esentutl.exe` to export the SAM database:  
  ```shell
  esentutl /d sam /y outputdir
  ```
- Parse the dumped SAM with `pypykatz`:  
  ```shell
  pypykatz samdump :: samfile
  ```

## Blind Spots and Assumptions
- Detection may not catch zero-day tools or custom scripts designed to evade existing signatures.
- Assumes that standard credential dumping behaviors are consistent across different systems.
- Potential gaps in detecting stealthier methods, such as those involving advanced evasion techniques.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks requiring access to SAM for troubleshooting or maintenance.
- Use of debugging tools by system administrators which may mimic malicious behavior.
- Scheduled tasks that legitimately interact with registry hives for backup purposes.

## Priority
**Severity: High**

Justification: Accessing and extracting credentials from the SAM database poses a significant threat as it can lead to full domain compromise. The ability to bypass security monitoring underscores its critical nature, necessitating high-priority detection efforts.

## Validation (Adversary Emulation)
Step-by-step instructions to emulate this technique in a test environment:

1. **Registry Dump of SAM, creds, and secrets:**
   - Use `esentutl.exe` to export the SAM database:
     ```shell
     esentutl /d sam /y outputdir
     ```

2. **Registry Parse with pypykatz:**
   - Analyze the dumped SAM file:
     ```shell
     pypykatz samdump :: samfile
     ```

3. **Volume Shadow Copy Hives Dumping:**
   - Use `certutil` to dump shadow copies of hives:
     ```shell
     certutil -urlcache -f http://127.0.0.1/somefile c:\temp\sam.hive
     ```
   - Alternatively, use `System.IO.File` in a script for similar operations.

4. **PowerDump Hashes and Usernames from Registry:**
   - Execute PowerDump to retrieve hashes:
     ```shell
     PowerDump.exe --just-dc-ip <domain_controller_ip>
     ```

5. **WinPwn - Loot Local Credentials:**
   - Use WinPwn to dump the SAM file for NTLM hashes:
     ```shell
     winpwn --loot
     ```

6. **Registry Export for Credential Data:**
   - Manually export registry keys related to credentials.

## Response
Guidelines for analysts when the alert fires:

1. **Immediate Isolation:** Quarantine affected systems to prevent further data exfiltration.
2. **Forensic Analysis:** Collect and analyze logs from system events, process monitoring, and registry access.
3. **Review Permissions:** Verify user permissions and roles to identify potential privilege escalation vectors.
4. **Update Security Policies:** Enhance security controls around sensitive registry areas and credential management.
5. **Incident Report:** Document the incident, including timeline, tools used by adversaries, and mitigation steps.

## Additional Resources
- [Copying Sensitive Files with Credential Data](https://example.com/copying-sensitive-files)
- [Potentially Suspicious CMD Shell Output Redirect](https://example.com/suspicious-cmd-output)
- [Sensitive File Access Via Volume Shadow Copy Backup](https://example.com/volume-shadow-copy-access)
- [File Encoded To Base64 Via Certutil.EXE](https://example.com/base64-certutil)
- [File In Suspicious Location Encoded To Base64 Via Certutil.EXE](https://example.com/suspicious-location-base64)