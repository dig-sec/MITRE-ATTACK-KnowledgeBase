# Alerting & Detection Strategy (ADS) Report: Disk Wipe Detection

## Goal
The primary goal of this detection strategy is to identify adversarial attempts to wipe disk partitions on endpoints across various platforms with the intent of hindering forensic analysis and data recovery efforts.

## Categorization
- **MITRE ATT&CK Mapping:** T1561 - Disk Wipe
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1561)

## Strategy Abstract
The detection strategy leverages multiple data sources such as system logs (e.g., Sysmon on Windows, Auditd on Linux), process monitoring tools, and file integrity checks to identify disk wipe activities. The analysis focuses on detecting patterns indicative of data destruction, including the use of known wiping commands (like `shred`, `srm`), unusual access to disk management utilities, and abrupt changes in file system metadata that suggest large-scale data removal.

## Technical Context
Adversaries may execute a disk wipe by employing various tools or scripts designed for secure deletion. Common methods include using built-in OS utilities such as Windows Disk Management commands (`format`, `clean`), Linux utilities like `dd`, `shred`, and `srm`, or third-party software known to overwrite data sectors multiple times.

### Adversary Emulation Details
- **Sample Commands:**
  - Windows: `cmd.exe /c format C:\`
  - Linux: `sudo dd if=/dev/zero of=/dev/sda bs=1M` 
- **Test Scenarios:**
  - Execute the above commands in a controlled test environment to observe system behavior and log entries.
  
## Blind Spots and Assumptions
- Detection may not cover custom or obfuscated wiping scripts that do not employ known tools or patterns.
- Assumes that logging mechanisms are fully operational and unaltered by adversaries before the wipe attempt.

## False Positives
- Legitimate administrative activities such as routine disk formatting for decommissioning hardware or secure deletion of sensitive data in compliance with policies.
- Automated backup processes that may overwrite certain partitions during cleanup operations.

## Priority
**High:** The ability to detect and respond to disk wipes is critical, as successful execution can significantly impact forensic investigations and lead to permanent data loss. Given the potential severity of such activities, prompt detection is paramount.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Setup Test Environment:**
   - Prepare a test machine for each platform (Windows, Linux, macOS).
2. **Monitor Baseline Activity:**
   - Establish normal logging activity using Sysmon, Auditd, or similar tools.
3. **Execute Wipe Commands:**
   - Run typical disk wipe commands as outlined in the Technical Context section.
4. **Observe and Document:**
   - Capture logs generated during the wipe attempt and analyze for patterns indicative of malicious intent.
5. **Evaluate Detection Efficacy:**
   - Assess whether alerts were triggered appropriately and refine detection rules based on observations.

## Response
When an alert is fired, analysts should:
- Immediately isolate affected endpoints to prevent further data loss or propagation of the adversary's activities.
- Preserve existing logs and memory dumps for forensic analysis.
- Investigate the scope of the wipe by identifying affected partitions and assessing potential data recovery options.
- Initiate incident response procedures as per organizational policies.

## Additional Resources
- Further research into advanced disk wiping techniques and emerging tools used by adversaries could enhance detection capabilities.
- Collaboration with cybersecurity communities to share insights on novel indicators of compromise (IOCs) related to disk wipes.

---

This report provides a structured approach for detecting disk wipe activities, emphasizing the importance of comprehensive monitoring and timely response in mitigating potential threats.