# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using NTFS Alternate Data Streams (ADS)

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by leveraging NTFS Alternate Data Streams (ADS). Specifically, it focuses on the misuse of ADS for hiding malicious payloads or sensitive data from traditional file system scanning tools.

## Categorization

- **MITRE ATT&CK Mapping:** T1564.004 - NTFS File Attributes
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1564/004)

## Strategy Abstract

The detection strategy involves monitoring file system activities on Windows platforms to identify the creation and manipulation of NTFS Alternate Data Streams (ADS). Key data sources include:

- **Windows Event Logs:** Monitoring for events related to file operations, specifically focusing on Event IDs that indicate changes in file attributes or the addition of alternate data streams.
- **File Integrity Monitoring Tools:** These tools can help detect unauthorized changes to files, including the addition of ADS.
- **Behavioral Analysis:** Analyzing patterns of behavior associated with known ADS manipulation techniques.

Patterns analyzed include:

- Unusual creation of large numbers of alternate data streams on files or directories.
- Access patterns that indicate attempts to read from or write to these streams without typical user interaction.
- File operations that do not align with normal business processes, such as the sudden appearance of hidden directories or files.

## Technical Context

Adversaries exploit NTFS ADS by hiding malicious payloads within alternate data streams. This technique allows them to evade detection by traditional antivirus and file integrity monitoring tools, which may not inspect these streams during their scans.

### Execution in Real World

1. **Command Prompt:** Adversaries might use commands like `echo <malicious_content> > <filename>:<stream_name>` to create an ADS.
2. **PowerShell:** Commands such as `[System.IO.File]::WriteAllText("<filename>:<stream_name>", "<malicious_content>")` can be used to write data into an ADS.

### Adversary Emulation Details

- **Sample Command Prompt Scenario:**
  - `echo MalwarePayload > maliciousfile.txt:hiddenstream`
  
- **Sample PowerShell Scenario:**
  - `[System.IO.File]::WriteAllText("maliciousfile.txt:hiddenstream", "MalwarePayload")`

## Blind Spots and Assumptions

- **Blind Spots:** 
  - Detection may not be effective if ADS are used in conjunction with other sophisticated evasion techniques.
  - Limited visibility into encrypted streams or those accessed via low-level APIs.

- **Assumptions:**
  - The system logs and monitoring tools are correctly configured to capture relevant file system events.
  - Analysts have access to baseline behavior patterns for normal versus malicious ADS usage.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate software using ADS for storing metadata or configuration settings.
- System processes that create temporary ADS during routine operations.
- User actions that inadvertently create ADS, such as copying files with embedded streams from another system.

## Priority

**Severity:** High

**Justification:** The ability to hide malicious payloads within ADS can significantly compromise the security posture of an organization by bypassing traditional detection mechanisms. Given the stealth nature and potential impact, this technique warrants high priority for detection and response efforts.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Create Alternate Data Stream:**
   - Open Command Prompt as Administrator.
   - Execute: `echo TestPayload > testfile.txt:hiddenstream`

2. **Verify ADS Creation:**
   - Use the command: `more < testfile.txt:hiddenstream` to view the stream content.

3. **PowerShell Alternative:**
   - Run PowerShell as Administrator.
   - Execute: `[System.IO.File]::WriteAllText("testfile.txt:hiddenstream", "TestPayload")`

4. **Create Hidden Directory via $index_allocation:**
   - Use: `fsutil file queryextattr testdir:$index_allocation` to create a hidden directory.

5. **Validate Detection:**
   - Ensure monitoring tools and logs capture these activities as expected.

## Response

When an alert for ADS manipulation is triggered:

1. **Immediate Containment:**
   - Isolate the affected system from the network to prevent further spread or data exfiltration.
   
2. **Investigation:**
   - Analyze the specific file and stream involved to determine if malicious content exists.
   - Review related logs for additional context on the operation.

3. **Remediation:**
   - Remove any identified malicious payloads from ADS.
   - Update security tools to ensure they inspect alternate data streams in future scans.

4. **Post-Incident Analysis:**
   - Conduct a thorough review of the incident to identify how the adversary gained access and how detection could be improved.

## Additional Resources

- [Microsoft Documentation on NTFS Alternate Data Streams](https://docs.microsoft.com/en-us/windows/win32/fileio/alternate-data-streams)
- [Whitepapers on ADS Detection Techniques](#) (Placeholder for future resources)

This report provides a comprehensive framework for detecting and responding to adversarial use of NTFS Alternate Data Streams, aligning with Palantir's Alerting & Detection Strategy.