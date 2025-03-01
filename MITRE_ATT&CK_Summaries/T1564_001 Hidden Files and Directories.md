# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this technique is to detect adversarial attempts to bypass security monitoring through the creation of hidden files and directories on systems across various platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1564.001 - Hidden Files and Directories
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, macOS, Linux
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1564/001)

## Strategy Abstract
This detection strategy leverages multiple data sources such as file system logs, process monitoring tools, and registry activity on Windows systems. By analyzing patterns that involve the creation of hidden files or directories, it aims to identify attempts at evasion by adversaries. The key focus is on tracking changes in file attributes (hidden, system) and detecting the use of specific commands or scripts indicative of such activities.

## Technical Context
Adversaries often exploit hidden files and directories to conceal malicious payloads or tools, thereby evading detection from traditional security mechanisms. These techniques can be executed using various methods:

- **Windows:** Using command-line utilities like `attrib` or PowerShell commands.
  - Example: `attrib +h +s filename`
  - PowerShell: `Set-ItemProperty -Path .\filename.txt -Name Attributes -Value "Hidden, System"`
  
- **macOS/Linux:** Utilizing file attribute changes or prefixing filenames with a dot to hide them.
  - Example: `mv filename.txt .filename.txt`

Adversary emulation can be performed using these methods in controlled environments to validate detection capabilities.

## Blind Spots and Assumptions
- Assumes that all hidden files are malicious, which may not always be the case.
- Relies on accurate logging of file attribute changes; gaps in logging could lead to missed detections.
- May not detect files hidden through advanced obfuscation techniques beyond simple attribute modifications.

## False Positives
Potential benign activities include:
- Legitimate software that uses hidden directories for configuration or cache data.
- User practices, such as hiding personal files, which may result in the creation of hidden files and folders.

## Priority
**High**: The technique is prioritized at a high level due to its effectiveness in allowing adversaries to bypass security controls undetected. Detection can significantly enhance visibility into potential evasion tactics used by advanced threat actors.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Create a hidden file in a hidden directory**
   - Create a directory: `mkdir .hiddenDir`
   - Navigate to it: `cd .hiddenDir`
   - Create a hidden file: `touch .hiddenFile`

2. **Mac Hidden file**
   - Use the command: `mv filename.txt .filename.txt`

3. **Create Windows System File with Attrib**
   - Command: `attrib +s filename.exe`

4. **Create Windows Hidden File with Attrib**
   - Command: `attrib +h filename.txt`

5. **Hide a Directory**
   - Use the command: `attrib +h directoryName`

6. **Show all hidden files**
   - On Windows: `dir /a:h`
   - On macOS/Linux: `ls -la`

7. **Hide Files Through Registry (Windows)**
   - Modify registry key to hide specific file extensions:
     ```powershell
     Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt' -Name 'Hidden' -Value 1
     ```

8. **Create Windows Hidden File with PowerShell**
   - Command: `Set-ItemProperty -Path .\filename.txt -Name Attributes -Value "Hidden"`

9. **Create Windows System File with PowerShell**
   - Command: `Set-ItemProperty -Path .\filename.exe -Name Attributes -Value "System"`

## Response
When an alert for hidden file or directory creation is triggered:
1. Verify the context and source of the activity.
2. Assess whether the files are associated with known legitimate applications or user behavior.
3. Investigate further to determine if there is any suspicious activity linked to these files (e.g., unusual network connections, execution patterns).
4. If malicious intent is confirmed, follow incident response protocols including containment, eradication, and recovery measures.

## Additional Resources
- None available

This comprehensive ADS report provides a structured approach to detecting the use of hidden files and directories by adversaries across multiple platforms, enhancing the ability to identify potential security evasion tactics effectively.