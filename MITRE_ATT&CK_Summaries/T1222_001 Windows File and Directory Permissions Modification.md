# Detection Strategy Report: Windows File and Directory Permissions Modification (T1222.001)

## Goal

The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring mechanisms by altering file and directory permissions on Windows systems. This technique allows adversaries to gain unauthorized access or elevate privileges, thereby compromising system integrity and confidentiality.

## Categorization

- **MITRE ATT&CK Mapping:** T1222.001 - Windows File and Directory Permissions Modification
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1222/001)

## Strategy Abstract

The detection strategy involves monitoring changes in file and directory permissions on Windows platforms. Key data sources include:

- Security Event Logs (e.g., Event ID 4663 for permission change events)
- System audit logs
- File integrity monitoring systems

Patterns analyzed involve unauthorized permission modifications, especially those that grant elevated privileges or obscure critical files from view.

## Technical Context

Adversaries often use built-in Windows utilities like `takeown`, `icacls`, and `attrib` to modify file permissions. These changes can bypass traditional security controls by hiding files, making them writable, or granting full access to unauthorized users or groups.

### Adversary Emulation Details

- **Take Ownership:** Using the `takeown` command to take ownership of a directory or file.
  - Example: `takeown /f C:\TargetFolder /r`
  
- **Change Access Control Lists (ACLs):** Granting permissions using `icacls`.
  - Example: `icacls C:\TargetFolder /grant Everyone:F /t`

- **Modify Attributes:** Using `attrib` to remove the read-only attribute or hide files.
  - Remove read-only: `attrib -r C:\TargetFile`
  - Hide file: `attrib +h C:\TargetFile`

## Blind Spots and Assumptions

- Limited visibility into all remote file systems may result in missed permission changes.
- Assumes that security logs are properly configured to capture all relevant events.
- May not detect sophisticated evasion techniques where attackers revert changes post-execution.

## False Positives

- Legitimate administrative activities involving bulk permission changes could trigger alerts.
- System or application updates that modify permissions as part of installation processes.
- Routine file management tasks by authorized personnel.

## Priority

**High:** Unauthorized modification of file and directory permissions can lead to significant security breaches, including data exfiltration and system compromise. The impact on confidentiality and integrity justifies a high priority for detection.

## Validation (Adversary Emulation)

To validate this detection strategy in a test environment:

1. **Take Ownership:**
   - Execute `takeown /f C:\TestFolder /r` to recursively take ownership of files within the folder.
   
2. **Change ACLs:**
   - Run `icacls C:\TestFolder /grant Everyone:F /t` to grant full access permissions to everyone recursively.

3. **Modify Attributes:**
   - Remove read-only attribute using `attrib -r C:\TestFile`.
   - Hide a file with `attrib +h C:\TestFile`.

4. **Ryuk Ransomware Style Permission Change:**
   - Execute `icacls C:\SensitiveData /grant Everyone:F` to simulate full access permission changes.

5. **SubInAcl Execution:**
   - Use SubInAcl tool for advanced permission modifications that are harder to detect with standard tools.

## Response

When an alert fires, analysts should:

- Immediately review the affected files and directories.
- Verify if the change was authorized by cross-referencing with administrative logs or requests.
- Revert unauthorized changes using PowerShell scripts or other privilege management tools.
- Investigate any associated lateral movement or data exfiltration activities.

## Additional Resources

For further context and additional details, consider these resources:

- File or Folder Permissions Modifications
- Potentially Suspicious CMD Shell Output Redirect
- Suspicious Recursive Takeown
- File or Folder Permissions Modifications techniques in various adversary tools

This comprehensive strategy aims to enhance detection capabilities against adversaries manipulating file permissions on Windows platforms.