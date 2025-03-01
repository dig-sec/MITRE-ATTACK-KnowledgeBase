# Alerting & Detection Strategy (ADS) Framework Report

## **Goal**

The objective of this detection technique is to identify adversarial attempts aimed at bypassing security monitoring mechanisms through unauthorized modifications of file and directory permissions on macOS and Linux systems.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1222.002 - Linux and Mac File and Directory Permissions Modification
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** macOS, Linux

For more details, visit the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1222/002).

## **Strategy Abstract**

The detection strategy focuses on monitoring file and directory permission changes that may indicate adversarial activity. This involves analyzing logs from various data sources, including system audit logs, process event logs, and network traffic associated with commands altering permissions. Patterns of unauthorized `chmod`, `chown`, or attribute modification commands (e.g., `chattr`, `chflags`) are flagged for further investigation.

## **Technical Context**

Adversaries often modify file permissions to mask their tracks, gain persistence, or escalate privileges. Common methods include:
- Using `chmod` and `chown` to alter file/directory modes and ownership.
- Removing immutable attributes with `chattr -i` on Linux or `chflags nouchg` on macOS.

Adversaries might execute these commands through scripts embedded in legitimate processes or as part of larger exploitation frameworks. For instance, they may inject a C script into a running process to change permissions without triggering traditional security alerts.

## **Blind Spots and Assumptions**

- Assumes that all unauthorized permission changes are adversarial, potentially missing context for legitimate administrative tasks.
- Relies on accurate logging; misconfigurations or disabled logging can result in missed detections.
- Does not account for adversaries using sophisticated methods to bypass detection (e.g., leveraging kernel exploits).

## **False Positives**

Potential benign activities that could trigger false alerts include:
- Routine system administration and maintenance tasks.
- Scripted deployment processes altering permissions on files or directories.
- Legitimate software installations requiring permission changes.

## **Priority**

**Severity:** High

Justification: Unauthorized permission modifications can lead to significant security breaches, including data exfiltration, persistence, privilege escalation, and disruption of critical services. Due to the potential impact on system integrity and confidentiality, this detection is prioritized highly.

## **Validation (Adversary Emulation)**

To validate the detection strategy, follow these steps in a controlled test environment:

1. **chmod - Change file or folder mode (numeric mode)**
   ```bash
   chmod 777 /path/to/file
   ```

2. **chmod - Change file or folder mode (symbolic mode)**
   ```bash
   chmod u+s /path/to/file
   ```

3. **chmod - Change file or folder mode (numeric mode) recursively**
   ```bash
   find /directory/path -type d -exec chmod 755 {} \;
   ```

4. **chmod - Change file or folder mode (symbolic mode) recursively**
   ```bash
   find /directory/path -type f -exec chmod u+w,g-w,o-rwx {} \;
   ```

5. **chown - Change file or folder ownership and group**
   ```bash
   chown user:group /path/to/file
   ```

6. **chown - Change file or folder ownership and group recursively**
   ```bash
   find /directory/path -exec chown user:group {} \;
   ```

7. **chown - Change file or folder mode ownership only**
   ```bash
   chown --from=currentuser user /path/to/file
   ```

8. **chown - Change file or folder ownership recursively**
   ```bash
   find /directory/path -exec chown user {} \;
   ```

9. **chattr - Remove immutable file attribute (Linux)**
   ```bash
   chattr -i /path/to/file
   ```

10. **chflags - Remove immutable file attribute (macOS)**
    ```bash
    chflags nouchg /path/to/file
    ```

11. **Chmod through C script**  
    Compile and execute a simple C program that changes permissions:
    ```c
    #include <sys/stat.h>
    int main() {
        chmod("/path/to/file", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        return 0;
    }
    ```

12. **Chmod through C script (FreeBSD)**
    Similar to the above, using FreeBSD-specific libraries if needed.

13. **Chown through C script**  
    Compile and execute a simple C program that changes ownership:
    ```c
    #include <unistd.h>
    int main() {
        chown("/path/to/file", 1000, 100);
        return 0;
    }
    ```

14. **Chown through C script (FreeBSD)**
    Similar to the above, using FreeBSD-specific libraries if needed.

## **Response**

When an alert is triggered:
- Immediately isolate and review affected systems.
- Analyze logs for unauthorized access or privilege escalation attempts.
- Verify changes against a baseline of known good configurations.
- Engage with incident response protocols to determine further actions such as containment, eradication, recovery, and post-mortem analysis.

## **Additional Resources**

For further reading and context:
- [Remove Immutable File Attribute](https://www.cyberciti.biz/faq/linux-change-file-and-directory-permissions/)
- [Execution Of Script Located In Potentially Suspicious Directory](https://attack.mitre.org/techniques/T1106)
- [Chmod Suspicious Directory](https://attack.mitre.org/techniques/T1098)

These resources provide deeper insights into the techniques and implications of unauthorized file permission changes.