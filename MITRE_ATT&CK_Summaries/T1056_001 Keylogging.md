# Palantir's Alerting & Detection Strategy (ADS) Report: Keylogging Detection

## Goal
The objective of this detection strategy is to identify adversarial attempts to implement keylogging activities across various platforms—Windows, macOS, Linux—to gain unauthorized access and collect sensitive information without detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1056.001 - Keylogging
- **Tactic / Kill Chain Phases:** Collection, Credential Access
- **Platforms:** Windows, macOS, Linux, Network

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1056/001)

## Strategy Abstract
This detection strategy leverages multiple data sources such as logs from authentication services (e.g., SSHD), process monitoring systems (like Auditd on Linux), and system-specific logging utilities (e.g., Bash history, PAM modules). The patterns analyzed include unusual keystroke logging activities or unexpected output from typical command execution that suggests keylogging behavior. 

### Data Sources
- **Windows:** Event logs related to remote access and keyboard activity.
- **macOS:** System logs capturing input sequences indicative of keylogging.
- **Linux:** 
  - `pam.d` configurations for SSHD sessions.
  - Bash and sh history logging into syslog.
  - Auditd logs capturing detailed user actions.

## Technical Context
Adversaries often employ keyloggers to bypass security mechanisms by directly harvesting credentials or other sensitive information. These keylogging methods can include:
- Using legitimate system tools modified for malicious purposes (e.g., modifying `bash_history` configurations).
- Installing third-party keylogging software via phishing attacks.
- Leveraging compromised credentials to elevate access and deploy keyloggers.

Adversaries may execute these techniques using scripts or binaries that hook into keyboard event listeners. For example:
```sh
# Example of configuring SSHD PAM for capturing terminal input on Linux
echo "auth required pam_exec.so /usr/local/bin/keylogger" >> /etc/pam.d/sshd
```

## Blind Spots and Assumptions
- **Blind Spot:** The detection may miss obfuscated keylogging scripts or those embedded within legitimate software.
- **Assumptions:** This strategy assumes logging mechanisms are intact and properly configured to capture relevant data.

## False Positives
Potential benign activities that could trigger false alerts include:
- Legitimate system administration tasks involving command history captures for troubleshooting.
- Development environments where keystroke capturing is used for debugging or testing purposes.

## Priority
**Severity: High**

Justification: Keylogging can lead directly to credential theft and unauthorized access, making it a critical threat vector with potentially severe consequences.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

1. **Linux - Input Capture via PAM**
   - Modify the SSHD configuration to include PAM-based keylogging.
   ```sh
   echo "auth required pam_exec.so /usr/local/bin/keylogger" >> /etc/pam.d/sshd
   ```

2. **Bash and Sh History Logging to Syslog/Messages**
   - Configure bash history logging:
     ```sh
     echo 'export PROMPT_COMMAND="history -a; history -n"' >> ~/.bashrc
     ```
   - Redirect logs:
     ```sh
     logger -p local0.info "Captured command: $(history 1)"
     ```

3. **Bash Session Keylogger**
   - Create a simple bash session keylogger script.
     ```sh
     cat << 'EOF' > ~/.bashrc_keylogger.sh
     trap 'logger -p user.notice "Command: $BASH_COMMAND"' DEBUG
     EOF
     source ~/.bashrc_keylogger.sh
     ```

4. **Auditd Keylogger**
   - Set up `auditd` to monitor keyboard events:
     ```sh
     auditctl -w /dev/input/eventX -p wa -k keylogger
     ```

5. **macOS Swift Keylogger**
   - Deploy a Swift-based keylogger script and execute it within the macOS environment.
   - Example setup might involve using Xcode to compile a basic keylogging utility.

## Response
When an alert indicating potential keylogging activity is detected, analysts should:
- Immediately isolate affected systems from the network to prevent data exfiltration.
- Review log files for suspicious entries or patterns associated with unauthorized access attempts.
- Conduct a thorough investigation into recent administrative changes that might have enabled such activities.
- Notify security operations and legal teams if sensitive data has been potentially compromised.

## Additional Resources
- [Malicious PowerShell Commandlets - ProcessCreation](#)
- Comprehensive guides on secure logging configurations across platforms to prevent exploitation of log systems themselves. 

This strategy provides a multi-faceted approach for detecting keylogging attempts, addressing common adversarial techniques and offering robust detection capabilities across diverse operating environments.