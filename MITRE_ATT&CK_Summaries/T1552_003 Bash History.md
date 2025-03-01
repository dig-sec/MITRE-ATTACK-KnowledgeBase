# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
The aim of this technique is to detect adversarial attempts to bypass security monitoring by manipulating bash and shell history files on Unix-based systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1552.003 - Bash History
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1552/003)

## Strategy Abstract
The detection strategy leverages system logs and file integrity monitoring to identify unauthorized modifications or accesses to bash and shell history files. Key data sources include:
- **Audit Logs:** To capture access attempts on `.bash_history` and `.sh_history`.
- **File Integrity Monitoring (FIM):** To detect changes in these files.

Patterns analyzed involve:
- Unexpected modifications or deletions.
- Access patterns that deviate from normal user behavior, such as accessing history files at unusual times or by unauthorized users.

## Technical Context
Adversaries exploit bash history to cover their tracks by modifying or deleting entries. This technique involves manipulating the `.bash_history` and `.sh_history` files to erase command traces used in privilege escalation or lateral movement.

### Adversary Emulation Details:
- **Sample Commands:**
  - `history -c`: Clears the current session's bash history.
  - `cat /dev/null > ~/.bash_history`: Overwrites the bash history file with an empty file.
  
- **Test Scenarios:**
  - Simulate an adversary clearing command history after performing malicious activities.
  - Monitor for unauthorized users accessing or modifying these files.

## Blind Spots and Assumptions
### Known Limitations:
- Detection may not cover all scenarios where history manipulation occurs, such as non-standard shell usage or custom configurations that alter default behavior.
  
### Assumptions:
- The system maintains comprehensive audit logging and FIM capabilities.
- Users adhere to standard practices without extensive customizations that could obscure history logs.

## False Positives
Potential benign activities include:
- Legitimate users clearing their command history for privacy reasons.
- System administrators performing maintenance tasks involving bash history files.
- Automated scripts that temporarily modify or clear history as part of a routine process.

## Priority
**Severity: High**

### Justification:
Manipulating bash history can obscure the presence and actions of adversaries, making detection and response more challenging. The ability to bypass security monitoring significantly increases the risk to sensitive systems and data.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Search Through Bash History:**
   - Execute `history` command to view current session history.
   - Use `echo "test_command" >> ~/.bash_history` to append a test entry.
   - Run `history -c` to clear the session history.

2. **Search Through sh History:**
   - For systems using `sh`, check `.sh_history`.
   - Append with `echo "test_command" >> ~/.sh_history`.
   - Clear with `cat /dev/null > ~/.sh_history`.

Monitor system logs and FIM alerts for any unauthorized access or modifications during these steps.

## Response
When the alert fires:
1. **Verify Context:** Determine if the activity aligns with known legitimate operations (e.g., maintenance).
2. **Investigate User Activity:** Assess whether an authorized user performed the actions.
3. **Analyze Timing and Scope:** Evaluate when and how often such activities occur to identify patterns.
4. **Contain Potential Threat:** If suspicious, isolate affected systems and conduct a thorough investigation.

## Additional Resources
- None available

This report provides a comprehensive framework for detecting and responding to adversarial attempts at history manipulation on Unix-based platforms.