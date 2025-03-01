# Detection Strategy: Unauthorized Use of SSH Authorized Keys for Persistence

## Goal
This technique aims to detect adversarial attempts to use unauthorized SSH authorized keys to maintain persistence on compromised systems, particularly in environments running Linux and macOS.

## Categorization
- **MITRE ATT&CK Mapping:** T1098.004 - SSH Authorized Keys
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Linux, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1098/004)

## Strategy Abstract
The detection strategy focuses on monitoring changes to the SSH authorized keys file (`~/.ssh/authorized_keys`) across systems. Key data sources include system logs (e.g., auditd, syslog) and configuration management databases that track authorized key entries. The strategy analyzes patterns of unauthorized modifications or additions to these files, especially those not aligning with typical administrative activities or baseline configurations.

## Technical Context
Adversaries may insert their own SSH keys into the `authorized_keys` file on a target system without authorization, allowing them persistent access even if other accounts are locked out. This technique is often used post-compromise as part of lateral movement and persistence strategies.

### Adversary Emulation Details
- **Execution:** An adversary with sufficient privileges might execute commands such as:
  ```bash
  echo 'ssh-rsa AAA... user@domain' >> ~/.ssh/authorized_keys
  ```
- **Detection Scenario:** Monitor for unauthorized writes to the `authorized_keys` file, especially when no corresponding legitimate administrative action is recorded.

## Blind Spots and Assumptions
- Assumes that changes to `authorized_keys` are logged accurately.
- May not detect scenarios where keys are added without direct modification of the file (e.g., using configuration management tools).
- Relies on having a baseline for normal authorized key entries, which may vary across environments.

## False Positives
- Authorized administrative updates to SSH configurations could trigger alerts if not properly accounted for in baselines.
- Automated scripts or configuration management tools used by IT teams that modify `authorized_keys` without explicit logging of such activities.

## Priority
**High**: Given the potential for adversaries to maintain access stealthily, detecting unauthorized changes to SSH keys is critical. Unauthorized persistence poses significant risks as it allows continued access and control over compromised systems.

## Validation (Adversary Emulation)
To validate this detection strategy in a test environment:

1. **Baseline Setup:**
   - Identify existing authorized keys on the system.
   - Configure logging for `authorized_keys` modifications.

2. **Emulate Adversarial Activity:**
   - Gain access to a test Linux or macOS machine with sudo privileges.
   - Execute:
     ```bash
     echo 'ssh-rsa AAA... simulated@adversary' >> ~/.ssh/authorized_keys
     ```
   - Verify that this action is logged by system monitoring tools.

3. **Verification:**
   - Confirm the detection system flags the unauthorized key addition as per the defined pattern rules.
   - Ensure alerts are generated and correlate with the activity log entries.

## Response
When an alert for unauthorized SSH key modification fires, analysts should:

1. **Verify Alert:** Cross-check the alert against known administrative activities to rule out false positives.
2. **Investigate:**
   - Review logs around the time of the change for signs of compromise or unauthorized access attempts.
   - Identify which user accounts were modified and assess their privileges.
3. **Containment:**
   - Immediately disable any suspicious keys from the `authorized_keys` file.
   - Revoke potentially compromised credentials and rotate SSH keys.
4. **Remediation:**
   - Conduct a thorough security review of all affected systems.
   - Update monitoring baselines to reflect legitimate changes.

5. **Follow-Up:**
   - Document findings and remedial actions taken.
   - Enhance detection mechanisms based on insights gained from the incident.

## Additional Resources
- None available

This report provides a comprehensive overview of detecting unauthorized SSH key modifications as part of an ADS framework, offering strategic guidance for implementation and response in enterprise environments.