# Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers (PAM Exploits)

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring using containers by exploiting Pluggable Authentication Modules (PAM). The focus is on identifying unauthorized modifications or the introduction of malicious PAM rules/modules that adversaries use to evade detection and maintain persistent access.

## Categorization

- **MITRE ATT&CK Mapping:** T1556.003 - Pluggable Authentication Modules
- **Tactic / Kill Chain Phases:**
  - Credential Access
  - Defense Evasion
  - Persistence
- **Platforms:** Linux, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1556/003)

## Strategy Abstract
The detection strategy involves monitoring for unauthorized changes to PAM configurations and the loading of unexpected or unverified PAM modules. Key data sources include:

- System log files (e.g., `/var/log/auth.log` on Linux, `system.log` in macOS)
- Configuration file change tracking (e.g., using tools like Tripwire or AIDE for PAM-related files such as `/etc/pam.d/`)
- Anomaly detection in authentication events that could indicate the presence of malicious modules

Patterns analyzed include:

- Unauthorized modifications to existing PAM configuration files
- Introduction of new, unverified PAM modules into system directories
- Unusual patterns or spikes in failed authentication attempts

## Technical Context
Adversaries may exploit PAM by inserting malicious rules or loading unauthorized modules designed to bypass security controls. These activities can facilitate credential theft, unauthorized access persistence, and evasion of logging mechanisms.

### Adversary Emulation Details

1. **Sample Commands:**
   - On Linux:
     ```bash
     sudo nano /etc/pam.d/common-auth
     ```
     Add a malicious rule or module path.
   - On FreeBSD:
     ```bash
     sudo vi /etc/login.conf
     ```
     Insert suspicious configurations.

2. **Test Scenarios:**
   - Create a test environment with PAM monitoring tools.
   - Simulate the insertion of a benign but unusual rule to observe detection capabilities.
   - Emulate loading a non-standard PAM module and verify if it triggers alerts.

## Blind Spots and Assumptions
- Assumes that all legitimate changes to PAM configurations are appropriately documented or monitored by other systems.
- Detection might miss sophisticated adversaries who manipulate logs post-exploitation.
- Relies on the assumption that standard logging mechanisms capture relevant data without tampering.

## False Positives
Potential benign activities that could trigger false alerts include:

- Legitimate updates to PAM rules as part of routine maintenance or system upgrades.
- Changes made by administrators for testing purposes in development environments.
- Misconfigurations introduced inadvertently during software installations or migrations.

## Priority
**Priority: High**

Justification:
- Exploitation of PAM can lead to severe security breaches, including credential theft and persistent unauthorized access.
- The technique is prevalent among sophisticated adversaries aiming to maintain stealthy control over compromised systems.

## Validation (Adversary Emulation)

### Steps to Emulate in a Test Environment

#### Malicious PAM Rule
1. Create a test environment using virtual machines or containers with Linux/macOS.
2. Insert a benign but unusual rule into `/etc/pam.d/common-auth`.
   ```bash
   echo "auth optional pam_test.so" | sudo tee -a /etc/pam.d/common-auth > /dev/null
   ```
3. Observe if any security monitoring tools detect this change.

#### Malicious PAM Rule (FreeBSD)
1. On a FreeBSD test system, modify `/etc/login.conf`.
2. Add an unusual setting:
   ```bash
   vi /etc/login.conf
   # Insert under appropriate section
   auth	: system-auth { ... }
   ```
3. Monitor for detection alerts.

#### Malicious PAM Module
1. Create or obtain a test PAM module that mimics malicious behavior.
2. Place it in `/lib/security/` (or equivalent) on the test system.
3. Ensure the module is referenced in a configuration file like `/etc/pam.d/common-auth`.
4. Check for alert triggers.

## Response
When an alert fires:

1. **Immediate Actions:**
   - Isolate affected systems to prevent further compromise.
   - Review recent changes to PAM configurations and validate their legitimacy.

2. **Investigation:**
   - Analyze logs for suspicious activities or unauthorized access attempts.
   - Verify if any additional security controls (e.g., IDS/IPS) have been bypassed.

3. **Remediation:**
   - Revert unauthorized changes to PAM files.
   - Remove unauthorized PAM modules and restore from backups if necessary.
   - Update monitoring systems to improve detection of similar future attempts.

4. **Post-Incident Review:**
   - Conduct a thorough analysis to understand the breach's scope.
   - Improve security policies, training, and technical controls based on findings.

## Additional Resources
- None available

This report provides a comprehensive strategy for detecting adversarial exploitation of PAM configurations within Linux and macOS environments. The outlined approach leverages monitoring tools and anomaly detection techniques to identify unauthorized modifications or the introduction of malicious modules effectively.