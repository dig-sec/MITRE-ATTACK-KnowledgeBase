# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring using containers and other methods that involve discovering system network configurations.

---

## Categorization
- **MITRE ATT&CK Mapping:** T1016 - System Network Configuration Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1016)

---

## Strategy Abstract

### Overview
The detection strategy focuses on identifying unauthorized attempts to discover system network configurations. It leverages multiple data sources and pattern recognition techniques across various platforms.

### Data Sources
- **Log Files:** System logs, firewall logs, and security event logs.
- **Network Traffic:** Packet captures and flow data for anomalous behavior analysis.
- **Endpoint Monitoring:** Processes and command execution tracking on endpoints.

### Patterns Analyzed
1. Execution of network discovery commands or scripts.
2. Unusual access patterns to network configuration files.
3. Anomalous changes in firewall rules or system network settings.
4. Discovery attempts that bypass security controls using containerization methods.

---

## Technical Context

Adversaries typically execute system network configuration discovery through command-line tools, scripts, and exploit kits designed to probe the target environment for vulnerabilities or misconfigurations.

### Real-World Execution
- **Command Usage:** Adversaries may use commands like `netstat`, `ipconfig`, `ifconfig`, or custom scripts.
- **Tools:** Tools such as AdFind, Qakbot Recon tools, and others tailored to network discovery.

### Emulation Scenarios
- Simulating command executions that reveal network configurations.
- Testing the detection of unauthorized access to network configuration files.

---

## Blind Spots and Assumptions

### Known Limitations
- Inability to detect highly obfuscated commands or scripts designed to evade signature-based detection.
- Detection might not cover all variations of custom tools used by adversaries.

### Assumptions
- Assumes that baseline configurations are well-documented and deviations can be identified as suspicious.
- Relies on the availability of comprehensive logging mechanisms across platforms.

---

## False Positives

Potential benign activities include:
- Legitimate network management tasks performed by IT personnel.
- Routine administrative scripts executed during maintenance windows.
- Standard software updates or patches that alter network configurations temporarily.

---

## Priority
**Severity:** High  
**Justification:** Unauthorized access to system network configuration can lead to significant security breaches, including data exfiltration and lateral movement within the network. The ability of adversaries to bypass monitoring mechanisms heightens this threat.

---

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **System Network Configuration Discovery on Windows**
   - Use `netsh advfirewall show allprofiles` to list firewall rules.
   - Execute `ipconfig /all` for network configuration details.

2. **List Windows Firewall Rules**
   - Command: `Get-NetFirewallRule | Select DisplayName, Enabled`

3. **System Network Configuration Discovery**
   - Linux/MacOS: Use commands like `ifconfig`, `netstat`.
   - Check logs for unusual execution patterns of these commands.

4. **System Network Configuration Discovery (TrickBot Style)**
   - Utilize scripts that automate discovery processes similar to TrickBot behavior.
   - Monitor script executions and resultant changes in network settings.

5. **List Open Egress Ports**
   - Use `netstat -an` or equivalent tools across platforms to identify open ports.

6. **Adfind - Enumerate Active Directory Subnet Objects**
   - Execute AdFind tool with relevant parameters to simulate adversary behavior.

7. **Qakbot Recon**
   - Simulate Qakbot reconnaissance activities and monitor for associated command patterns.

8. **List macOS Firewall Rules**
   - Command: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps`

9. **DNS Server Discovery Using nslookup**
   - Execute `nslookup` commands to probe DNS configurations and log results for analysis.

---

## Response

### Guidelines for Analysts
1. Verify the legitimacy of detected activities by cross-referencing with scheduled tasks or known administrative processes.
2. Isolate affected systems to prevent potential lateral movement.
3. Conduct a thorough investigation into logs and network traffic associated with the alert.
4. Update detection rules based on findings to improve future response accuracy.

---

## Additional Resources

- **Network Reconnaissance Activity:** Detailed analysis of common reconnaissance techniques used by adversaries.
- **PUA - AdFind Suspicious Execution:** Understanding potential misuse of tools like AdFind in malicious contexts.
- **Suspicious Network Command:** Patterns and indicators of network-related commands that may suggest adversarial intent.

This report provides a comprehensive overview of the ADS framework for detecting system network configuration discovery attempts, aligned with Palantir's strategic approach to threat detection.