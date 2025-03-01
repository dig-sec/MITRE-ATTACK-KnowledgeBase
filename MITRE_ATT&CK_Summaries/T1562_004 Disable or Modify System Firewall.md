# Alerting & Detection Strategy (ADS) Report

## Goal
This technique aims to detect adversarial attempts to disable, modify, or bypass system firewalls on various platforms. Such activities are often part of broader defense evasion strategies used by adversaries to maintain persistence and avoid detection.

## Categorization
- **MITRE ATT&CK Mapping:** T1562.004 - Disable or Modify System Firewall
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562/004)

## Strategy Abstract
The detection strategy leverages multiple data sources including system logs (Windows Event Logs, syslog), firewall configuration files, and network traffic patterns to identify unauthorized modifications or disabling of firewalls. The analysis focuses on detecting changes in firewall rules, unexpected service stops, and anomalies in firewall logging activities.

### Data Sources:
- System event logs
- Firewall rule configurations
- Network traffic analytics

### Patterns Analyzed:
- Unexpected changes in firewall configurations
- Stopping or restarting of firewall services
- Anomalies indicating unauthorized rule modifications

## Technical Context
Adversaries may disable or modify system firewalls to avoid detection and facilitate lateral movement within a network. Real-world techniques include registry modifications on Windows, command-line alterations on Linux/macOS, or direct changes via scripts.

### Adversary Emulation Details:
- **Windows:** Using commands like `netsh advfirewall set allprofiles state off` to disable the firewall.
- **Linux/Unix:** Commands such as `sudo ufw disable` to stop UFW (Uncomplicated Firewall).
- **macOS:** Utilizing built-in `pfctl` commands to disable Packet Filter.

## Blind Spots and Assumptions
- Assumes all modifications to firewall settings are malicious, which may not always be the case.
- Does not cover custom or proprietary firewalls that may have different configurations and log structures.
- Relies on predefined baselines for normal behavior; anomalies could be missed if baseline is not accurately defined.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate administrative actions to update firewall rules.
- Scheduled maintenance tasks involving temporary firewall deactivation or rule modification.
- Deployment of new applications requiring changes in firewall settings.

## Priority
**Severity: High**

Justification: Disabling or modifying system firewalls can provide adversaries with significant advantages, allowing them to move laterally within the network and access sensitive data without detection. This technique is a critical component of defense evasion tactics.

## Validation (Adversary Emulation)
The following steps outline how to emulate this technique in a controlled test environment:

1. **Disable Microsoft Defender Firewall**
   - Command: `netsh advfirewall set allprofiles state off`

2. **Modify Registry to Disable Windows Firewall**
   - Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess`
   - Modify the `Start` DWORD value to 4

3. **Enable SMB and RDP on Firewall**
   - Use `netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes`

4. **Open Ports via Proxy (HARDRAIN)**
   - Configure proxy settings allowing specific traffic through designated ports.

5. **Allow Local Port Through Windows Firewall**
   - Command: `New-NetFirewallRule -DisplayName "LocalPort" -Direction Inbound -LocalPort 3389 -Action Allow`

6. **Stop/Start UFW Firewall (Linux)**
   - Stop: `sudo ufw disable`
   - Start: `sudo ufw enable`

7. **Disable Iptables and Modify Rules (Linux)**
   - Disable: `sudo systemctl stop iptables`
   - Add/Delete rules using: `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` or `iptables -D INPUT -p tcp --dport 22 -j ACCEPT`

8. **Modify UFW Configurations (Linux)**
   - Edit files like `/etc/ufw/user.rules`, `/etc/default/ufw`, and `/etc/sysctl.conf`
   - Command to view logs: `tail -f /var/log/auth.log | grep ufw`

9. **Disable Windows Firewall via PowerShell (Blackbit Method)**
   - PowerShell: `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`

10. **ESXi Commands for Firewall Management**
    - Disable: `esxcli network firewall ruleset set --enabled=false`
    - Set to Pass Traffic: `esxcli network firewall ruleset set --action=pass`

## Response
When the alert fires:
1. Immediately isolate affected systems from the network.
2. Review recent firewall logs for unauthorized changes or service stops.
3. Verify with system administrators if any legitimate modifications were recently made.
4. Rollback unauthorized changes to restore baseline security settings.
5. Initiate a thorough investigation to determine potential breach vectors and ensure no other components of the defense-in-depth strategy have been compromised.

## Additional Resources
- None available

---

This report provides a structured approach for detecting, responding to, and validating techniques involving the disabling or modification of system firewalls across multiple platforms. By implementing this ADS framework, organizations can enhance their ability to detect adversarial activities and respond effectively.