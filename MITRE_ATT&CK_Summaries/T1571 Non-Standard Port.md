# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Non-Standard Ports

## Goal
The primary goal of this technique is to detect adversarial attempts to bypass security monitoring by utilizing non-standard network ports. Such techniques are often employed in command and control (C2) operations, where adversaries seek to avoid detection by traditional security systems that focus on well-known or standard ports.

## Categorization

- **MITRE ATT&CK Mapping:** T1571 - Non-Standard Port
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1571)

## Strategy Abstract
The detection strategy involves monitoring network traffic across all ports to identify any activity that deviates from established norms. Key data sources include:

- Network Traffic Logs: Capturing and analyzing packets for unusual port usage.
- Firewall Rules: Monitoring changes or exceptions in firewall configurations that might enable non-standard port usage.

Patterns analyzed will focus on unexpected or irregular traffic volumes, particularly where the traffic is directed to ports not typically associated with legitimate services. The strategy emphasizes correlating this network activity with other indicators of compromise (IOCs) to enhance detection accuracy and reduce false positives.

## Technical Context
Adversaries often execute this technique by configuring their malware or tools to communicate over non-standard ports, such as 4444, 8080, or any other port not typically associated with the intended service. This allows them to bypass security measures that are tuned only for standard ports like HTTP (80) or HTTPS (443).

### Adversary Emulation Details
- **Sample Commands:**
  - PowerShell: `New-NetFirewallRule -DisplayName "Allow Port 4444" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Allow`
  - Linux/macOS: Using iptables or equivalent to redirect traffic:
    ```bash
    sudo iptables -t nat -A PREROUTING -p tcp --dport 4444 -j REDIRECT --to-port 80
    ```

- **Test Scenarios:**
  - Simulate C2 communication by sending packets from a controlled client machine to a server on a non-standard port.
  - Monitor and log the traffic using network monitoring tools like Wireshark or tcpdump.

## Blind Spots and Assumptions
### Known Limitations:
- The strategy assumes that all ports are monitored, which may not be feasible in highly dynamic environments with numerous open ports.
- It relies on anomaly detection systems to distinguish between benign and malicious use of non-standard ports, which can be challenging without comprehensive baseline data.

### Assumptions:
- Organizations have implemented logging for all network traffic.
- Security teams have established baselines for normal network behavior.

## False Positives
Potential benign activities that might trigger false alerts include:

- Legitimate applications or services configured to use non-standard ports due to port conflicts or specific requirements (e.g., development environments, testing scenarios).
- Misconfigured internal devices using non-standard ports inadvertently.

To mitigate these false positives, it is essential to continuously update the baseline of normal network activity and integrate context from other security layers such as endpoint detection and response (EDR) systems.

## Priority
**Severity: High**

Justification:
The use of non-standard ports for C2 communications represents a significant threat due to its potential to bypass traditional security measures, making it challenging to detect without dedicated monitoring. Early detection is crucial in preventing adversaries from establishing persistent access or exfiltrating data undetected.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

#### Testing Usage of Uncommonly Used Port with PowerShell
1. **Set up a Test Environment:**
   - Use virtual machines to simulate both the client and server environments.
2. **Configure Firewall Rule:**
   ```powershell
   New-NetFirewallRule -DisplayName "Test Non-Standard Port" -Direction Inbound -LocalPort 9999 -Protocol TCP -Action Allow
   ```
3. **Create a Simple Server Script (Python):**
   ```python
   import socket

   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server.bind(('0.0.0.0', 9999))
   server.listen(5)

   while True:
       client_socket, addr = server.accept()
       print(f"Connection from {addr}")
       client_socket.close()
   ```
4. **Client Communication:**
   ```powershell
   $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 9999)
   ```

#### Testing Usage of Uncommonly Used Port (Generic)
1. **Set up Network Monitoring:**
   - Use tools like Wireshark to capture traffic on all ports.
2. **Simulate Traffic:**
   - From the client, connect to the server using a non-standard port (e.g., 9999).
3. **Analyze Captured Data:**
   - Confirm that traffic is detected and logged correctly.

## Response
When an alert for non-standard port usage fires:

1. **Immediate Actions:**
   - Isolate affected systems from the network to prevent further communication.
   - Capture detailed logs of the suspicious activity for analysis.

2. **Investigation Steps:**
   - Correlate with other security alerts (e.g., unusual login attempts, file changes) to assess if this is part of a broader attack.
   - Identify the source and destination IP addresses involved in the communication.

3. **Remediation:**
   - Update firewall rules to block the suspicious port unless it's verified as legitimate.
   - Patch any vulnerabilities that allowed the adversary initial access.

4. **Post-Incident Review:**
   - Conduct a thorough review of security posture and update detection strategies accordingly.
   - Share findings with relevant stakeholders to enhance organizational awareness and defenses.

## Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Network Traffic Analysis Tools Documentation (e.g., Wireshark, tcpdump)
- PowerShell and Linux firewall configuration guides

This ADS report provides a comprehensive framework for detecting adversarial use of non-standard ports, highlighting key strategies, potential challenges, and actionable response guidelines.