# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring by using containers. Attackers may exploit container technology to obscure malicious activities and evade detection mechanisms.

## Categorization
- **MITRE ATT&CK Mapping:** T1562 - Impair Defenses
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows, Office 365, IaaS, Linux, macOS, Containers, Network

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1562)

## Strategy Abstract
The detection strategy leverages logs and network traffic data from containers to identify patterns indicative of adversarial activities. Key data sources include container orchestration platform logs (e.g., Kubernetes), host system logs, network flow data, and application-level logging within containers. The strategy focuses on detecting anomalies such as unauthorized changes in container configurations, unusual inter-container communications, or attempts to disable logging mechanisms.

## Technical Context
Adversaries may use containers to obscure command and control traffic, hide malicious payloads, or create isolated environments for their operations. In practice, they might:

- Modify container image layers to include malware.
- Use volume mounts to access sensitive data.
- Exploit container runtime vulnerabilities to gain elevated privileges.
- Disable logging within a container to prevent detection of their activities.

Adversary emulation can involve:
- Modifying `docker-compose.yml` files to include hidden services.
- Using tools like `kubectl exec` or `docker exec` to execute commands within containers.
- Attempting to disable logging by altering configuration files or using in-container scripts.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Detection might miss highly sophisticated techniques where adversaries use legitimate container operations for malicious purposes without triggering known patterns.
  - Limited visibility into encrypted traffic within containers could obscure detection of certain activities.
  
- **Assumptions:**
  - The security monitoring system has full visibility and access to all relevant logs from the container environment.
  - Security policies are in place to prevent unauthorized modifications to container configurations.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate use of containers for development or testing purposes, where unusual network traffic patterns may occur.
- Routine updates or maintenance tasks performed by IT teams that alter logging configurations temporarily.
- Misconfigured security tools within containers leading to unintended log suppression.

## Priority
**Severity:** High  
**Justification:** The ability to bypass security monitoring using containers poses a significant threat as it can allow adversaries to operate undetected, potentially causing substantial damage or data exfiltration before detection.

## Validation (Adversary Emulation)
To validate the strategy, follow these steps in a controlled test environment:

1. **Windows Disable LSA Protection:**
   - Use PowerShell:
     ```powershell
     Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableProtection" -Value 1
     ```

2. **Disable Journal Logging via `systemctl` Utility:**
   - For a service (e.g., `rsyslog`):
     ```bash
     sudo systemctl stop rsyslog
     sudo systemctl disable rsyslog
     ```

3. **Disable Journal Logging via `sed` Utility:**
   - Modify `journald.conf`:
     ```bash
     sudo sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
     sudo systemctl restart systemd-journald
     ```

## Response
When an alert is triggered, analysts should:

1. **Verify the Alert:** Confirm whether the detected activity aligns with known adversarial patterns.
2. **Investigate the Source:** Identify the source of the suspicious container activity and trace its origin.
3. **Contain the Threat:** Isolate affected containers to prevent further spread or data exfiltration.
4. **Analyze Logs:** Review logs from the container orchestration platform, host systems, and network traffic for additional indicators of compromise.
5. **Remediate:** Re-enable any disabled logging features and apply necessary patches or updates to mitigate vulnerabilities.

## Additional Resources
- **Disable Or Stop Services**: Explore techniques adversaries use to disable services as part of their defense evasion tactics.
- **LSA PPL Protection Disabled Via Reg.EXE**: Understand how disabling LSA protection can aid in adversary persistence and concealment efforts.