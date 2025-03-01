# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this detection strategy is to identify adversarial attempts to bypass security monitoring by using containers for data exfiltration.

## Categorization
- **MITRE ATT&CK Mapping:** T1560 - Archive Collected Data
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1560)

## Strategy Abstract
This detection strategy aims to identify adversaries using container technologies for data exfiltration. It leverages network traffic analysis, file system monitoring, and process tracking across multiple platforms (Linux, macOS, Windows). The key indicators include unusual network traffic patterns originating from container workloads, unexpected creation of archive files within containers, and anomalous execution of compression utilities.

## Technical Context
Adversaries may use containers to hide data exfiltration activities by executing processes that compress and export sensitive data. Containers can encapsulate these processes, making detection more challenging due to their ephemeral nature. Adversary techniques often involve:

- **Compression and Encryption:** Using tools like `tar`, `zip`, or PowerShell cmdlets (`Compress-Archive`) to create compressed datasets.
- **Network Egress Monitoring:** Identifying unexpected traffic patterns that deviate from the normal baseline.

### Emulation Example
Adversaries may execute commands such as:
```bash
# On Linux/macOS
tar -czf /path/to/archive.tar.gz /sensitive/data

# On Windows (PowerShell)
Compress-Archive -Path C:\SensitiveData\* -DestinationPath C:\Archive\SensitiveData.zip
```

## Blind Spots and Assumptions
- **Blind Spots:** Detection may not capture highly obfuscated or encrypted traffic that appears benign.
- **Assumptions:** Assumes baseline normal network and file system behavior is well-established for accurate anomaly detection.

## False Positives
Potential false positives include:
- Legitimate backup operations using similar compression tools.
- Routine software updates packaged in compressed archives.
- Development environments where containerized applications frequently package data.

## Priority
**Priority: High**

Justification: The ability to exfiltrate data undetected poses significant risks, especially if sensitive or critical information is involved. Given the stealth capabilities of containers and their potential use by sophisticated adversaries, this technique warrants a high priority for detection efforts.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

#### Environment Setup
1. **Install Docker:** Ensure Docker is installed on your test environment.
2. **Prepare Test Data:** Create sample sensitive data files for testing.

#### Compress Data for Exfiltration With PowerShell
1. Open a Windows machine with PowerShell.
2. Execute the following command to compress data:
   ```powershell
   Compress-Archive -Path C:\SensitiveData\* -DestinationPath C:\Archive\SensitiveData.zip
   ```
3. Start a Docker container and observe network traffic or file system changes.

#### Observations
- Monitor for unexpected creation of compressed files.
- Analyze network traffic patterns to identify unusual data transfers from the container.

## Response
When an alert is triggered:
1. **Verify Activity:** Confirm if the detected activity aligns with known benign operations (e.g., backups, updates).
2. **Investigate Context:** Examine logs for associated events and correlate with other security incidents.
3. **Contain Threat:** If malicious intent is confirmed, isolate affected containers to prevent further data exfiltration.

## Additional Resources
- None available

---

This report provides a comprehensive framework for detecting adversarial use of containers in data exfiltration activities, following Palantir's ADS methodology.