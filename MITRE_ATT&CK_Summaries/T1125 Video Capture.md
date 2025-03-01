# Palantir's Alerting & Detection Strategy (ADS) Framework: Detect Adversarial Use of Video Capture

## Goal
The primary aim of this detection strategy is to identify adversarial attempts that leverage video capture functionalities within applications running on Windows and macOS systems, with a focus on detecting unauthorized or covert use of webcams for surveillance purposes.

## Categorization
- **MITRE ATT&CK Mapping:** T1125 - Video Capture
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Windows, macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1125)

## Strategy Abstract
The detection strategy leverages various data sources including system logs, process monitoring, and registry changes. By analyzing patterns of access to webcam hardware, the system flags any unauthorized attempts to activate or monitor the camera without user consent. Key indicators include unusual application behaviors such as unexpected launching of video capture software, registry modifications related to webcam permissions, and network traffic suggesting remote transmission of video data.

## Technical Context
Adversaries may exploit legitimate applications or use malicious scripts to gain access to a system’s video capture capabilities. This is often achieved by modifying registry settings to grant unauthorized applications control over the camera. In real-world scenarios, attackers might deploy tools that request webcam access for seemingly benign activities but subsequently stream video data to remote servers.

### Adversary Emulation Details
- **Sample Commands:** Attackers may use PowerShell or batch scripts to modify registry keys associated with camera permissions.
- **Test Scenarios:** Simulate unauthorized attempts by altering registry settings to allow non-standard applications webcam access and observe system alerts.

## Blind Spots and Assumptions
- **Blind Spots:**
  - Encrypted traffic that conceals video data transmission may evade detection.
  - Sophisticated adversaries might use steganography within legitimate streams of data.
  
- **Assumptions:**
  - User consent for webcam access is typically granted through explicit application requests, detectable in logs.
  - Registry changes are a reliable indicator of attempts to manipulate device permissions.

## False Positives
Potential benign activities that could trigger false alerts include:
- Users granting webcam access to legitimate applications (e.g., video conferencing software).
- Updates or installations of new software requiring temporary camera access for configuration purposes.
- User-initiated system scans or backups that include hardware checks involving the webcam.

## Priority
**Severity:** High

**Justification:** Unauthorized use of webcams poses a significant privacy risk and can lead to sensitive information being captured without user knowledge. The potential damage from such surveillance activities justifies prioritizing this detection strategy as high.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Environment Setup:**
   - Use a controlled test environment with Windows or macOS systems.
   
2. **Simulate Unauthorized Access:**
   - Open an elevated command prompt and execute the following PowerShell script to modify registry keys related to webcam access:
     ```powershell
     Set-ItemProperty -Path "HKLM:\Software\Classes\{4d36e968-e8f1-11d0-becc-00a0c9054129}" -Name "Permission" -Value "{unauthorized app GUID}"
     ```
   - Observe system alerts and logs for any detection of unauthorized webcam access attempts.

3. **Monitor Detection:**
   - Validate that the alerting mechanism flags the registry change as suspicious activity.
   - Ensure logging captures detailed information about the modification attempt, including timestamps and user accounts involved.

## Response
When an alert fires indicating potential unauthorized video capture:
1. **Immediate Actions:**
   - Isolate the affected system from the network to prevent further data exfiltration.
   - Disable webcam access through device manager or firewall settings.

2. **Investigation:**
   - Review logs for recent changes in registry keys and application permissions.
   - Analyze network traffic for any unusual outbound connections that may indicate video streaming.

3. **Remediation:**
   - Revoke unauthorized permissions by restoring original registry settings.
   - Update security policies to restrict webcam access to pre-approved applications only.

4. **Follow-up:**
   - Conduct a thorough audit of all systems within the network for similar vulnerabilities.
   - Educate users on recognizing and responding to suspicious application requests for hardware access.

## Additional Resources
- None available

This ADS framework provides comprehensive guidelines for detecting adversarial video capture activities, emphasizing rapid response and robust detection capabilities to mitigate privacy risks effectively.