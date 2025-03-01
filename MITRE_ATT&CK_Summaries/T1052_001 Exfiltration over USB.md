# Detection Strategy: Detecting USB Exfiltration (MITRE ATT&CK T1052.001)

## Goal
The primary goal of this detection strategy is to identify adversarial attempts to exfiltrate sensitive data via USB devices across multiple operating systems, specifically Linux, macOS, and Windows.

## Categorization

- **MITRE ATT&CK Mapping:** [T1052.001 - Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows

## Strategy Abstract

This strategy focuses on monitoring and analyzing USB-related activities across systems to detect data exfiltration attempts. Key data sources include:

- **Event Logs:** System logs that track device connections/disconnections.
- **Network Traffic:** Monitoring any unusual network activity that might indicate a transfer to external devices.
- **File Access Patterns:** Observing files accessed or transferred shortly before USB connection events.

Patterns analyzed involve sudden spikes in large file transfers coinciding with USB insertion/removal, and monitoring for access to sensitive directories/files prior to these events.

## Technical Context

Adversaries often use USB drives as a simple yet effective method to exfiltrate data due to the ubiquity of USB ports and their general accessibility. Real-world execution involves:

- **Data Copying:** Directly copying files onto a USB device.
- **Automated Scripts:** Using scripts or tools to automate file transfers when a USB is connected.

Example Command:
```bash
cp /sensitive/data/* /media/usb/
```

Test Scenario: 
1. Insert a USB drive into a test system.
2. Use above command to copy sensitive files.
3. Monitor logs and network activity for detection.

## Blind Spots and Assumptions

- **Blind Spots:** Detection might miss encrypted data transfers or when files are split into smaller chunks across multiple devices.
- **Assumptions:** Assumes that any large, unauthorized file transfer via USB is potentially malicious. Does not account for legitimate bulk data backups unless flagged as suspicious.

## False Positives

Potential benign activities include:
- Legitimate use of USB drives by employees for transferring authorized documents or media files.
- Automatic backups to USB devices configured in IT policies.
- System-generated logs from routine device connection/disconnection events (e.g., docking stations).

## Priority
**Severity: High**

Justification: USB exfiltration can lead to significant data breaches, especially when sensitive information is involved. Given its simplicity and the challenge of controlling physical media, it poses a high risk.

## Validation (Adversary Emulation)

Currently, no standardized step-by-step instructions are available for emulating this technique in a test environment. However, analysts should:

1. Set up a controlled environment with multiple OS systems.
2. Insert USB drives containing dummy sensitive data.
3. Execute file transfer commands to simulate exfiltration.
4. Monitor detection tools and validate if the activity is logged as suspicious.

## Response

When an alert for potential USB exfiltration fires, analysts should:

1. Immediately isolate the affected system from the network to prevent further data loss.
2. Review logs to identify the files accessed or transferred.
3. Interview the user associated with the device ID, if applicable.
4. Conduct a forensic analysis of the USB drive and the host machine for any additional evidence.
5. Update detection rules based on findings to improve future accuracy.

## Additional Resources

Currently, there are no specific external resources available beyond general cybersecurity guidelines related to data exfiltration prevention strategies.

---

This report outlines a comprehensive approach to detecting USB-based data exfiltration attempts across multiple platforms, ensuring proactive monitoring and response capabilities within an organization.