# Alerting & Detection Strategy (ADS) Report

## Goal

This strategy aims to detect adversarial attempts to bypass security monitoring by using removable media for communication, specifically focusing on the MITRE ATT&CK technique T1092 - Communication Through Removable Media.

## Categorization

- **MITRE ATT&CK Mapping:** T1092 - Communication Through Removable Media
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows  
[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1092)

## Strategy Abstract

The detection strategy leverages a combination of endpoint security logs, file system monitoring tools, and network traffic analysis to identify patterns indicative of removable media being used for malicious communication. Key data sources include USB event logs from the operating systems, disk I/O activity, and any anomalous network connections initiated by newly accessed files on removable drives.

Patterns analyzed include:
- Unusual USB device connection events
- File transfers between removable media and system storage
- Network activity originating from applications accessing files on removable media

## Technical Context

Adversaries exploit T1092 to exfiltrate data or receive commands by copying malicious payloads onto removable media, which can then be inserted into other systems. This method evades typical network-based detection mechanisms because it uses physical devices as intermediaries.

**Execution in the Real World:**
- Adversaries may use USB drives formatted with encrypted partitions to store and transfer sensitive information.
- They might employ software that automatically syncs specific directories from a system to a removable drive.

**Adversary Emulation Details:**
- Commands like `mount` on Linux/macOS or `subst`/`diskpart` on Windows can be used to connect removable media as network drives, facilitating file transfers that appear benign.
- Test scenarios include using scripts to automate the copying of files between a machine and a USB drive.

## Blind Spots and Assumptions

- Assumes that all removable media are connected through standard interfaces detectable by system logs.
- May not detect encrypted or obfuscated data on removable devices without prior signature-based detection mechanisms.
- Relies on accurate logging of USB device events, which can be disabled by sophisticated adversaries.

## False Positives

Potential benign activities include:
- Users transferring personal files to USB drives for backup purposes.
- Standard use of external drives for media storage (e.g., photos, music).
- Automated software updates or backups that utilize removable media.

## Priority

**Severity: Medium**

Justification: While using removable media is a less common vector compared to network-based attacks, it poses significant risks due to its ability to bypass network security controls. The potential impact includes data exfiltration and command-and-control activities without detection through traditional network monitoring.

## Validation (Adversary Emulation)

None available

## Response

When the alert fires:
1. **Verify the Alert:** Confirm that a removable media device was accessed during suspicious activity.
2. **Review Logs:** Examine USB event logs, file transfer histories, and any associated network connections.
3. **Isolate the Affected System:** Temporarily disconnect the system from the network to prevent further unauthorized data exchange.
4. **Conduct Forensic Analysis:** Investigate files transferred to/from the removable media for signs of malicious content.
5. **Update Security Policies:** Implement stricter controls on removable media usage, such as disabling auto-run features and restricting USB ports where feasible.

## Additional Resources

None available

---

This report outlines a comprehensive strategy for detecting and responding to threats involving communication through removable media, providing guidance on identifying suspicious activities while acknowledging potential limitations and false positive scenarios.