# Detection Strategy: Disk Structure Wipe (T1561.002)

## Goal

The aim of this technique is to detect adversarial attempts to compromise data integrity by wiping disk structures on target systems. This activity can be part of a larger objective to disrupt operations, cause damage, or cover tracks.

## Categorization

- **MITRE ATT&CK Mapping:** T1561.002 - Disk Structure Wipe
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1561/002)

## Strategy Abstract

This detection strategy leverages log and event data from a variety of sources to identify patterns indicative of disk structure wiping activities. Key data sources include:

- **File Integrity Monitoring (FIM):** To detect changes in critical system files or configurations.
- **System Logs:** For signs of unauthorized modifications or abnormal commands that target disk operations.
- **Network Traffic Analysis:** To catch any command-and-control communications or data exfiltration attempts post-wipe.

Patterns analyzed include:

- Unusual file deletion or modification patterns.
- Commands associated with wiping operations, such as `dd`, `shred`, or custom scripts designed for data destruction.
- Network anomalies coinciding with disk activity indicative of a wipe event.

## Technical Context

In the real world, adversaries may execute this technique by deploying malware that targets and destroys disk structures. Common tools used include:

- **Linux:** Utilities like `dd` to overwrite sectors, `shred` for secure file deletion.
- **macOS & Windows:** Similar utilities or scripts designed to perform mass file deletions and system alterations.

Adversaries often use these techniques in scenarios where they aim to destroy evidence or cripple a target’s operational capabilities. For instance, in ransomware attacks, wiping data is used as a last resort when encryption fails.

### Adversary Emulation Details

To emulate this technique:

- **Linux:** Use `dd if=/dev/zero of=/dev/sda` to wipe a disk.
- **Windows:** Deploy scripts using PowerShell commands like `Get-ChildItem -Recurse | Remove-Item`.

Test scenarios should be conducted in isolated environments where the impact can be controlled and monitored.

## Blind Spots and Assumptions

### Known Limitations:

- Detection may not capture all wiping methods, especially custom or obfuscated ones.
- Reliance on logs assumes they are properly configured and retained.
- Some legitimate maintenance activities might mimic wipe patterns (e.g., disk formatting).

### Assumptions:

- The environment has sufficient logging capabilities.
- Analysts have the ability to correlate events across multiple data sources.

## False Positives

Potential benign activities that could trigger false alerts include:

- Legitimate disk defragmentation or cleanup operations.
- Scheduled maintenance tasks like backups, which may involve overwriting or deleting temporary files.
- User actions resulting in mass file deletion during system reconfiguration or upgrades.

## Priority

**Priority: High**

Justification: Disk structure wipes can lead to significant data loss and operational disruption. Given the potential impact on an organization’s ability to function and recover from such incidents, early detection is crucial.

## Response

When an alert indicating a disk structure wipe fires:

1. **Immediate Containment:** Isolate affected systems from the network to prevent further spread.
2. **Incident Analysis:** Conduct a thorough investigation using logs and forensic tools to understand the scope of impact.
3. **Communication:** Notify relevant stakeholders, including IT security teams and management, about the incident.
4. **Recovery Planning:** Initiate data recovery procedures if backups are available; otherwise, assess alternative recovery options.

## Additional Resources

No additional resources currently available for this specific technique beyond standard forensic tools and logs analysis methods.

This strategy provides a structured approach to detect and respond to disk structure wipes, ensuring organizations can maintain resilience against such adversarial tactics.