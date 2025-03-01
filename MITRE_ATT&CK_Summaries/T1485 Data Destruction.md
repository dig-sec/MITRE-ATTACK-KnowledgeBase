# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this detection strategy is to detect adversarial attempts to bypass security monitoring by using methods such as file overwrites on various platforms, including Windows, IaaS, Linux, and macOS.

## Categorization
- **MITRE ATT&CK Mapping:** T1485 - Data Destruction
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Windows, IaaS, Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1485)

## Strategy Abstract
The detection strategy leverages multiple data sources including file system monitoring, event logs, and network traffic analysis to identify patterns indicative of file overwriting activities. The focus is on detecting tools like SysInternals SDelete on Windows and the `dd` command on Unix-based systems (FreeBSD, macOS, Linux) as well as suspicious behavior related to deletion and overwrite operations in cloud environments such as GCP bucket deletions and ESXi VM snapshot removals.

## Technical Context
Adversaries often use file overwriting techniques to hide their tracks or corrupt data intentionally. This is done by using tools like SysInternals SDelete on Windows, which can securely delete files, making them unrecoverable. On Unix-based systems, the `dd` command can be used for similar purposes. In cloud environments, adversaries might delete critical snapshots or buckets as part of their attack strategy.

### Adversary Emulation Details
- **Windows:** Use SysInternals SDelete to overwrite and securely delete a file.
  ```shell
  sdelete -z <file_path>
  ```
- **FreeBSD/macOS/Linux:** Overwrite files using the `dd` command.
  ```shell
  dd if=/dev/urandom of=<file_path> bs=1M count=10
  ```

## Blind Spots and Assumptions
- Detection may miss file overwrites executed in highly obfuscated manners or on encrypted volumes where typical monitoring tools have limited visibility.
- Assumes the presence of appropriate logging mechanisms to capture overwrite activities.

## False Positives
Potential benign activities that might trigger false alerts include:
- System administrators performing routine secure deletion tasks.
- Automated scripts designed for data sanitization purposes.
- Legitimate use of disk wiping utilities during system maintenance or decommissioning.

## Priority
**High:** The technique poses a significant risk as it directly impacts data integrity and availability, potentially leading to data loss or corruption that is difficult to recover from. Its ability to evade detection makes it crucial to identify such activities promptly.

## Validation (Adversary Emulation)
### Windows
1. Install SysInternals Suite.
2. Use SDelete to overwrite a file:
   ```shell
   sdelete -z C:\path\to\file.txt
   ```

### FreeBSD/macOS/Linux
1. Open terminal.
2. Execute the `dd` command to overwrite a file:
   ```shell
   dd if=/dev/urandom of=/path/to/file bs=1M count=10
   ```

### Overwrite Deleted Data on C Drive (Windows)
1. Use SDelete to target deleted files:
   ```shell
   sdelete -z C:\
   ```

### GCP - Delete Bucket
1. Authenticate with Google Cloud.
2. Execute bucket deletion:
   ```shell
   gsutil rb -r gs://bucket-name
   ```

### ESXi - Delete VM Snapshots
1. Log into the vSphere Client.
2. Select the VM, navigate to its snapshots section, and delete all snapshots.

## Response
When an alert is triggered, analysts should:
- Immediately isolate affected systems to prevent further data loss or corruption.
- Investigate logs for unauthorized access or suspicious activities leading up to the overwrite event.
- Review recent system changes and user actions that might have contributed to the incident.
- Restore from backups if possible and necessary.

## Additional Resources
- [Sysinternals SDelete](https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete)
- [DD File Overwrite](https://en.wikipedia.org/wiki/Dd_(Unix))
- [GCP Bucket Management](https://cloud.google.com/storage/docs/objects#management)
- [ESXi Snapshot Documentation](https://www.vmware.com/support/pubs/vimapi/VI-API-Reference-docs.pdf)

This report provides a comprehensive framework for detecting and responding to file overwrite techniques used by adversaries, with a focus on maintaining data integrity across diverse platforms.