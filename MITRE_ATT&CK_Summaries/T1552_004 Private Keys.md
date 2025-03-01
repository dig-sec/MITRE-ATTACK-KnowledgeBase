# Alerting & Detection Strategy: Private Key Theft via Various Methods

## **Goal**
This detection strategy aims to identify adversarial attempts to exfiltrate private keys from systems, which can be used for malicious purposes such as unauthorized access and data breaches.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1552.004 - Private Keys
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1552/004)

## **Strategy Abstract**
The detection strategy involves monitoring various data sources such as file access logs, process execution records, and network traffic to identify patterns indicative of private key exfiltration. Key indicators include abnormal file read/write operations on directories containing sensitive keys, unusual command-line activities involving tools like `cp`, `rsync`, or `CertUtil`, and unexpected remote connections that may indicate unauthorized data transfer.

## **Technical Context**
Adversaries often target systems to extract private keys by leveraging legitimate system utilities or exploiting vulnerabilities. Common techniques include:

- Using commands such as `cp` or `rsync` on Linux/macOS to copy SSH or GnuPG keys.
- Employing PowerShell cmdlets like `Export-PFXCertificate` for certificate theft in Windows environments.
- Utilizing tools like Mimikatz to export sensitive certificates.

Adversaries may also use command-line reconnaissance and execution methods to locate and move these keys, bypassing security measures by mimicking legitimate administrative tasks.

## **Blind Spots and Assumptions**
- The strategy assumes that key directories are well-defined and monitored; unexpected locations may be overlooked.
- It presumes a baseline of normal behavior is established for detecting anomalies.
- Relies on the assumption that all relevant log sources are available and properly configured.

## **False Positives**
Potential benign activities include:

- Legitimate administrative tasks involving key management or backup operations.
- Routine software updates or migrations that involve copying configuration files, including keys.
- Scheduled scripts running maintenance tasks during off-hours without malicious intent.

## **Priority**
**High**: The unauthorized access and potential misuse of private keys pose significant security risks, potentially leading to data breaches and loss of sensitive information. Early detection is crucial for preventing exploitation.

## **Validation (Adversary Emulation)**
To validate the detection strategy, emulate the following techniques in a controlled environment:

1. **Private Keys:**
   - Simulate copying SSH/GnuPG keys using `cp` or `rsync`.
   - Execute PowerShell commands like `Export-PFXCertificate` to mimic certificate theft.
   - Use Mimikatz for exporting certificates.

2. **Commands and Tools:**
   - Use command-line reconnaissance tools to locate private key files.
   - Simulate PowerShell download and execution cradles to test detection of unauthorized script activity.
   - Employ web request commands to simulate remote data exfiltration attempts.

### Test Scenarios

- On Linux/macOS:
  - Copy SSH keys with `cp` or `rsync`.
  - Enumerate directories using the `dir` command to locate key files.

- On Windows:
  - Use `CertUtil ExportPFX` to export certificates.
  - Execute Mimikatz commands for certificate theft.

## **Response**
When an alert is triggered:

1. Verify the context of the activity, including user identity and task legitimacy.
2. Isolate affected systems if unauthorized access or exfiltration is confirmed.
3. Conduct a thorough investigation to determine the scope and impact.
4. Update security policies and controls based on findings to prevent recurrence.

## **Additional Resources**
For further reading and understanding:

- Explore techniques for private key reconnaissance using command-line tools.
- Review methods of file enumeration via `dir` commands.
- Understand how Mimikatz can be used for credential extraction.
- Investigate PowerShell-based download and execution cradles.
- Analyze the use of web request commands in potential exfiltration scenarios.

This structured approach ensures a comprehensive understanding and effective detection of private key theft attempts within an organization's environment.