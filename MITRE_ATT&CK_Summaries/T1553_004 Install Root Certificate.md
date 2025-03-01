# Alerting & Detection Strategy: Detect Adversarial Attempts to Install Root Certificates

## Goal
This detection strategy aims to identify adversarial attempts to install root certificates across various operating systems (Linux, macOS, Windows) as a means of evading security monitoring and intercepting secure communications.

## Categorization
- **MITRE ATT&CK Mapping:** T1553.004 - Install Root Certificate
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1553/004)

## Strategy Abstract
The detection strategy leverages monitoring of system-level events and security logs to identify unauthorized installation of root certificates. It focuses on detecting changes in trusted certificate authorities across multiple platforms by analyzing patterns such as unusual command executions, modifications to the certificate store, or unexpected network requests for downloading certificate files.

### Data Sources:
- Windows Event Logs (Event ID 3688)
- Audit logs from Linux systems (/var/log/audit.log or similar)
- macOS System Logs (for certificate modifications)
- Network traffic analysis tools

## Technical Context
Adversaries install root certificates to intercept and manipulate secure communications. They often use legitimate administrative privileges or exploit vulnerabilities to perform these installations, allowing them to bypass SSL/TLS monitoring by masquerading as trusted entities.

### Adversary Emulation Details:
1. **Sample Commands:**
   - On Linux: `sudo update-ca-certificates`
   - On macOS: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <path-to-certificate>`
   - On Windows: Using PowerShell or certutil to import certificates.

2. **Test Scenarios:**
   - Emulate an adversary installing a root certificate using administrative tools.
   - Monitor the changes in trusted certificate lists and correlate with suspicious network activity.

## Blind Spots and Assumptions
- Detection may miss installations that occur during system startup scripts or via automated deployment tools.
- Assumes proper configuration of security logs and monitoring systems across platforms.
- May not detect highly sophisticated techniques using kernel-level exploits to install certificates without leaving traces in standard logs.

## False Positives
- Legitimate administrative tasks such as updating trusted root certificates for business purposes.
- Network operations involving certificate management, like automated updates from legitimate software vendors.
- Misconfigured systems where trusted certificates are added during initial setup or by non-malicious third-party applications.

## Priority
**High:** Installing a root certificate can significantly undermine the security posture of an organization by enabling adversaries to intercept and manipulate secure communications undetected. The potential impact justifies prioritizing this detection strategy.

## Validation (Adversary Emulation)
### Install Root CA on CentOS/RHEL:
1. Obtain the root certificate file.
2. Copy it to `/etc/pki/ca-trust/source/anchors/`.
3. Run `sudo update-ca-trust`.

### Install Root CA on FreeBSD:
1. Place the certificate in `/usr/local/etc/ssl/certs/`.
2. Execute `certctl -d trust add <certificate-file>`.

### Install Root CA on Debian/Ubuntu:
1. Copy the root certificate to `/usr/local/share/ca-certificates/`.
2. Run `sudo update-ca-certificates`.

### Install Root CA on macOS:
1. Use the command:  
   ```bash
   security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <path-to-certificate>
   ```

### Install Root CA on Windows:
1. Open PowerShell as Administrator.
2. Execute:  
   ```powershell
   Import-Certificate -FilePath "<certificate-path>" -CertStoreLocation Cert:\LocalMachine\Root
   ```

### Install Root CA on Windows with certutil:
1. Use the command:  
   ```cmd
   certutil -addstore "Root" <certificate-file>
   ```

### Add Root Certificate to CurrentUser Certificate Store:
- On all platforms, use platform-specific commands or GUI tools to add certificates to user-level trusted stores and monitor for changes.

## Response
When an alert is triggered indicating the installation of a root certificate:
1. **Verify Authenticity:** Confirm whether the installation was authorized by checking with relevant IT personnel.
2. **Analyze Context:** Review logs around the time of installation, including network traffic and command history.
3. **Containment:** Isolate affected systems to prevent further exploitation.
4. **Remediation:** Remove unauthorized root certificates from trusted stores across all platforms.
5. **Incident Report:** Document findings and actions taken for future reference.

## Additional Resources
- [PowerShell Download and Execution Cradles](https://attack.mitre.org/techniques/T1086/)
- [Usage Of Web Request Commands And Cmdlets](https://attack.mitre.org/techniques/T1048/)
- [PowerShell Web Download](https://attack.mitre.org/techniques/T1105/) 

This strategy provides a structured approach to detecting and responding to attempts by adversaries to install root certificates, enhancing the organization's ability to maintain secure communications.