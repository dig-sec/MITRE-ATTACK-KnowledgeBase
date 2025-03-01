# Alerting & Detection Strategy: Pass the Hash (T1550.002)

## Goal
This detection strategy aims to identify adversarial attempts to bypass security monitoring systems by exploiting credential misuse via the "Pass the Hash" technique on Windows platforms.

## Categorization

- **MITRE ATT&CK Mapping:** T1550.002 - Pass the Hash
- **Tactic / Kill Chain Phases:** Defense Evasion, Lateral Movement
- **Platforms:** Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1550/002)

## Strategy Abstract

The detection strategy focuses on monitoring and analyzing various data sources within the Windows environment to detect "Pass the Hash" activities. The primary data sources include:

- **Event Logs:** Particularly those related to authentication (such as Event ID 4624) to track successful logins with hashed credentials.
- **Network Traffic:** Monitoring for unusual or unauthorized remote procedure calls (RPCs), which may indicate credential misuse.
- **Process Activity:** Detecting suspicious process creation that is associated with known tools used in "Pass the Hash" attacks, like Mimikatz and Invoke-WMIExec.

Patterns analyzed include anomalous login attempts from unexpected sources, repeated authentication failures followed by success without password change, and unusual network activity involving known ports for lateral movement.

## Technical Context

Adversaries execute the "Pass the Hash" technique to authenticate with a remote system using only the hash of an account’s NTLM credentials, bypassing the need for passwords. This is often done after obtaining credential hashes through tools like Mimikatz or exploiting vulnerabilities that leak hashed credentials.

### Adversary Emulation Details

**Sample Commands:**

- **Mimikatz:** 
  ```shell
  mimikatz.exe "sekurlsa::logonpasswords"
  ```
  
- **crackmapexec Pass the Hash:**
  ```shell
  crackmapexec smb <target_ip> -u 'username' -H <hash>
  ```

- **Invoke-WMIExec:**
  ```powershell
  Invoke-WMIExec -ComputerName <target_ip> -Credential (New-Object System.Management.Automation.PSCredential ('username', (ConvertTo-SecureString -String '<NTLM_HASH>' -AsPlainText -Force)))
  ```

### Test Scenarios

1. **Emulate Local Exploitation:** Use Mimikatz to extract hashed credentials from a compromised machine.
2. **Simulate Remote Access:** Attempt to use extracted hashes to access other systems within the network using tools like crackmapexec or Invoke-WMIExec.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection may not cover all potential tools used for "Pass the Hash" that aren't widely recognized.
  - Encrypted communication channels can obscure credential exchange, hindering detection.

- **Assumptions:**
  - The environment logs necessary events in sufficient detail.
  - Security controls are sufficiently granular to identify unauthorized access attempts effectively.

## False Positives

Potential benign activities that might trigger false alerts include:

- Legitimate remote administration tools executing actions with elevated privileges within the network.
- Scheduled tasks or services using hashed credentials for operations, which may be misinterpreted as malicious activity if context is not properly analyzed.

## Priority
**Priority: High**

Justification: The "Pass the Hash" technique allows adversaries to evade password protection mechanisms entirely, facilitating lateral movement and further exploitation. Its ability to bypass traditional authentication controls poses a significant threat to network security.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Set Up Test Environment:** Prepare isolated Windows machines with monitoring tools in place.
2. **Extract Hashes:**
   - Run Mimikatz on the target machine:
     ```shell
     mimikatz.exe "sekurlsa::logonpasswords"
     ```
3. **Simulate Remote Access:**
   - Use crackmapexec to attempt access from another machine:
     ```shell
     crackmapexec smb <target_ip> -u 'username' -H <hash>
     ```
   - Alternatively, use Invoke-WMIExec for similar results.
4. **Monitor and Analyze:**
   - Track logs for unusual login attempts (Event ID 4624).
   - Observe network traffic for unexpected RPCs or lateral movements.

## Response

When the alert fires:

1. **Immediate Isolation:** Quarantine affected systems to prevent further unauthorized access.
2. **Investigate Logs:** Examine event logs, process activity, and network traffic for signs of "Pass the Hash" usage.
3. **Credential Reset:** Change passwords and rehash credentials where applicable.
4. **Incident Documentation:** Record findings and response actions for future reference.

## Additional Resources

- [Mimikatz Execution](https://github.com/gentilkiwi/mimikittenz)
- [Pass the Hash Overview](https://attack.mitre.org/techniques/T1550/002)

This detailed report outlines a comprehensive approach to detecting and responding to "Pass the Hash" activities, aligning with Palantir's ADS framework.