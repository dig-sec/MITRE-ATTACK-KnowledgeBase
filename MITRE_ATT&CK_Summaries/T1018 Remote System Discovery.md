# Palantir's Alerting & Detection Strategy (ADS) Report

## Goal
This strategy aims to detect adversarial attempts at discovering remote systems within a network. The focus is on identifying techniques and tools used by adversaries to map out the environment, which could precede more targeted attacks.

## Categorization
- **MITRE ATT&CK Mapping:** T1018 - Remote System Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1018)

## Strategy Abstract
The detection strategy leverages multiple data sources, including network traffic logs, system event logs, and command execution records. By analyzing patterns such as unusual network scanning activity, unexpected use of specific reconnaissance tools (e.g., `net`, `nltest`), and anomalous system commands, the strategy aims to flag potential remote system discovery attempts.

## Technical Context
Adversaries often execute Remote System Discovery to gather information about active systems within a target network. They might employ various techniques such as:
- **Net Commands:** Using `net view` or similar commands to enumerate resources.
- **Ping Sweeps and ARP Scans:** To identify live hosts on the network.
- **Domain Queries:** Utilizing tools like `nltest` or `adfind` to query Active Directory for domain information.

Adversary emulation can involve executing these commands in a controlled environment to understand their signatures and behaviors.

## Blind Spots and Assumptions
- Assumes that legitimate administrative activity is well-understood and baseline behaviors are established.
- May not detect highly obfuscated or custom-developed reconnaissance tools.
- Relies on accurate logging of system and network activities, which might be bypassed by sophisticated adversaries.

## False Positives
Potential benign activities include:
- Legitimate network administrators performing routine scans for maintenance.
- Automated backup processes that include host discovery as part of their operation.
- Software updates or patches requiring enumeration of systems for deployment checks.

## Priority
**High:** The ability to detect Remote System Discovery is crucial as it often precedes more harmful actions. Early detection allows organizations to respond before adversaries can exploit discovered systems.

## Validation (Adversary Emulation)
To emulate this technique in a test environment, follow these steps:

1. **Net Commands:**
   - Execute `net view` to list network resources.
   - Use `net group Domain Computers /domain` to enumerate domain computers.

2. **Ping Sweeps and ARP Scans:**
   - Perform a ping sweep using `ping <IP range>`.
   - Conduct an ARP scan with `arp -a`.

3. **Domain Queries:**
   - Execute `nltest /dsgetdc:<domain>` to retrieve domain controllers.
   - Use `adfind computer -f` to find Active Directory computers.

4. **Additional Tools and Commands:**
   - Run `nslookup <hostname>.<domain>` for DNS lookups.
   - Use `ip neigh show` (Linux) or `arp /a` (Windows) for ARP table inspection.
   - Execute `netstat -an` to view active connections.

5. **Active Directory Enumeration:**
   - Utilize PowerShell with `Get-AdComputer -Filter *` to list computers.
   - Employ `ADSISearcher` for directory searches.
   - Use `Get-DomainController` from PowerView for domain controller discovery.

## Response
When an alert is triggered:
1. **Immediate Analysis:** Verify the source and context of the detected activity.
2. **Containment:** Isolate affected systems to prevent further reconnaissance.
3. **Investigation:** Determine if the activity is part of a broader attack campaign.
4. **Remediation:** Update detection rules based on findings to reduce false positives.

## Additional Resources
- [Net.EXE Execution](https://example.com/netexe)
- [Suspicious Group And Account Reconnaissance Activity Using Net.EXE](https://example.com/suspicious-net)
- [PUA - AdFind Suspicious Execution](https://example.com/adfind-pua)
- [Potential Recon Activity Via Nltest.EXE](https://example.com/nltest-recon)
- [Nltest.EXE Execution](https://example.com/nltest-execution)
- [Share And Session Enumeration Using Net.EXE](https://example.com/share-session-net)
- [Use Short Name Path in Command Line](https://example.com/short-name-path)
- [Suspicious Scan Loop Network](https://example.com/suspicious-scan-loop)

This report provides a comprehensive framework for detecting and responding to Remote System Discovery activities, aligning with Palantir's ADS approach.