# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## **Goal**
This detection strategy aims to identify adversarial attempts to discover and gather system information across various platforms. This technique is crucial for detecting reconnaissance activities that adversaries use to plan further attacks.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1082 - System Information Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Windows, IaaS, Linux, macOS  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1082)

## **Strategy Abstract**
The detection strategy leverages multiple data sources such as system logs, network traffic analysis, and endpoint monitoring to identify patterns indicative of system information discovery. Key patterns include unexpected command execution, unusual script activity, and reconnaissance tool usage.

## **Technical Context**
Adversaries often execute this technique using native commands or specialized tools to extract detailed system information. Common methods involve querying the operating system for hardware details, running scripts like `wmic` on Windows, or using tools such as `systeminfo` on Linux/macOS. Adversary emulation can replicate these activities through:

- **Sample Commands:**
  - Windows: `systeminfo`, `wmic computersystem get model`
  - Linux/macOS: `uname -a`, `sysctl -a`
  
- **Test Scenarios:**
  - Execution of PowerShell scripts that retrieve machine details.
  - Use of reconnaissance tools like `winpeas` or `itm4nprivesc`.

## **Blind Spots and Assumptions**
- Detection might miss obfuscated command executions or when information is gathered through less common means not covered by the strategy.
- Assumes that all system information discovery attempts are malicious, which may not always be true.

## **False Positives**
Potential benign activities include:
- System administrators performing routine checks.
- Legitimate software installation processes querying system details for compatibility.
  
These can trigger false alerts if similar patterns are detected.

## **Priority**
**Severity:** High

Justification: Detecting system information discovery is critical as it often precedes more destructive phases of an attack. Early detection allows for timely intervention and mitigation.

## **Validation (Adversary Emulation)**
1. **System Information Discovery**
   - Execute `systeminfo` on Windows.
   - Run `uname -a` on Linux/macOS.

2. **List OS Information**
   - Use commands like `ver` to check the OS version.

3. **Linux VM Check via Hardware & Kernel Modules**
   - Examine hardware details with `lscpu`, list kernel modules using `lsmod`.

4. **FreeBSD VM Check via Kernel Modules**
   - List kernel modules using `kldstat`.

5. **Hostname Discovery (Windows)**
   - Use `hostname` on Windows and cross-reference with other systems.

6. **Windows MachineGUID Discovery**
   - Query MachineGUID using PowerShell: `(Get-WmiObject Win32_ComputerSystem).UUID`

7. **Griffon Recon**
   - Execute scripts or tools like Griffon to simulate information gathering.

8. **Environment Variables Discovery**
   - On Windows, use `set` command.
   - On Linux/macOS/FreeBSD, use `printenv`.

9. **Show System Integrity Protection Status (MacOS)**
   - Use `csrutil status` on MacOS.

10. **WinPwn Suite Utilization**
    - Execute various checks like `winPEAS`, `itm4nprivesc`, and others to simulate information gathering.

11. **Azure Security Scan with SkyArk**

12. **ESXi System Information Discovery**
    - Use `esxcli` commands for VM discovery on ESXi hosts.

13. **BIOS Information via Registry (Windows)**
    - Query registry keys related to BIOS details.

14. **Volume Shadow Copies Display (`vssadmin`)**
    - Use `vssadmin list shadows` to reveal shadow copies.

15. **Identify System Locale and Regional Settings with PowerShell**

16. **Enumerate Available Drives via `gdr`**

17. **Discover OS Product Name & Build Number via Registry (Windows)**

## **Response**
When an alert is triggered:
1. Confirm if the activity is legitimate or unauthorized.
2. Isolate the affected systems to prevent further information leakage.
3. Conduct a thorough investigation to determine the scope and intent of the activity.
4. Update detection rules to minimize false positives without compromising on threat detection.

## **Additional Resources**
- Study tools and scripts used in reconnaissance, such as `GatherNetworkInfo.VBS`.
- Monitor for suspicious PowerShell activities and configurations that could indicate system information discovery attempts.
  
By following this comprehensive strategy, organizations can enhance their ability to detect and respond to adversarial system information discovery effectively.