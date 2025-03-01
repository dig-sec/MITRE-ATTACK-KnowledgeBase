# Alerting & Detection Strategy (ADS) Report: System Shutdown/Reboot

## Goal
The objective of this detection strategy is to identify adversarial attempts to execute system shutdowns and reboots across multiple platforms. This includes detecting unauthorized commands intended to disrupt operations by forcing systems offline or rebooting them without legitimate authorization.

## Categorization
- **MITRE ATT&CK Mapping:** T1529 - System Shutdown/Reboot
- **Tactic / Kill Chain Phases:** Impact
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1529)

## Strategy Abstract
The detection strategy leverages various data sources to monitor system shutdown and reboot activities. These include:

- **Syslog / Event Logs**: Collects logs from system event channels that document shutdown, restart, or logoff events.
- **Process Monitoring**: Tracks execution of commands related to shutdown operations such as `shutdown`, `reboot`, `halt`, `poweroff`, and specific vendor commands like `vim-cmd`.
- **Network Traffic Analysis**: Monitors for remote command executions indicative of unauthorized access.

The strategy analyzes patterns indicative of malicious intent, such as:
- Unusual timing or frequency of shutdown events.
- Commands executed by non-administrative users without proper authorization.
- Anomalies in network traffic suggesting remote commands from suspicious sources.

## Technical Context
Adversaries may attempt to execute system shutdowns and reboots through various vectors:

1. **Local Execution**: Using legitimate administrative tools like `shutdown` or `reboot` on Linux/macOS systems, `shutdown.exe` or `Restart-Computer` cmdlets in Windows.
2. **Remote Access Tools (RATs)**: Executing commands remotely to disrupt services.
3. **Exploited Vulnerabilities**: Leveraging vulnerabilities to gain elevated privileges and perform shutdown operations.

### Adversary Emulation Details
Adversaries might use the following commands:
- Windows: `shutdown /r`, `shutdown /s`
- Linux/macOS: `sudo reboot`, `sudo shutdown -h now`
- ESXi: `vim-cmd vmsvc/power.off <VMID>`

## Blind Spots and Assumptions
- **Assumption**: Administrative users typically perform legitimate shutdown/restart operations. Unusual patterns in these activities are flagged.
- **Blind Spot**: Legitimate automated maintenance scripts that cause system reboots may not be accounted for, leading to potential false positives.

## False Positives
Potential benign activities include:
- Scheduled maintenance tasks initiating restarts or shutdowns.
- Administrators performing routine system reboots during off-hours.
- Automated backup systems temporarily shutting down services.

## Priority
**Severity: High**
This technique is prioritized highly due to its potential impact on operational continuity and availability. Unauthorized shutdowns can lead to significant service disruptions, data loss, and extended downtime.

## Validation (Adversary Emulation)
### Instructions to Emulate Technique in a Test Environment

#### Windows
1. **Shutdown System**:
   ```cmd
   shutdown /s /t 0
   ```
2. **Restart System**:
   ```cmd
   shutdown /r /t 0
   ```

#### FreeBSD/macOS/Linux
3. **Restart System via `shutdown`**:
   ```bash
   sudo shutdown -r now
   ```
4. **Shutdown System via `shutdown`**:
   ```bash
   sudo shutdown -h now
   ```
5. **Restart System via `reboot`**:
   ```bash
   sudo reboot
   ```

#### FreeBSD/Linux
6. **Shutdown System via `halt`**:
   ```bash
   sudo halt
   ```
7. **Reboot System via `halt`** (FreeBSD):
   ```bash
   sudo halt -r
   ```
8. **Reboot System via `halt`** (Linux):
   ```bash
   sudo telinit 6 # Equivalent to reboot
   ```

#### FreeBSD/Linux
9. **Shutdown System via `poweroff`**:
   ```bash
   sudo poweroff
   ```
10. **Reboot System via `poweroff`** (FreeBSD):
    ```bash
    sudo shutdown -r now
    ```
11. **Reboot System via `poweroff`** (Linux):
    ```bash
    sudo telinit 6 # Equivalent to reboot
    ```

#### Windows
12. **Logoff System**:
    ```cmd
    shutdown /l
    ```

#### ESXi
13. **Terminates VMs using pkill**:
    ```bash
    pkill -f <VM process name>
    ```
14. **Avoslocker enumerates VMs and forcefully kills VMs**:
    Emulate with targeted termination scripts.
15. **vim-cmd Used to Power Off VMs**:
    ```bash
    vim-cmd vmsvc/power.off <VMID>
    ```

## Response
Upon alert activation, analysts should:

1. Verify the legitimacy of the shutdown/reboot event by consulting with system administrators.
2. Investigate any unauthorized access or anomalous network traffic that may have triggered the action.
3. Assess the scope and impact on affected systems and services.
4. Initiate incident response procedures if malicious activity is confirmed.

## Additional Resources
For further context, consider exploring:
- **Tunneling Tool Execution**: Understanding how adversaries use tunneling tools to execute remote commands can provide additional insights into shutdown/reboot techniques.
  
By integrating these detection methods into your security operations framework, organizations can better defend against adversarial actions that seek to disrupt system availability.