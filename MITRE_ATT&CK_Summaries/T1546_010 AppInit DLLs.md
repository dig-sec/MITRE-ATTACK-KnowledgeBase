# Alerting & Detection Strategy (ADS) Report

## Goal
The goal of this detection technique is to identify adversarial attempts to bypass security monitoring mechanisms using AppInit DLLs on Windows systems. This involves detecting unauthorized changes to the `AppInit_DLLs` registry key and subsequent execution of malicious DLLs that can establish persistence or escalate privileges.

## Categorization

- **MITRE ATT&CK Mapping:** T1546.010 - AppInit DLLs
- **Tactic / Kill Chain Phases:**
  - Privilege Escalation
  - Persistence
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1546/010)

## Strategy Abstract

This detection strategy focuses on monitoring the `AppInit_DLLs` registry key for unauthorized modifications and tracking execution events related to DLLs loaded via this mechanism. Data sources include:

- **Windows Event Logs:** Specifically, logs related to registry changes (Event ID 4616) and process creation (Event IDs 4688).
- **Sysmon:** For enhanced monitoring of system-wide activities including file creation, process creation, and network connections.

Patterns analyzed involve:

- Unauthorized or unexpected modifications to the `AppInit_DLLs` registry key.
- Execution of DLLs that are not part of known software installations or updates.

## Technical Context

Adversaries use AppInit DLLs by adding malicious DLL paths to the `AppInit_DLLs` registry value. When an application using the Winlogon process starts, these DLLs are loaded into its context, potentially executing arbitrary code with elevated privileges.

### Execution in Real World
- **Initial Access:** Adversaries gain initial access and elevate their privilege level.
- **Tactics:** Modify the `AppInit_DLLs` registry key to include a malicious DLL path.
- **Execution:** Malicious DLLs are executed whenever applications using the Winlogon process start, often leading to persistence or privilege escalation.

### Adversary Emulation Details
To emulate this technique:
1. Gain administrative access to a Windows machine.
2. Modify `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` or `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AppInit_DLLs`.
3. Add the path of a benign test DLL.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection may not cover scenarios where AppInit DLL modifications are made in memory, avoiding registry changes.
  - Limited visibility if Sysmon is not configured to monitor all relevant events.
  
- **Assumptions:**
  - Assumes that legitimate applications do not frequently modify the `AppInit_DLLs` key without proper justification.

## False Positives

Potential benign activities include:
- Legitimate software installations or updates that modify the `AppInit_DLLs`.
- System maintenance tasks where the AppInit DLLs are updated as part of a routine update process.

## Priority
**High**

Justification: The technique allows adversaries to execute code with elevated privileges and establish persistence, making it critical to detect these activities promptly to prevent further compromise.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Setup Test Environment:** Ensure you have a controlled Windows environment where changes can be safely made.
2. **Install Sysmon:**
   - Download and install Sysmon with necessary configuration to monitor registry changes and process creation.
3. **Modify `AppInit_DLLs`:**
   - Open Registry Editor (`regedit.exe`).
   - Navigate to `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows` or `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.
   - Add a new string value named `AppInit_DLLs` and set it to the path of a benign DLL.
4. **Monitor Events:**
   - Use Sysmon to track registry modifications (Event ID 13) and process creation events (Event ID 1).
5. **Analyze Results:** Ensure that the alerts correspond to changes made in step 3.

## Response

When an alert fires:
- **Immediate Actions:**
  - Isolate the affected system from the network.
  - Perform a detailed investigation of the registry modifications and process execution related to AppInit DLLs.
  
- **Further Steps:**
  - Review logs for additional indicators of compromise (IOCs).
  - Engage incident response protocols if malicious activity is confirmed.

## Additional Resources

- [MITRE ATT&CK Technique T1546.010](https://attack.mitre.org/techniques/T1546/010)
  
This report aims to provide a comprehensive framework for detecting adversarial use of AppInit DLLs, emphasizing the importance of monitoring and responding to these activities in Windows environments.