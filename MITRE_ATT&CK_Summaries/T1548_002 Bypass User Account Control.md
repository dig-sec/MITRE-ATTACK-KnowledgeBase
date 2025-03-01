# Alerting & Detection Strategy: Bypass User Account Control (UAC)

## **Goal**

This strategy aims to detect adversarial attempts to bypass Security Monitoring systems using techniques that exploit vulnerabilities in User Account Control (UAC) mechanisms on Windows platforms.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1548.002 - Bypass User Account Control
- **Tactic / Kill Chain Phases:** Privilege Escalation, Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1548/002)

## **Strategy Abstract**

The detection strategy leverages multiple data sources including system event logs, registry modifications, process execution patterns, and network traffic to identify anomalous behaviors indicative of UAC bypass attempts. Patterns analyzed include:

- Sudden changes in the `ConsentPromptBehaviorAdmin` registry key.
- Use of specific command-line tools (`Event Viewer`, `Fodhelper`) that are commonly exploited for UAC bypass.
- Unusual PowerShell script execution patterns, particularly those involving web downloads or utilizing specific cmdlets to alter system states.

## **Technical Context**

Adversaries often attempt to gain higher privileges by circumventing Windows User Account Control (UAC) using various techniques:

1. **Exploiting Trusted Applications:** Using built-in tools like `Event Viewer` and `Fodhelper` which are trusted by the system.
2. **Registry Manipulation:** Altering registry keys such as `ConsentPromptBehaviorAdmin` to suppress UAC prompts or change its behavior.
3. **Scheduled Tasks Exploitation:** Leveraging tasks like `SilentCleanup` to execute commands without UAC intervention.
4. **Command-Line Techniques:** Using tools and scripts that can bypass UAC, often through exploiting specific system vulnerabilities or using known command sequences.

**Adversary Emulation Details:**
- Commands such as running `eventvwr.exe /s` for Event Viewer or utilizing PowerShell scripts to modify the registry key settings.
- Testing environments should simulate these actions without causing harm, focusing on observing log outputs and changes in system behavior.

## **Blind Spots and Assumptions**

- Some legitimate administrative tasks may mimic UAC bypass patterns (e.g., authorized software updates).
- Assumes adversaries are using known techniques; novel methods might go undetected.
- Detection assumes access to comprehensive event logs, which might not be available in all environments.

## **False Positives**

Potential benign activities include:

- Legitimate use of tools like `Event Viewer` for system maintenance or troubleshooting.
- Authorized administrative scripts that modify UAC settings temporarily as part of a controlled update process.
- Scheduled tasks like Windows Disk Cleanup running with elevated privileges without malicious intent.

## **Priority**

**Severity: High**

Justification: Bypassing UAC can lead to privilege escalation, allowing adversaries to perform unauthorized actions and evade detection. This technique poses a significant threat by undermining fundamental security controls designed to protect the system integrity and confidentiality of sensitive data.

## **Validation (Adversary Emulation)**

To emulate UAC bypass techniques in a controlled test environment:

1. **Bypass UAC using Event Viewer:**
   - Execute `eventvwr.exe /s` from the command prompt.
   
2. **Bypass UAC using PowerShell:**
   ```powershell
   Start-Process powershell -Verb runAs -ArgumentList "Get-UacEvent"
   ```

3. **Bypass UAC using Fodhelper:**
   - Run `C:\Windows\System32\fodhelper.exe`.

4. **Bypass UAC using PowerShell and Fodhelper:**
   ```powershell
   Start-Process C:\Windows\System32\fodhelper.exe -Verb runAs
   ```

5. **Bypass UAC using ComputerDefaults (PowerShell):**
   ```powershell
   New-ItemProperty "HKCU:\SOFTWARE\Classes\AppID\{D27CDB6E-AE6D-11CF-96B8-444553540000}\InprocServer32" -Name ThreadingModel -Value apartment -PropertyType String -Force
   ```

6. **Mock Trusted Directories for UAC Bypass:**
   - Create a directory in the `Program Files` folder and execute files from there.

7. **Bypass UAC using sdclt DelegateExecute:**
   ```powershell
   Start-Process "C:\Windows\System32\sdclocal.dll" -Verb runAs
   ```

8. **Disable UAC via reg.exe:**
   ```cmd
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
   ```

9. **Bypass UAC using SilentCleanup Task:**
   - Schedule a task with elevated privileges that performs actions without prompting for consent.

10. **UACME Bypass Method Testing (e.g., Method 23, 31):**
    - Follow specific instructions from the UACME tool repository to test different bypass techniques.

11. **WinPwn Techniques:**
    - Use WinPwn scripts and methods like `UAC Magic`, `ccmstp` technique, etc., in a safe environment for testing purposes.

## **Response**

When an alert indicating a potential UAC bypass is triggered:

1. **Immediate Verification:** Confirm the legitimacy of the activity through logs, network traffic analysis, and user reports.
2. **Containment:** If malicious intent is confirmed, isolate affected systems to prevent lateral movement.
3. **Remediation:** Revert any unauthorized changes made by adversaries (e.g., restore registry keys).
4. **Notification:** Inform relevant stakeholders including IT security teams and possibly affected departments.
5. **Review and Enhance Controls:** Analyze the breach vector for future prevention, ensuring security policies and monitoring strategies are updated accordingly.

## **Additional Resources**

- PowerShell Download and Execution Cradles
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Suspicious PowerShell Download and Execute Pattern
- PowerShell Web Download
- PowerShell Download Pattern
- Usage Of Web Request Commands And Cmdlets
- Suspicious Copy From or To System Directory
- Suspicious Reg Add Open Command

These resources provide further context on related behaviors and detection techniques that complement the detection strategy for UAC bypass attempts.