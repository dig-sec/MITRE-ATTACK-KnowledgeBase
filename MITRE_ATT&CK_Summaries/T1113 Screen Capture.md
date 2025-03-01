# Palantir's Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## **Goal**
The primary goal of this strategy is to detect adversarial attempts to bypass security monitoring using container technologies, with a specific focus on screen capture activities.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1113 - Screen Capture
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Linux, macOS, Windows

For more information about this technique, see the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1113).

## **Strategy Abstract**

The detection strategy aims to identify and alert on screen capture activities across various platforms (Linux, macOS, Windows) that might indicate adversarial actions. The key data sources for this strategy include system logs, process monitoring outputs, and registry changes. Patterns analyzed involve unusual executions of screen capturing tools or scripts that are typically associated with malicious activity.

## **Technical Context**

Adversaries often execute screen capture to gather sensitive information from compromised systems without detection. This can be achieved through various methods:

- On Windows, adversaries might use built-in utilities like `Snipping Tool`, PowerShell commands such as `CopyFromScreen`, or third-party tools.
- On Linux and macOS, attackers may leverage command-line tools (`import` for screenshots) or scripts to capture the screen.

Adversary emulation involves simulating these activities in a controlled environment using specific commands:

- **Windows:** Use of `SnippingTool.exe`, PowerShell cmdlets like `Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::GetImage().Save('screenshot.png', 'image/png')`.
- **Linux/macOS:** Execution of `import /tmp/screenshot.png` to capture the screen.

## **Blind Spots and Assumptions**

- **Assumptions:**
  - The strategy assumes that detection logs are comprehensive and up-to-date.
  - It presumes standard operating system configurations without significant customizations by users or organizations.

- **Known Limitations:**
  - Potentially undetectable if an adversary uses advanced obfuscation techniques to hide their screen capture activities.
  - Inability to detect all forms of screen captures, especially those executed in memory-only environments without disk I/O.

## **False Positives**

Potential benign activities that might trigger false alerts include:

- Legitimate usage of screenshot tools by users for personal or professional purposes.
- Automated system processes that utilize screen capture functionalities for troubleshooting or remote support.
  
It is crucial to differentiate between legitimate and malicious activity based on context, user behavior analytics, and additional corroborating evidence.

## **Priority**

This strategy holds a **High** priority due to the sensitive nature of information often captured during these activities. Unauthorized access to screen data can lead to significant security breaches, including exposure of confidential information and credentials.

## **Validation (Adversary Emulation)**

To validate detection capabilities, follow these steps in a test environment:

1. **Screencapture**
   - Windows: `SnippingTool.exe`
   - macOS/Linux: Use terminal commands like `import /tmp/screenshot.png`

2. **Screencapture (silent)**
   - PowerShell: `[System.Windows.Forms.Clipboard]::GetImage().Save('C:\screenshot.png', 'image/png')`

3. **X Windows Capture**
   - Execute on Linux with X11: `xwd -root -out /tmp/screenshot.xwd`

4. **X Windows Capture (freebsd)**
   - Utilize similar commands as X Window System in FreeBSD environments.

5. **Capture Linux Desktop using Import Tool**
   - `import -window root /tmp/desktop.png`

6. **Capture Linux Desktop using Import Tool (freebsd)**
   - Adapt the above import command for FreeBSD systems.

7. **Windows Screencapture**
   - Execute `powershell.exe -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::GetImage().Save('C:\screenshot.png', 'image/png')"`

8. **Windows Screen Capture (CopyFromScreen)**
   - Use PowerShell: `[System.Drawing.Graphics]::FromHWND((Get-Process explorer | Select-Object -ExpandProperty MainWindowHandle)).CopyFromScreen(0, 0, 0, 0, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Size); Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::GetImage().Save('C:\screenshot.png', 'image/png')`

9. **Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted**
   - Alter registry settings to test detection: `reg delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\WinSAT" /v DisableAIDataAnalysis /f`

## **Response**

When the alert fires, analysts should:

1. Verify if the activity is associated with known legitimate processes or user behavior.
2. Conduct a deeper investigation to determine the context and scope of screen capture activities.
3. Collect relevant logs and metadata for further analysis and evidence gathering.
4. Implement containment measures if malicious intent is confirmed.
5. Update security policies and controls to prevent recurrence.

## **Additional Resources**

Further reading and context can be found in these related resources:

- Execution Of Script Located In Potentially Suspicious Directory
- Suspicious PowerShell Invocations - Specific - ProcessCreation
- Windows Recall Feature Enabled Via Reg.EXE

This report provides a comprehensive framework for detecting adversarial attempts to bypass security monitoring using container technologies, specifically focusing on screen capture techniques.