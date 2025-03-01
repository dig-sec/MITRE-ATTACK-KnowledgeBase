# Alerting & Detection Strategy (ADS) Report: Base64 Encoding for Obfuscation and DLP Evasion

## **Goal**
This technique aims to detect adversarial attempts to bypass security monitoring using base64 encoding for obfuscating scripts, commands, and data to evade Data Loss Prevention (DLP) systems.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1027 - Obfuscated Files or Information
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1027)

## **Strategy Abstract**
The detection strategy focuses on identifying encoded scripts and data within various file types across multiple platforms. Key data sources include:

- Network traffic logs for unusual base64 patterns
- File monitoring systems for suspiciously large or malformed files
- Process execution logs for abnormal script behavior

Patterns analyzed include:
- Base64 strings in unexpected locations (e.g., within scripts, configuration files)
- Execution of encoded commands using tools like PowerShell, WScript, or custom interpreters
- Network requests containing base64-encoded payloads

## **Technical Context**
Adversaries often use base64 encoding to obfuscate malicious content such as shellcode, command and control URLs, and sensitive data. This technique helps them bypass signature-based detection systems by transforming readable text into a format that resembles benign data.

**Real-World Execution:**

1. Encoding of PowerShell commands:
   ```bash
   echo "powershell.exe -c 'Get-Process'" | base64
   ```
2. Embedding encoded scripts in compressed files or VBA macros.
3. Using Windows Registry to execute encoded payloads.

## **Blind Spots and Assumptions**
- Detection systems may not identify all base64-encoded content due to variations in encoding methods.
- Assumption that base64 encoding is primarily used for obfuscation rather than legitimate data compression.
- Limited detection capability against novel or custom encoding schemes beyond standard base64.

## **False Positives**
Potential benign activities include:
- Legitimate use of base64 encoding in configuration files (e.g., Docker images, SSL certificates).
- Software development practices involving encoding data for storage or transmission.
- Use of base64 in email attachments containing non-malicious scripts or documents.

## **Priority**
**High.** Base64 obfuscation is a common technique used by adversaries to evade detection systems and execute malicious activities undetected across multiple platforms, posing significant security risks.

## **Validation (Adversary Emulation)**

1. **Decode base64 Data into Script:**
   - Create a script encoded in base64.
   - Use tools like `base64 --decode` or PowerShell's `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('encoded_string'))`.

2. **Execute base64-encoded PowerShell:**
   ```powershell
   powershell.exe -Enc [Base64_Encoded_Command]
   ```

3. **Execute base64-encoded PowerShell from Windows Registry:**
   - Add a new key in `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` with a value containing the encoded command.

4. **Execution from Compressed File:**
   - Create a ZIP file containing a base64-encoded script.
   - Use tools like 7-Zip to extract and execute the script.

5. **DLP Evasion via Sensitive Data in VBA Macro over email:**
   - Embed sensitive data in a base64-encoded string within an Excel macro.
   - Send as an email attachment.

6. **DLP Evasion via Sensitive Data in VBA Macro over HTTP:**
   - Host the encoded macro on a web server and download it using an embedded link in another document.

7. **Obfuscated Command in PowerShell:**
   ```powershell
   $cmd = [Convert]::FromBase64String('Encoded_Command')
   iex([System.Text.Encoding]::UTF8.GetString($cmd))
   ```

8. **Obfuscated Command Line using special Unicode characters:**
   - Insert unicode variants to create non-ASCII representations of base64 strings.

9. **Snake Malware Encrypted crmlog file:**
   - Observe and analyze encrypted files with base64 content indicative of Snake malware activity.

10. **Execution from Compressed JScript File:**
    - Create a compressed archive containing a JScript encoded in base64.
    - Extract and execute using a script engine like WScript or Cscript.

## **Response**
When an alert is triggered:
- Isolate the affected system to prevent further malicious activity.
- Analyze network traffic, file changes, and process executions associated with the alert.
- Review logs for indicators of compromise (IOCs) such as unusual command execution patterns or unexpected base64 data.
- Update detection rules to capture similar activities more effectively.

## **Additional Resources**
- [WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript](https://attack.mitre.org/techniques/T1129/)
- Usage Of Web Request Commands And Cmdlets
- [PowerShell Web Download](https://attack.mitre.org/techniques/T1190/)
- Suspicious Invoke-WebRequest Execution

This report provides a comprehensive overview of the base64 encoding technique within the context of ADS, aiming to bolster detection and response capabilities against such obfuscation methods.