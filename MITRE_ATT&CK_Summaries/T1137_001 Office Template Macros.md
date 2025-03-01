# Alerting & Detection Strategy (ADS) Report: Office Template Macros (T1137.001)

## Goal
This detection strategy aims to identify adversarial attempts to use macros within Microsoft Office templates for establishing persistence on target systems. Specifically, it focuses on detecting when adversaries inject malicious macros into commonly used Office template files, such as Word's `Normal.dotm`, to achieve persistent access.

## Categorization

- **MITRE ATT&CK Mapping:** T1137.001 - Office Template Macros
- **Tactic / Kill Chain Phases:** Persistence
- **Platforms:** Windows, Office 365
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1137/001)

## Strategy Abstract

The detection strategy leverages multiple data sources to identify the presence and execution of malicious macros within Microsoft Office templates. Key data sources include:

- **Office Activity Logs:** Monitor for unusual macro executions or template modifications.
- **File Integrity Monitoring (FIM):** Detect changes in common Office template files such as `Normal.dotm`.
- **Endpoint Detection & Response (EDR) Tools:** Identify suspicious processes related to macro execution and persistence mechanisms.

Patterns analyzed include:

- Unexpected changes in the contents of templates like `Normal.dotm` or `GlobalTemplate.dotm`.
- Execution of macros from modified templates without explicit user initiation.
- Correlation of file modifications with script executions indicative of macro deployment, e.g., via PowerShell scripts.

## Technical Context

Adversaries often exploit Office template macros to establish persistence due to their ability to execute malicious code when the application launches. These macros can be injected into documents or template files that are regularly used by end-users, such as `Normal.dotm` in Word. Once embedded, these macros can run automatically, enabling persistent access and further actions on compromised systems.

### Adversary Emulation Details

- **Sample Commands:** Use of PowerShell scripts to inject malicious macros into templates.
  ```powershell
  $template = "C:\Users\Public\Documents\Normal.dotm"
  $macroCode = 'Sub AutoOpen() ... End Sub'
  ```

- **Test Scenarios:**
  - Modify the `Normal.dotm` template file to include a macro that writes a log entry or connects back to a C2 server.
  - Execute Word application and observe if macros run without user intervention.

## Blind Spots and Assumptions

- **Blind Spots:** Detection may not capture highly obfuscated macro code or techniques using legitimate templates for malicious purposes.
- **Assumptions:** Assumes that Office applications are configured to allow macro execution, which might not be the case in environments with strict security settings.

## False Positives

Potential benign activities triggering false alerts include:

- Legitimate use of macros by users for productivity enhancements.
- Regular updates or modifications to template files by IT administrators.
- Scheduled tasks running legitimate maintenance scripts involving Office templates.

## Priority

**Severity:** High  
**Justification:** The ability to establish persistence through Office template macros represents a significant risk, particularly in environments where macro execution is enabled and users frequently open documents. This technique can facilitate lateral movement and further compromise within the network.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Preparation:**
   - Ensure PowerShell is installed on the test environment.
   - Back up `Normal.dotm` file to avoid data loss.

2. **Inject Macro into Template:**
   ```powershell
   $template = "C:\Users\Public\Documents\Normal.dotm"
   $macroCode = 'Sub AutoOpen() MsgBox "Persistence Established" End Sub'
   
   # Load the template as a Word document
   $word = New-Object -ComObject Word.Application
   $doc = $word.Documents.Open($template)

   # Add macro to document
   $vbProject = $doc.VBProject
   $moduleCode = @"
   Sub AutoOpen()
       MsgBox "Persistence Established"
   End Sub
   "@

   $module = $vbProject.VBComponents.Add(1)  # vbext_ct_StdModule
   $vbpCodeModule = $module.CodeModule
   $vbpCodeModule.InsertLines(1, $moduleCode)

   # Save and close the document
   $doc.Save()
   $word.Quit()

   [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
   ```

3. **Execute Word Application:**
   - Open Microsoft Word to trigger the macro execution.
   - Observe if the "Persistence Established" message box appears.

4. **Monitor Logs and Alerts:**
   - Check logs for alerts indicating macro execution or template modification.
   - Validate detection through configured monitoring tools.

## Response

When an alert related to malicious Office template macros is triggered, analysts should:

1. **Isolate Affected Systems:** Disconnect from the network if necessary to prevent further compromise.
2. **Analyze Logs and Alerts:** Review logs for details on macro execution, file modifications, and associated processes.
3. **Remove Malicious Macros:**
   - Manually remove malicious macros from template files.
   - Restore templates from backups if available.

4. **Update Security Policies:**
   - Enforce stricter security settings to disable macro execution without user consent.
   - Educate users on the risks of enabling macros in documents and templates.

5. **Incident Reporting:** Document findings, actions taken, and update incident response plans accordingly.

## Additional Resources

- [Microsoft Office Macro Security](https://support.microsoft.com/en-us/office/security-options-for-microsoft-office)
- [Office Template Macros Detection Techniques](https://example.com/detection-guidelines)

This report provides a comprehensive framework for detecting and responding to adversarial use of Office template macros, emphasizing the importance of monitoring, analysis, and proactive security measures.