# Palantir Alerting & Detection Strategy (ADS) Framework Report

## Goal
This strategy aims to detect adversarial attempts to bypass security monitoring using XML and XSL transformations on Windows platforms.

## Categorization
- **MITRE ATT&CK Mapping:** T1220 - XSL Script Processing
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1220)

## Strategy Abstract
The detection strategy focuses on identifying misuse of XML and XSL transformations to execute scripts or commands that could evade security controls. The key data sources include system logs, process monitoring tools, and network traffic analysis. Patterns analyzed involve unusual script executions via Windows Management Instrumentation Command-line (WMIC) with embedded XSLT transformations.

## Technical Context
Adversaries exploit the XML/XSL processing capabilities to run scripts or commands indirectly, often using legitimate tools like WMIC. This technique is particularly challenging because it leverages built-in Windows features that are not commonly monitored for malicious activity.

### Adversary Emulation Details:
- **MSXSL Bypass using local files:** Adversaries may use `msxsl.exe` to process a locally stored XML file with an XSL script, executing commands or scripts hidden within the transformation.
  
- **MSXSL Bypass using remote files:** Similar to the local method, but the XML and/or XSL files are fetched from a remote server.

- **WMIC bypass using local XSL file:** Uses WMIC to execute commands by applying an XSL transformation on local XML data that contains malicious script logic.

- **WMIC bypass using remote XSL file:** Adversaries use WMIC in combination with remotely hosted XSL files, making detection harder due to network traffic obfuscation.

## Blind Spots and Assumptions
- Detection assumes familiarity with normal baseline behaviors of XML/XSL processing within the environment.
- May not detect highly obfuscated or custom implementations of similar techniques.
- Assumes security tools are capable of monitoring relevant logs and process activities effectively.

## False Positives
Potential benign triggers include:
- Legitimate administrative tasks using WMIC for system management.
- Standard data transformation processes that use XML/XSLT within business applications.

To minimize false positives, contextual analysis such as user behavior, command history, and network origin should be considered alongside alert generation.

## Priority
**Severity: Medium**

The technique is not exceedingly common but poses a significant risk due to its stealthy nature. It exploits legitimate system functions, making it difficult to detect without robust monitoring and anomaly detection systems.

## Validation (Adversary Emulation)
### MSXSL Bypass using local files:
1. Create an XML file with embedded script logic.
2. Develop an XSL stylesheet that processes the XML to execute commands.
3. Run `msxsl.exe` with both files as arguments in a controlled environment.

### MSXSL Bypass using remote files:
1. Host the XML and XSL files on a remote server.
2. Use PowerShell or another tool to fetch and process them locally via `msxsl.exe`.

### WMIC bypass using local XSL file:
1. Prepare an XML document containing script logic.
2. Craft an XSL file that transforms the XML into executable commands.
3. Execute: `wmic os get /format:C:\path\to\xml.xml; msxsl C:\path\to\xml.xml C:\path\to\xsl.xslt`.

### WMIC bypass using remote XSL file:
1. Host the XSL file on a remote server.
2. Fetch and apply it to local XML data using WMIC and `msxsl.exe` in sequence.

## Response
When an alert is triggered, analysts should:
- Verify the legitimacy of the user or process initiating the command.
- Analyze network traffic for suspicious activity related to file downloads/uploads.
- Examine logs for anomalies in script execution patterns.
- Consider disabling or restricting WMIC and msxsl.exe usage until further investigation.

## Additional Resources
- [XSL Script Execution Via WMIC.EXE](https://example.com/xsl-wmic)
- [Process Reconnaissance Via Wmic.EXE](https://example.com/process-recon-wmic)

This report serves as a foundational guide for implementing and refining detection strategies targeting XSL script processing techniques within Windows environments.