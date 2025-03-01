# Alerting & Detection Strategy: Detect Adversarial Use of Signed Scripts on Windows

## **Goal**
This strategy aims to detect adversarial attempts that utilize signed scripts for execution, potentially bypassing security monitoring mechanisms. The focus is primarily on recognizing and alerting when adversaries leverage trusted script signatures to execute malicious activities on Windows platforms.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1216 - Signed Script Proxy Execution
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows

For more details, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1216).

## **Strategy Abstract**
The detection strategy involves monitoring and analyzing script execution patterns on Windows systems. By focusing on PowerShell and Windows Script Host (WSH) activities, specifically those involving signed scripts, this approach identifies potential misuse of trusted digital signatures for executing unauthorized actions.

### Data Sources
- PowerShell logs
- Windows Event Logs (specifically application and system logs)
- File integrity monitoring to track changes in script files

### Analyzed Patterns
- Execution of known benign-signed scripts outside their typical operational context.
- Frequent modifications or executions of signed scripts following suspicious events.
- Usage patterns that deviate from established baseline behaviors.

## **Technical Context**
Adversaries often use signed scripts to evade detection by security solutions that trust digitally signed executables. In practice, attackers obtain legitimate signing certificates (via theft or compromise) and sign their malicious scripts. These scripts appear benign due to the trusted signature but perform harmful actions once executed.

### Adversary Emulation Details
- **Command Examples:**
  - Using `PowerShell.exe` with a signed script for command execution.
  - Execution of WSH files (e.g., `.wsf`) using `Cscript` or `Wscript`.

## **Blind Spots and Assumptions**
- Detection relies on recognizing anomalies in the usage patterns of signed scripts, which can be subtle.
- Assumes that baseline behavior profiling is accurate and up-to-date.
- Some legitimate environments may use dynamic signing practices, potentially leading to misclassification.

## **False Positives**
Potential benign activities include:
- Legitimate administrative tasks using signed scripts as part of routine maintenance or updates.
- DevOps operations involving automated deployment processes that utilize signed scripts for configuration changes.

## **Priority**
**High:** The potential impact is significant as adversaries can leverage trusted signatures to execute code stealthily, circumventing detection mechanisms. Early detection and response are crucial in mitigating such threats.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions

1. **SyncAppvPublishingServer Signed Script PowerShell Command Execution:**
   - Obtain or generate a digital signature for testing purposes.
   - Create a simple PowerShell script that performs a benign action, such as logging current system time.
   - Sign the script using `signtool.exe` with your test certificate.
   - Schedule execution of this signed script through Task Scheduler to mimic legitimate usage patterns.

2. **manage-bde.wsf Signed Script Command Execution:**
   - Develop a basic `.wsf` file that outputs system information (e.g., disk management details).
   - Sign the `.wsf` script with your test certificate.
   - Execute the signed script using `Cscript.exe /nologo manage-bde.wsf`.

## **Response**
When an alert is triggered:
1. Validate the legitimacy of the script's execution context and purpose.
2. Check for any recent changes in digital certificates or signing authorities within the environment.
3. Investigate associated processes and network activity for signs of lateral movement or data exfiltration.
4. Contain the affected systems to prevent further unauthorized actions.

## **Additional Resources**
- WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript
- SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
- Suspicious Calculator Usage

These resources provide additional context and examples of how adversaries might exploit signed scripts in various scenarios.