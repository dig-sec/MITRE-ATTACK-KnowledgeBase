# Alerting & Detection Strategy (ADS) Report: System Owner/User Discovery

## **Goal**
The goal of this strategy is to detect adversarial attempts aimed at discovering system owners and users as a precursor to further malicious activities. This can involve bypassing security monitoring mechanisms, gaining unauthorized access, or establishing persistence within the target environment.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1033 - System Owner/User Discovery
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1033)

## **Strategy Abstract**
This detection strategy focuses on identifying attempts to discover system owners and users. It leverages a variety of data sources including process monitoring, command execution logs, and user activity records across supported platforms (Linux, macOS, Windows). The patterns analyzed include frequent use of commands like `whoami`, environment variable access indicative of user discovery scripts, and unusual PowerShell script executions. Cross-referencing these indicators with baseline behavior can help identify suspicious activities.

## **Technical Context**
Adversaries execute system owner/user discovery to tailor further attacks based on the privileges available. Common real-world techniques include:

- Utilizing built-in commands like `whoami` in Windows or `id`, and `uname` in Linux/macOS.
- Running PowerShell scripts that leverage environment variables for user context acquisition.
- Employing stealthy command execution frameworks such as PowerView to fetch session details without triggering alerts.

Adversaries often use these techniques early in the attack lifecycle, typically during reconnaissance phases, to gather information critical for escalating privileges or evading detection.

## **Blind Spots and Assumptions**
- **Blind Spots:** 
  - Encrypted command executions that bypass logging.
  - Adversaries using custom tools not covered by standard signature-based detections.
  
- **Assumptions:**
  - Assumes logs are enabled and comprehensive enough to capture all relevant activities.
  - Relies on establishing a baseline of normal user behavior for anomaly detection.

## **False Positives**
Potential benign activities that could trigger false alerts include:
- Legitimate administrative tasks using `whoami` or similar commands.
- Routine maintenance scripts that query system information.
- Developers running environment variable scripts during software development or testing phases.

These can be mitigated by context-aware analysis, such as evaluating the frequency and source of the commands.

## **Priority**
**Severity: Medium**

Justification:
- System owner/user discovery is a common precursor to more harmful activities like privilege escalation. While it doesn't directly cause damage, its detection is critical for early intervention.
- Balances between the necessity to detect potential malicious activity and the risk of false positives in environments with frequent legitimate use of discovery commands.

## **Validation (Adversary Emulation)**
### Step-by-step Instructions:
1. **System Owner/User Discovery:**
   - Use `whoami` or equivalent commands (`id`, `uname`) on respective platforms to simulate user identification attempts.
   
2. **Find computers where user has session - Stealth mode (PowerView):**
   - Execute PowerView commands such as `Get-NetComputer` in PowerShell with stealth options.

3. **User Discovery With Env Vars PowerShell Script:**
   - Run a script that accesses environment variables to extract user information:
     ```powershell
     $env:USERNAME
     ```

4. **GetCurrent User with PowerShell Script:**
   - Execute scripts using `Get-CurrentPrincipal` or equivalent commands.

5. **System Discovery - SocGholish whoami:**
   - Simulate reconnaissance by executing `whoami` in conjunction with other system discovery tools like SocGholish.

6. **System Owner/User Discovery Using Command Prompt:**
   - Use command prompt-based tools such as `systeminfo` to gather user and system information on Windows environments.

## **Response**
When the alert fires, analysts should:
- Immediately investigate the context of the activity (time, location, involved accounts).
- Check for additional indicators of compromise or suspicious behavior in related logs.
- Assess whether the discovered users align with legitimate administrative activities.
- Notify relevant stakeholders if a security breach is confirmed and escalate according to incident response protocols.

## **Additional Resources**
- Recon Command Output Piped To Findstr.EXE
- Whoami.EXE Execution With Output Option

These resources provide further examples of command usage patterns that can be monitored for detection purposes, aiding in understanding adversary techniques and refining alerting mechanisms.