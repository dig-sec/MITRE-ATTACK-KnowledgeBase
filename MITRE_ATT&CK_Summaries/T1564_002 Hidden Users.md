# Detection Strategy Report: Detecting Hidden Users on macOS and Windows

## Goal
The primary objective of this detection strategy is to identify adversarial attempts to bypass security monitoring by creating hidden users. This technique aims to uncover unauthorized access that remains undetected due to the obscurity created by these hidden accounts.

## Categorization
- **MITRE ATT&CK Mapping:** T1564.002 - Hidden Users
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** macOS, Windows

For more information on this technique, see the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1564/002).

## Strategy Abstract
This detection strategy employs a combination of system log analysis and registry/event monitoring to identify patterns indicative of hidden user creation. On both macOS and Windows platforms, it focuses on discrepancies between visible users in system interfaces and those recorded in lower-level system files or registries. Key data sources include:

- **Windows Event Logs:** Monitoring for account creations that do not appear in standard user listings.
- **macOS System Logs:** Analyzing `dscl` commands and `launchctl` outputs to detect inconsistencies.
- **Registry Files (Windows):** Inspecting registry keys related to user profiles.

## Technical Context
Adversaries may employ various methods to create hidden users, such as:

- Assigning unique IDs less than 500 on Windows, which are typically reserved for system accounts and not displayed by default in standard user interfaces.
- Using the `IsHidden` option within account properties to conceal their presence from graphical user interface listings.
- Modifying registry keys or leveraging command-line tools (`dscl` on macOS, PowerShell/cmdlets on Windows) that manipulate user visibility.

### Adversary Emulation Details
Adversaries might use commands like:
- **Windows:** `net user hiddenUser /add`, followed by setting `IsHidden:1` via `reg.exe`.
- **macOS:** Using `dscl . -create /Users/hiddenUser IsHidden 1`.

## Blind Spots and Assumptions
- Detection may miss users created with advanced privilege escalation techniques or through kernel-level exploits.
- Assumes that monitoring systems have full visibility over necessary logs and registries, which might not be the case in segmented network environments.

## False Positives
Potential benign activities triggering false positives include:
- System administrators creating hidden accounts for management purposes (e.g., service accounts).
- Software installations that configure hidden users as part of their setup process.
- Misconfigured systems where legitimate user visibility settings are altered inadvertently.

## Priority
**Priority Level: High**

Justification:
The ability to create and use hidden users allows adversaries to conduct unauthorized activities undetected, making it a significant threat to system integrity. Early detection is crucial for maintaining robust defense mechanisms.

## Validation (Adversary Emulation)
### Step-by-Step Instructions

#### Create Hidden User using UniqueID < 500
1. **Windows:**
   - Open Command Prompt as Administrator.
   - Execute `net user hiddenUser password /add`.
   - Modify the user account properties to set a unique ID below 500 with `wmic useraccount where "name='hiddenUser'" call rename newname='hiddenUser'`.

#### Create Hidden User using IsHidden option
1. **Windows:**
   - Run Command Prompt as Administrator.
   - Execute `net user hiddenUser /add`.
   - Set the account to hidden: `reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v SpecialAccounts\UserList /t REG_MULTI_SZ /d "hiddenUser" /f`.

2. **macOS:**
   - Open Terminal.
   - Execute `sudo dscl . -create /Users/hiddenUser IsHidden 1`.
   - Create the user: `sudo dscl . -create /Users/hiddenUser UserShell /bin/false`.

#### Create Hidden User in Registry
1. **Windows:**
   - Use `regedit` to navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.
   - Add a new entry under "SpecialAccounts" for the user to set visibility flags.

## Response
When an alert triggers, analysts should:
1. Verify the legitimacy of the hidden user by checking against known service accounts and administrative practices.
2. Investigate the timeline of creation and any associated activities linked to this account.
3. Assess the potential impact on system security and data integrity.
4. Document findings and update incident response protocols accordingly.

## Additional Resources
- None available

This report outlines a comprehensive approach for detecting hidden users, providing clear guidance for implementation within a security framework aimed at minimizing adversarial evasion tactics.