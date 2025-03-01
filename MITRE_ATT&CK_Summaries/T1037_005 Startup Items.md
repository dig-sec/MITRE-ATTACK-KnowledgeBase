# Alerting & Detection Strategy (ADS) Report

## Goal
The objective of this detection strategy is to identify adversarial attempts to establish persistence on macOS systems by exploiting startup items, launch daemons, and launch agents. This includes detecting unauthorized changes or additions to these components that could be used for persistent access or privilege escalation.

## Categorization
- **MITRE ATT&CK Mapping:** T1037.005 - Startup Items
- **Tactic / Kill Chain Phases:** Persistence, Privilege Escalation
- **Platforms:** macOS

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1037/005)

## Strategy Abstract
This strategy leverages monitoring of system logs and configuration files to detect unauthorized modifications to startup items, launch daemons, and launch agents. Key data sources include:
- System logs (`/var/log/system.log`, `/Library/Logs`).
- Launch services database (`launchctl list` output).
- File integrity checks for directories like `~/Library/LaunchAgents/`, `/Library/LaunchDaemons/`.

Patterns analyzed include unexpected modifications to these files and the addition of new scripts or binaries that execute at startup, which could indicate persistence mechanisms.

## Technical Context
Adversaries often modify startup items, launch daemons, and agents on macOS to achieve persistent access. These techniques allow them to run malicious code automatically upon system boot or user login. Common methods include:
- Adding a script to `~/Library/LaunchAgents/`.
- Creating a new entry in `/Library/LaunchDaemons/`.

Adversary emulation might involve:
- Using `sudo` commands like `launchctl load /path/to/script.plist` to activate daemons.
- Modifying plist files directly to include malicious code execution paths.

## Blind Spots and Assumptions
- **Blind Spots:** Detection may miss obfuscated scripts or those with minimal permissions that evade logging.
- **Assumptions:** Assumes baseline knowledge of what constitutes normal startup behavior for the specific environment. Relies on accurate baselining of system configurations.

## False Positives
Potential benign activities triggering false alerts include:
- Legitimate software installations modifying launch daemons/agents.
- System updates or configurations changes that alter startup items.

Mitigation involves tuning detection to known application behaviors and whitelisting common legitimate modifications.

## Priority
**Priority:** High

**Justification:** Persistence is a critical stage in an adversary's lifecycle, enabling long-term access and privilege escalation. Detecting unauthorized persistence mechanisms on macOS can significantly reduce the risk of prolonged system compromise.

## Validation (Adversary Emulation)
To validate this detection strategy, follow these steps in a controlled test environment:

1. **Add file to Local Library StartupItems:**
   - Create a new plist file at `~/Library/StartupItems/testAgent/Contents/`.
   - Define a script within the plist that executes on startup.

2. **Add launch script to launch daemon:**
   - Place a plist in `/Library/LaunchDaemons/` with appropriate permissions.
   - Use `sudo launchctl load /Library/LaunchDaemons/com.example.testDaemon.plist`.

3. **Add launch script to launch agent:**
   - Create a plist file at `~/Library/LaunchAgents/`.
   - Load it using `launchctl load ~/Library/LaunchAgents/com.example.testAgent.plist`.

Monitor logs and detection alerts for each step to verify the strategy's effectiveness.

## Response
When an alert is triggered:
1. **Verify Changes:** Examine the modified plist files and scripts in question.
2. **Assess Impact:** Determine if any detected changes are legitimate or malicious.
3. **Containment:** If malicious, isolate affected systems and remove unauthorized modifications.
4. **Investigation:** Perform a thorough investigation to identify potential persistence mechanisms elsewhere.

## Additional Resources
Additional references and context:
- None available

This report provides a structured approach to detecting and responding to adversarial attempts at establishing persistence on macOS through startup items, launch daemons, and agents.