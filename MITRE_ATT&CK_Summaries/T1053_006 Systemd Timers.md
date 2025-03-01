# Palantir's Alerting & Detection Strategy: Systemd Timers (T1053.006)

## **Goal**
The goal of this technique is to detect adversarial attempts to use systemd timers as a method for execution, persistence, and privilege escalation on Linux systems.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1053.006 - Systemd Timers
- **Tactic / Kill Chain Phases:** Execution, Persistence, Privilege Escalation
- **Platforms:** Linux
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1053/006)

## **Strategy Abstract**
This detection strategy focuses on monitoring systemd timer activities to identify potential adversarial use. Data sources include system logs (e.g., journalctl, syslog) and file integrity monitoring systems. The strategy analyzes patterns such as unusual creation or modification of systemd service files, unexpected scheduling of timers, and timers set to execute commands with elevated privileges.

## **Technical Context**
Adversaries may exploit systemd timers to bypass traditional security monitoring by executing scripts at specific times or intervals. This technique is particularly insidious because it can be used for persistence by ensuring that malicious code runs periodically without direct user interaction.

### Adversary Emulation Details
- **Sample Commands:**
  - Creating a systemd service:
    ```bash
    sudo tee /etc/systemd/system/malicious-service.service <<EOF
    [Unit]
    Description=Malicious Service

    [Service]
    ExecStart=/bin/bash /path/to/malicious/script.sh

    [Install]
    WantedBy=multi-user.target
    EOF
    ```
  - Creating a systemd timer:
    ```bash
    sudo tee /etc/systemd/system/malicious-service.timer <<EOF
    [Unit]
    Description=Run malicious service every minute

    [Timer]
    OnBootSec=5min
    OnUnitActiveSec=1min

    [Install]
    WantedBy=timers.target
    EOF
    ```
  - Enabling and starting the timer:
    ```bash
    sudo systemctl enable malicious-service.timer
    sudo systemctl start malicious-service.timer
    ```

### Test Scenarios
- Set up a test environment with monitoring tools enabled.
- Execute the above commands to create and activate a systemd timer that triggers a benign script.

## **Blind Spots and Assumptions**
- **Limitations:** The strategy may not detect timers set with very infrequent intervals or those configured to trigger under specific conditions not monitored by logs.
- **Assumptions:** Assumes that system logging is comprehensive and that file integrity monitoring covers systemd files.

## **False Positives**
Potential benign activities include:
- Legitimate system maintenance scripts scheduled via systemd timers.
- Developer scripts for testing purposes.
- Automated backup processes using systemd timers.

## **Priority**
**Severity: Medium**

Justification: While not the most common method of attack, misuse of systemd timers can provide significant persistence and privilege escalation capabilities. The medium priority reflects its potential impact balanced against its relative obscurity compared to other techniques.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions

1. **Create Systemd Service and Timer:**
   - Use the sample commands provided in the Technical Context section.
   - Verify creation by checking `/etc/systemd/system/`.

2. **Create a User Level Transient Systemd Service and Timer:**
   ```bash
   mkdir -p ~/.config/systemd/user/
   cat <<EOF > ~/.config/systemd/user/malicious-user-service.service
   [Unit]
   Description=User Level Malicious Service

   [Service]
   ExecStart=/bin/bash /path/to/malicious/script.sh
   EOF
   ```
   ```bash
   cat <<EOF > ~/.config/systemd/user/malicious-user-service.timer
   [Unit]
   Description=Run user level malicious service every minute

   [Timer]
   OnBootSec=5min
   OnUnitActiveSec=1min

   [Install]
   WantedBy=timers.target
   EOF
   ```
   ```bash
   systemctl --user enable malicious-user-service.timer
   systemctl --user start malicious-user-service.timer
   ```

3. **Create a System Level Transient Systemd Service and Timer:**
   - Use the same commands as in step 1, but place files in `/etc/systemd/system/`.
   - Enable and start using `sudo systemctl enable` and `sudo systemctl start`.

## **Response**
When an alert fires:
- Investigate the systemd service and timer logs for unusual activity.
- Determine if the timer is associated with known legitimate processes or scripts.
- If malicious, disable the service and timer immediately:
  ```bash
  sudo systemctl stop malicious-service.timer
  sudo systemctl disable malicious-service.timer
  ```
- Conduct a thorough system scan to ensure no additional persistence mechanisms are present.

## **Additional Resources**
- [Understanding Systemd Timers](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
- [Execution Of Script Located In Potentially Suspicious Directory](#)

This report provides a comprehensive overview of detecting adversarial use of systemd timers, aligning with Palantir's ADS framework.