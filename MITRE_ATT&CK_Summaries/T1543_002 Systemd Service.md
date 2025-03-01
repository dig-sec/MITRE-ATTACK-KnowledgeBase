# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers on Linux Systems

## **Goal**
The goal of this detection technique is to identify and alert on adversarial attempts to bypass security monitoring by leveraging Systemd services, specifically through the exploitation of T1543.002 - Systemd Service. This strategy aims at detecting techniques used for persistence and privilege escalation within Linux environments.

## **Categorization**
- **MITRE ATT&CK Mapping:** 
  - [T1543.002 - Systemd Service](https://attack.mitre.org/techniques/T1543/002)
  
- **Tactic / Kill Chain Phases:**
  - Persistence
  - Privilege Escalation
  
- **Platforms:**
  - Linux

## **Strategy Abstract**
This detection strategy utilizes log data from system daemons and service management tools to monitor for suspicious activities involving Systemd services. The pattern analysis focuses on unauthorized creation, modification, or enabling of Systemd services that could be used by adversaries to maintain persistence and escalate privileges in a compromised environment.

Key Data Sources:
- System logs (e.g., /var/log/messages, journalctl)
- Audit logs
- System service directories (/etc/systemd/system/)

Patterns Analyzed:
- Creation or modification of new Systemd service files outside typical maintenance windows.
- Enabling of newly created services with unusual parameters or from uncommon locations.

## **Technical Context**
Adversaries may execute this technique to ensure their presence remains undetected on a compromised system. By exploiting Systemd's capabilities, adversaries can schedule tasks or create backdoors that are harder for traditional monitoring tools to detect. Common adversary actions include:

- Creating custom service files with scripts designed to hide activity.
- Modifying existing services to include malicious commands.

Adversary Emulation Details:
- Sample command to create a new Systemd service:
  ```bash
  echo '[Service]
  ExecStart=/usr/bin/python3 /tmp/malicious_script.py' > /etc/systemd/system/custom-malware.service
  systemctl enable custom-malware.service
  ```

## **Blind Spots and Assumptions**
- Detection may miss services configured via non-standard methods or obfuscated scripts.
- Assumes a baseline of typical system service management activity, which might not account for all benign use cases.

## **False Positives**
Potential false positives include:
- Legitimate installation of software packages that create Systemd services (e.g., Docker containers).
- Scheduled maintenance activities where new services are commonly created or modified by authorized personnel.
  
## **Priority**
**High**: Given the potential impact on system integrity and security posture, especially in environments with high-value assets or sensitive data. Early detection is crucial to prevent adversaries from establishing a persistent foothold.

## **Validation (Adversary Emulation)**
To validate this detection technique:

1. **Create Systemd Service:**
   - Create a test service file:
     ```bash
     echo '[Service]
     ExecStart=/bin/bash -c "echo Hello World > /tmp/test_service_output"' > /etc/systemd/system/test.service
     ```

2. **Enable the Service:**
   - Enable and start the service to simulate persistence setup:
     ```bash
     systemctl enable test.service
     systemctl start test.service
     ```

3. **Modify and Reload the Service:**
   - Modify the service file to change its behavior, simulating an adversarial action:
     ```bash
     echo 'ExecStart=/bin/bash -c "echo Modified by adversary > /tmp/test_service_output"' >> /etc/systemd/system/test.service
     systemctl daemon-reload
     systemctl restart test.service
     ```

## **Response**
When this alert fires, analysts should:

- Verify the origin of the Systemd service creation/modification.
- Investigate associated logs for indicators of compromise or suspicious activity.
- Assess the potential impact and determine if any actions by the service are unauthorized.
- Consider containment measures such as disabling the service.

## **Additional Resources**
For further context on related techniques, consider exploring:
- Execution Of Script Located In Potentially Suspicious Directory

This report provides a comprehensive framework for detecting adversarial use of Systemd services in Linux environments. Analysts should tailor detection rules and responses to their specific operational environment and threat landscape.