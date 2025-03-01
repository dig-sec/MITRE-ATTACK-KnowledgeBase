# Palantir's Alerting & Detection Strategy: Detect Adversarial Attempts to Bypass Security Monitoring Using Rogue Domain Controllers (T1207)

## **Goal**
This technique aims to detect adversarial attempts to bypass security monitoring through the use of rogue domain controllers, also known as DCShadow. This method allows adversaries to create a shadow copy of Active Directory, permitting them to perform unauthorized activities under the guise of legitimate operations.

## **Categorization**

- **MITRE ATT&CK Mapping:** T1207 - Rogue Domain Controller
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Windows

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1207)

## **Strategy Abstract**
The detection strategy focuses on monitoring Active Directory activities to identify signs of rogue domain controller creation. This involves analyzing data from security information and event management (SIEM) systems, network traffic logs, and endpoint detection and response tools.

Key patterns include:
- Anomalous or unauthorized replication events between DCs.
- Unusual authentication requests within the network that suggest shadow operations.
- Modifications to DNS settings indicating the presence of a rogue domain controller.

## **Technical Context**
Adversaries execute T1207 by compromising legitimate domain controllers and using tools like `ntdsutil` to set up a shadow instance. This allows them to perform unauthorized activities without detection, as these actions appear legitimate to security monitoring systems. Adversary emulation may involve executing commands such as:
- `ldifde -d <domain> -f rogue_dc.ldf -r "(objectClass=*)" //`
- Using `ntdsutil` to back up and restore AD databases on compromised machines.

Test scenarios could include setting up a controlled environment with a legitimate DC, then emulating an adversary's actions by creating a shadow instance and observing detection responses.

## **Blind Spots and Assumptions**
- Detection may miss rogue domain controllers that are carefully managed to avoid triggering alerts.
- Assumes all domain controller activities can be logged and monitored effectively.
- Potential for misconfiguration in monitoring tools leading to gaps in coverage.

## **False Positives**
Potential benign activities include:
- Legitimate network reconfigurations or maintenance activities involving multiple DCs.
- Misconfigured replication settings that may mimic unauthorized replication patterns.

## **Priority**
**High:** This technique poses a significant threat as it allows adversaries to operate undetected, potentially leading to data exfiltration and further compromise of the network. The high priority is justified by its impact on organizational security posture and the sophistication required for detection.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions to Emulate DCShadow:

1. **Setup Environment:**
   - Establish a lab with at least two Windows Server VMs configured as domain controllers.
   
2. **Compromise Domain Controller:**
   - Gain administrative access to one of the domain controllers.

3. **Create Rogue DC:**
   - Use `ntdsutil` to back up and restore AD database on a new server, simulating a shadow controller:
     ```shell
     ntdsutil
     secrets
     manage secrets
     restore secret <path_to_backup_file>
     quit
     ```
   
4. **Monitor for Indicators:**
   - Observe replication events, authentication requests, and DNS changes in logs.

5. **Analyze Detection Response:**
   - Verify if the detection system correctly identifies and alerts on the rogue DC activities.

## **Response**
When an alert fires indicating a potential rogue domain controller:
- Immediately isolate the suspected machine from the network.
- Conduct a forensic analysis to confirm unauthorized replication or shadow activities.
- Review logs for any unusual authentication patterns or DNS changes.
- Implement corrective measures such as restoring AD databases and updating credentials.
- Enhance monitoring configurations to reduce blind spots.

## **Additional Resources**
- None available

This report provides a comprehensive overview of detecting rogue domain controllers within the framework of Palantir's ADS, offering strategies for effective detection and response.