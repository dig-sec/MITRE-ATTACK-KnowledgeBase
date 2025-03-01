# Alerting & Detection Strategy (ADS) Report: SNMP (MIB Dump)

## Goal
The primary objective of this detection strategy is to identify adversarial attempts to bypass security monitoring by utilizing Simple Network Management Protocol (SNMP) for extracting management information bases (MIBs). This technique aims to detect activities where adversaries attempt to gather sensitive network information covertly.

## Categorization

- **MITRE ATT&CK Mapping:** T1602.001 - SNMP (MIB Dump)
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Network
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1602/001)

## Strategy Abstract

This detection strategy leverages network monitoring data to identify unusual SNMP activities indicative of a MIB dump. The core focus is on analyzing patterns such as atypical SNMP requests, especially from unauthorized sources or during irregular times. Data sources include network traffic logs and SNMP server activity logs. Analysts look for anomalies in the volume, frequency, and nature of SNMP queries that deviate from normal operational baselines.

## Technical Context

Adversaries use SNMP to collect information by querying MIB objects on network devices. This can reveal sensitive data such as device configurations and internal IP addresses. In a real-world context, adversaries might exploit misconfigured SNMP settings or default community strings to perform these queries undetected.

### Adversary Emulation Details
- **Commands Used:** Adversaries may use tools like `snmpwalk` to extract MIB information:
  ```bash
  snmpwalk -v2c -c public <target_ip> system
  ```

- **Test Scenario:** Simulate an adversary performing a series of SNMP queries targeting network devices using both standard and non-standard community strings.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection might not identify SNMP activities that mimic normal traffic patterns.
  - Encrypted SNMP communications (SNMPv3) may bypass detection if encryption hides query signatures.

- **Assumptions:**
  - The network has baseline activity data for comparison.
  - Network devices are configured to log SNMP queries and responses adequately.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate network management tasks using SNMP by authorized personnel, especially during maintenance windows.
- Misconfigured monitoring tools generating anomalous traffic patterns similar to adversarial activity.

## Priority
**Priority: High**

Justification: The extraction of sensitive information through MIB dumps poses a significant threat as it can provide adversaries with critical insights into the network architecture and aid in further exploitation. Early detection is crucial to mitigate potential breaches.

## Validation (Adversary Emulation)

- None available

## Response

When an alert for SNMP MIB dump activity fires, analysts should:
1. **Verify Source:** Determine if the source of SNMP requests is authorized.
2. **Analyze Patterns:** Compare with known baseline activities to confirm anomalies.
3. **Check Configurations:** Ensure SNMP configurations follow best practices and community strings are strong and unique.
4. **Notify Security Teams:** Alert relevant security teams for further investigation.
5. **Containment Measures:** Consider isolating affected devices from the network if malicious activity is confirmed.

## Additional Resources

Additional references and context:
- None available

---

This report outlines a comprehensive strategy to detect adversarial use of SNMP for MIB dumps, leveraging existing network data sources while acknowledging potential limitations in detection capabilities.