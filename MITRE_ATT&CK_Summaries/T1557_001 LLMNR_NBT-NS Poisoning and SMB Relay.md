# Palantir's Alerting & Detection Strategy: LLMNR/NBT-NS Poisoning and SMB Relay Detection

## Goal

The goal of this technique is to detect adversarial attempts to bypass security monitoring by utilizing Local Link Multicast Name Resolution (LLMNR) or NetBIOS Name Service (NBT-NS) poisoning. This method enables adversaries to intercept and relay Server Message Block (SMB) traffic, leading to unauthorized access to sensitive information.

## Categorization

- **MITRE ATT&CK Mapping:** 
  - T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
- **Tactic / Kill Chain Phases:**
  - Credential Access
  - Collection
- **Platforms:**
  - Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1557/001)

## Strategy Abstract

This detection strategy leverages network monitoring tools and endpoint detection capabilities to identify anomalous LLMNR/NBT-NS traffic indicative of poisoning attempts. The primary data sources include:

- **Network Traffic Logs:** To capture unusual spikes or patterns in name resolution traffic.
- **Endpoint Activity Monitoring:** Specifically focusing on SMB traffic and suspicious process execution that may suggest relay activities.

The strategy analyzes patterns such as:
- Uncharacteristic volume or type of LLMNR/NBT-NS packets.
- Unexpected SMB session initiations from endpoints associated with abnormal network activity.

## Technical Context

Adversaries execute LLMNR/NBT-NS poisoning by deploying malware like Inveigh that crafts and sends malicious name resolution requests. This allows the adversary to intercept communications between clients on a local network, redirecting or capturing sensitive data transmitted via SMB.

**Real-world Execution:**
1. Deploy a tool such as Inveigh.
2. Execute PowerShell scripts to flood the network with LLMNR/NBT-NS queries.
3. Intercept and relay responses to unauthorized endpoints for credential harvesting.

## Blind Spots and Assumptions

- **Blind Spots:** 
  - Detection may be less effective in networks where high volumes of legitimate LLMNR/NBT-NS traffic occur, potentially masking malicious activity.
  
- **Assumptions:**
  - Baseline network behavior is well-understood to differentiate between normal and abnormal traffic patterns.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate spikes in LLMNR/NBT-NS traffic during periods of high network activity.
- Network reconfigurations or legitimate use cases of Inveigh for testing purposes within controlled environments.

## Priority

**Severity:** High  
**Justification:** The technique allows adversaries to capture sensitive credentials and data, potentially leading to significant security breaches. The ability to bypass traditional detection mechanisms makes it a critical threat vector requiring immediate attention.

## Validation (Adversary Emulation)

To validate the detection strategy in a controlled test environment:

### LLMNR Poisoning with Inveigh (PowerShell)

1. **Setup Environment:**
   - Ensure a Windows-based test network is isolated from production environments.
   
2. **Deploy Inveigh:**
   - Download and execute Inveigh on a test machine:
     ```powershell
     Invoke-WebRequest -Uri "https://github.com/Kevin-Robertson/Inveigh/releases/download/v3.0/inveigh.exe" -OutFile "inveigh.exe"
     .\inveigh.exe
     ```

3. **Execute LLMNR Poisoning:**
   - Use PowerShell to start the Inveigh process:
     ```powershell
     Start-Process -FilePath "inveigh.exe" -ArgumentList "-i", "your-interface"
     ```

4. **Monitor Network Traffic:**
   - Observe network traffic logs for spikes in LLMNR/NBT-NS packets.
   - Check endpoint monitoring tools for unusual SMB activity.

5. **Analyze Results:**
   - Confirm detection by identifying increased or unexpected LLMNR/NBT-NS traffic correlated with unauthorized SMB sessions.

## Response

When an alert is triggered, analysts should:

1. **Isolate Affected Systems:** 
   - Disconnect suspicious endpoints from the network to prevent further data leakage.
   
2. **Investigate Network Traffic:**
   - Analyze captured packets for signs of LLMNR/NBT-NS poisoning and SMB relay activity.

3. **Review Endpoint Logs:**
   - Examine logs for any executed scripts or processes indicative of malicious activity.

4. **Update Security Posture:**
   - Implement network segmentation to limit the spread of poisoned queries.
   - Enhance endpoint security configurations to mitigate against similar attacks.

## Additional Resources

- No additional resources available at this time. Further investigation and collaboration with threat intelligence communities may provide more insights or tools for improving detection capabilities.