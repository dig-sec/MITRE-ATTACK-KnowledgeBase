# Alerting & Detection Strategy (ADS) Report: Compile After Delivery

## Goal
This technique aims to detect adversarial attempts to bypass security monitoring by leveraging the capability of executing post-delivery compilation of malicious scripts or binaries on target systems.

## Categorization

- **MITRE ATT&CK Mapping:** T1027.004 - Compile After Delivery
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1027/004)

## Strategy Abstract

The detection strategy focuses on monitoring and analyzing runtime activity indicative of post-delivery compilation attempts. This includes:

- **Data Sources:**
  - Process creation logs
  - System call traces
  - File system access patterns
  - Network traffic analysis for remote compilation commands

- **Patterns Analyzed:**
  - Unusual use of compilers or code execution tools (e.g., `csc.exe`, `gcc`)
  - Execution of scripts that result in dynamic compilation and immediate execution
  - Anomalies in process spawning patterns, particularly involving known compiler utilities

The strategy involves correlating these indicators with contextual data to improve detection accuracy.

## Technical Context

Adversaries may use compile-after-delivery techniques to evade traditional signature-based defenses. By compiling malicious code at runtime on the target system, they can generate unique binaries that change with each execution attempt, complicating detection efforts.

### Adversary Emulation Details:
- **C# Example:**
  ```shell
  csc.exe /target:exe /out:test.exe test.cs
  ```
  
- **C/C++ Example:**
  ```shell
  gcc -o malicious.exe malicious.c
  ```

- **Go Example:**
  ```shell
  go build -o malware.go
  ```

## Blind Spots and Assumptions

- Detection may not cover all compiler utilities or obscure methods of in-memory compilation.
- Assumes that the detection system can monitor a comprehensive set of process creation events without missing critical data due to resource constraints.

## False Positives

Potential benign activities include:
- Legitimate software development environments where compilation is routine.
- Automated build systems within an organization's network.
- Use of virtual machines for testing, which may involve frequent code compilation and execution.

## Priority

**Severity:** High

Justification: The technique effectively bypasses static defenses by generating new payloads on each use. It poses a significant risk to environments with insufficient dynamic behavioral monitoring capabilities.

## Validation (Adversary Emulation)

### Steps to Emulate in a Test Environment:

1. **Using `csc.exe` for C#:**
   - Write a simple malicious script (`test.cs`) containing benign code.
   - Compile using: `csc.exe /target:exe /out:test.exe test.cs`
   - Execute and observe the process logs.

2. **Dynamic C# Compilation:**
   - Use .NET's `CSharpCodeProvider` to compile code dynamically in-memory.
   - Observe any unusual memory or resource access patterns during execution.

3. **Using `gcc`:**
   - Write a simple C program (`malicious.c`) with benign content.
   - Compile using: `gcc -o malicious.exe malicious.c`
   - Execute and monitor process creation logs.

4. **Using `CC` Compiler:**
   - Similar to the GCC example, compile a small C program intended for analysis.

5. **Go Compilation:**
   - Write a Go file (`malware.go`) with benign functionality.
   - Compile using: `go build -o malware.exe`
   - Execute and trace process activities in logs.

## Response

When an alert fires indicating potential compile-after-delivery activity:

1. **Immediate Isolation:** Quarantine the affected host to prevent further malicious execution or lateral movement.
2. **Forensic Analysis:** Capture and analyze memory dumps, network traffic, and logs for deeper insights into the adversary's tactics.
3. **Root Cause Investigation:** Identify entry points and vectors used by adversaries to introduce malicious code.
4. **System Hardening:** Apply necessary patches, update security configurations, and enhance monitoring capabilities.

## Additional Resources

- None available

This report outlines a comprehensive approach for detecting and responding to compile-after-delivery techniques within an organization's network, ensuring robust defense against sophisticated evasion tactics.