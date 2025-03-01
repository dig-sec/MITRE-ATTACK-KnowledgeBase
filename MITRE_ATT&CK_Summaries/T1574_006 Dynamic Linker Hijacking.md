# Alerting & Detection Strategy (ADS) Report: Dynamic Linker Hijacking

## Goal
The primary aim of this technique is to detect adversarial attempts to bypass security monitoring by exploiting dynamic linker hijacking on systems running Linux and macOS. This involves adversaries manipulating shared libraries or runtime linking settings to execute malicious code when legitimate programs are run.

## Categorization

- **MITRE ATT&CK Mapping:** T1574.006 - Dynamic Linker Hijacking
- **Tactic / Kill Chain Phases:**
  - Persistence
  - Privilege Escalation
  - Defense Evasion
- **Platforms:** Linux, macOS
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1574/006)

## Strategy Abstract

The detection strategy for Dynamic Linker Hijacking focuses on monitoring changes to system configurations and runtime environments that could facilitate the execution of unauthorized code. Key data sources include:

- System logs (e.g., `/var/log/auth.log`, `/var/log/syslog`)
- File integrity monitoring logs
- Environment variables (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS)
- Changes to critical system directories like `/etc/ld.so.preload`

Patterns analyzed include unexpected modifications or the presence of malicious shared libraries in these locations. Additionally, unusual changes to environment variables that are used for dynamic linking can signal potential hijacking attempts.

## Technical Context

Dynamic linker hijacking allows adversaries to intercept calls to functions within legitimate applications by injecting their own malicious code via shared libraries. This is typically achieved through:

- Modifying the `/etc/ld.so.preload` file on Linux, which specifies libraries that should be loaded before any others.
- Setting the `LD_PRELOAD` environment variable on Linux to load a specified library before all others.
- Using the `DYLD_INSERT_LIBRARIES` environment variable on macOS for similar purposes.

Adversaries may execute these techniques using commands like:

```bash
# On Linux
echo "/path/to/malicious.so" > /etc/ld.so.preload

export LD_PRELOAD=/path/to/malicious.so

# On macOS
export DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib
```

## Blind Spots and Assumptions

- **Blind Spots:**
  - Detection may miss attacks if logs are disabled or tampered with.
  - Adversaries using sophisticated obfuscation techniques might evade detection.

- **Assumptions:**
  - It is assumed that changes to critical system files or environment variables are indicative of malicious activity unless whitelisted.
  - The environment for monitoring should have comprehensive logging enabled and actively monitored.

## False Positives

Potential false positives include:

- Legitimate software installations or updates modifying shared libraries or environment settings.
- Misconfigurations by users leading to unexpected changes in dynamic linker behavior.
- System administrators legitimately altering environment variables for debugging purposes.

## Priority

The severity of Dynamic Linker Hijacking is assessed as **High**. This is due to its capability to bypass security controls, facilitate persistent access, and escalate privileges without direct interaction with the system's main processes.

## Validation (Adversary Emulation)

To validate detection mechanisms, follow these steps in a controlled test environment:

### Shared Library Injection via `/etc/ld.so.preload`

1. Create a benign shared library for testing.
2. Modify `/etc/ld.so.preload` to include the path to this library.
3. Execute a standard application and observe if the shared library loads as expected.

```bash
# Step 2: Add test library
echo "/path/to/test_library.so" > /etc/ld.so.preload

# Test execution
some_application_command
```

### Shared Library Injection via `LD_PRELOAD`

1. Set `LD_PRELOAD` to point to a benign shared library.
2. Execute a program and verify if the preload is effective.

```bash
export LD_PRELOAD=/path/to/test_library.so
some_application_command
```

### Dylib Injection via `DYLD_INSERT_LIBRARIES`

1. On macOS, set `DYLD_INSERT_LIBRARIES` to point to a benign dylib.
2. Run an application and check if the library is injected.

```bash
export DYLD_INSERT_LIBRARIES=/path/to/test_library.dylib
some_application_command
```

## Response

Upon detection of potential Dynamic Linker Hijacking:

1. **Immediate Actions:**
   - Isolate affected systems to prevent further compromise.
   - Review and validate recent changes to critical files and environment variables.

2. **Investigation:**
   - Analyze logs for indicators of tampering or unauthorized access.
   - Check for unusual application behavior that may result from library injection.

3. **Mitigation:**
   - Remove any unauthorized modifications to dynamic linker settings.
   - Update security policies and ensure file integrity monitoring is in place.

4. **Reporting:**
   - Document findings and notify relevant stakeholders about the incident.
   - Consider engaging with a cybersecurity team for deeper forensic analysis.

## Additional Resources

Currently, no additional resources are available beyond the MITRE ATT&CK framework reference provided.

---

This report outlines a comprehensive strategy to detect and respond to Dynamic Linker Hijacking attacks on Linux and macOS systems, ensuring robust defense mechanisms against this advanced evasion technique.