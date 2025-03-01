# Palantir's Alerting & Detection Strategy (ADS) Framework: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal
The technique aims to detect adversarial attempts to bypass security monitoring by exploiting local group configurations within containers across various platforms including Linux, macOS, and Windows.

## Categorization

- **MITRE ATT&CK Mapping:** T1069.001 - Local Groups
- **Tactic / Kill Chain Phases:** Discovery
- **Platforms:** Linux, macOS, Windows  
  [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1069/001)

## Strategy Abstract

The detection strategy focuses on monitoring changes and unauthorized access to local group configurations within containerized environments. This involves analyzing logs from operating system-level processes and security tools that track changes in user permissions, group memberships, and privilege escalation attempts.

### Data Sources
- **Container Logs:** Collects logs related to process executions and system changes.
- **Operating System Audit Logs:** Monitors changes in local group configurations.
- **Security Information and Event Management (SIEM) Systems:** Aggregates data for correlation analysis.

### Patterns Analyzed
- Unauthorized modifications of local groups.
- Anomalies in permission escalations within containers.
- Unusual access patterns to sensitive system files or services by non-administrative users.

## Technical Context

Adversaries often exploit containerized environments due to their isolated nature, which may have less stringent security controls compared to traditional host systems. They may leverage misconfigurations or vulnerabilities in local group settings to elevate privileges or bypass monitoring.

### Adversary Emulation Details
- **Sample Commands:**
  - Windows: `net user /domain`
  - PowerShell: `Get-LocalGroup`
  - Linux (Docker): `docker exec container_id cat /etc/group`

### Test Scenarios
1. Modify local group membership to include unauthorized users.
2. Execute commands with elevated privileges through group changes.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Limited visibility into encrypted or obfuscated command execution within containers.
  - Detection may not cover all variations of privilege escalation techniques.

- **Assumptions:**
  - Containers are configured to log sufficient details for audit purposes.
  - Security tools have access to monitor and analyze container environments effectively.

## False Positives

Potential benign activities that might trigger false alerts include:
- Legitimate administrative tasks requiring local group modifications.
- Software updates or deployments that adjust user permissions as part of their configuration process.

## Priority
**High:** Due to the critical nature of privilege escalation and the potential for adversaries to gain unauthorized access and control over systems, this technique demands immediate attention. The ability to bypass security monitoring represents a significant threat vector in containerized environments.

## Validation (Adversary Emulation)

### Step-by-Step Instructions

1. **Permission Groups Discovery (Local)**
   - Execute: `net localgroup`
   - Objective: Identify all local groups and members.

2. **Basic Permission Groups Discovery Windows (Local)**
   - Execute: `whoami /groups`
   - Objective: Verify user group memberships.

3. **Permission Groups Discovery PowerShell (Local)**
   - Command: `Get-LocalGroup | ForEach { Get-LocalGroupMember $_ }`
   - Objective: List local groups and their members via PowerShell.

4. **SharpHound3 - LocalAdmin**
   - Deploy SharpHound script to enumerate administrators.
   - Objective: Identify users with elevated privileges.

5. **Wmic Group Discovery**
   - Command: `wmic useraccount get name,sid`
   - Objective: List all user accounts and their SIDs.

6. **WMIObject Group Discovery**
   - Command: `Get-WmiObject Win32_GroupUser | Select-Object PartComponent, Antecedent`
   - Objective: Map users to groups using WMI queries.

7. **Permission Groups Discovery for Containers (Local Groups)**
   - In Docker: `docker exec <container_id> cat /etc/group`
   - Objective: Review group configurations within a container.

## Response

When the alert fires, analysts should:
- Verify if there is legitimate administrative activity justifying changes.
- Assess the extent and impact of any unauthorized modifications.
- Initiate incident response protocols to contain potential breaches.
- Re-evaluate security controls around local groups in containers.

## Additional Resources

- **Local Groups Reconnaissance Via Wmic.EXE:** Explores using WMIC for group information gathering.
- **Use Short Name Path in Command Line:** Addresses the use of short names to bypass certain command-line restrictions.
- **Net.EXE Execution:** Discusses the utility and limitations of Net.EXE in managing user accounts and groups.

By following this detailed ADS framework, organizations can better prepare to detect and respond to adversarial attempts leveraging local group configurations within containerized environments.