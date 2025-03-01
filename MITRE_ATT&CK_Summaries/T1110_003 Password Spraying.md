# Alerting & Detection Strategy (ADS) Report: Detect Adversarial Attempts to Bypass Security Monitoring Using Containers

## Goal

The primary goal of this detection strategy is to identify adversarial attempts aimed at bypassing security monitoring mechanisms through the misuse of container technologies. Specifically, we focus on detecting credential access techniques like password spraying that could be leveraged within or across containerized environments.

## Categorization

- **MITRE ATT&CK Mapping:** T1110.003 - Password Spraying
- **Tactic / Kill Chain Phases:** Credential Access
- **Platforms:** Windows, Azure AD, Office 365, SaaS, IaaS, Linux, macOS, Google Workspace, Containers
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1110/003)

## Strategy Abstract

The detection strategy utilizes a combination of log data from container orchestration platforms (e.g., Kubernetes), authentication logs from identity providers (such as Azure AD and Office 365), and system event logs across various OS platforms. The pattern analysis focuses on identifying multiple failed login attempts using a limited set of passwords, which is characteristic of password spraying attacks.

Key data sources include:
- Container orchestration platform logs
- Identity provider authentication logs
- System and security event logs from endpoints

Patterns analyzed involve rapid sequential failures that suggest systematic credential testing rather than random brute force or individual account targeting. These patterns help in pinpointing potential password spray activities within a containerized environment.

## Technical Context

In real-world scenarios, adversaries may use containers to conduct password spraying by spinning up multiple instances of a service with different credentials rapidly. This can complicate detection due to the ephemeral nature of containers and their distribution across clusters or cloud environments. Adversaries might leverage automation scripts or tools like `Kerbrute` or `WinPwn` to perform these attacks.

Adversary emulation details:
- Tools such as `Invoke-DomainPasswordSpray`, `MSOLSpray`, and `GoAWSConsoleSpray` can be used to simulate password spraying in controlled environments.
- Commands may include iterating over user accounts with common passwords across multiple nodes or services within a containerized setup.

## Blind Spots and Assumptions

- **Blind Spots:** Detection might miss highly distributed attacks that are spread out temporally, making them appear as normal login attempts. Additionally, if adversaries use sophisticated evasion techniques such as rate limiting to avoid detection thresholds, the spray could go unnoticed.
  
- **Assumptions:** We assume that all container orchestration platforms and identity providers expose sufficient logging detail for analysis. The effectiveness of the strategy also assumes consistent log retention policies across environments.

## False Positives

Potential benign activities triggering false alerts include:
- System administrators performing routine password resets or audits with multiple credentials.
- Automated scripts configured by developers to test authentication processes without malicious intent.
- Users attempting to reset passwords from different devices within a short time frame, leading to temporary spikes in failed login attempts.

## Priority

**Priority:** High  
**Justification:** Password spraying is a common and effective technique for gaining unauthorized access, especially in environments with weak password policies. The ability of adversaries to leverage containerized setups for such attacks increases the risk significantly due to potential rapid lateral movement within networks if successful.

## Validation (Adversary Emulation)

To validate this detection strategy, follow these emulation steps in a controlled test environment:

1. **Password Spray all Domain Users:**
   - Use `Invoke-DomainPasswordSpray` to attempt login with multiple common passwords against domain users.
   
2. **Azure AD and Office 365:**
   - Execute `MSOLSpray` to perform password spraying on Azure Active Directory or Office 365 accounts.

3. **Kerbrute Tool Usage:**
   - Utilize the `Kerbrute` tool for Kerberos-based password spray attacks against domain controllers.

4. **AWS Environment Simulation:**
   - Deploy `GoAWSConsoleSpray` to simulate password spraying on AWS console login attempts.

Each of these steps should be conducted in isolation with robust monitoring to capture and analyze logs generated during the attack emulation process.

## Response

Upon detection of a potential password spray event:
- Immediately alert security analysts for investigation.
- Temporarily block affected accounts or IP addresses if feasible, pending further analysis.
- Investigate login patterns and correlate with other suspicious activities (e.g., unusual container activity).
- Review access controls and strengthen password policies to mitigate future risks.

## Additional Resources

As of now, no additional references are available. Future updates may include case studies or whitepapers detailing real-world detection and mitigation scenarios for adversarial use of containers in such attacks.