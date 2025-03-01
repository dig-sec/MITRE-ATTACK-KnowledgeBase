# Palantir's Alerting & Detection Strategy (ADS) Framework Report

## Goal
The primary goal of this detection strategy is to identify adversarial attempts aimed at bypassing security monitoring mechanisms through the use of container technologies.

## Categorization
- **MITRE ATT&CK Mapping:** T1612 - Build Image on Host
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** Containers

[MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1612)

## Strategy Abstract
This detection strategy focuses on monitoring and analyzing activities related to building container images directly on host systems. Key data sources include system logs, Docker or container runtime logs, network traffic patterns, and file integrity monitoring solutions. The analysis looks for anomalies such as unusual build commands executed by unauthorized users, unexpected image creation times, or discrepancies in image tags that could suggest malicious intent.

## Technical Context
Adversaries may exploit the flexibility of containers to evade detection by constructing images on the host. This allows them to customize environments and include malicious binaries without being detected by standard container scanning tools. In practice, adversaries might use native OS tools like Docker CLI or direct manipulation of image layers to achieve their goals.

### Adversary Emulation Details
- **Sample Commands:**
  - `docker build -t adversary_image .`
  - Direct modification of Dockerfiles and subsequent build using unauthorized scripts.
  
- **Test Scenarios:**
  - Simulate an unauthorized user executing container builds on a host system.
  - Modify image files directly on disk to avoid detection by traditional scanning tools.

## Blind Spots and Assumptions
- **Known Limitations:** 
  - Detection may not cover images built using non-standard or custom-built container runtimes.
  - Assumes that all unauthorized build activities are malicious, potentially missing legitimate but unlogged operations.
  
- **Assumptions:**
  - Host systems are equipped with adequate logging mechanisms to capture relevant data.
  - Security teams have predefined baselines for normal image build behavior.

## False Positives
Potential benign activities that might trigger false alerts include:
- Legitimate developers building images as part of their workflow but failing to follow established authorization protocols.
- Automated CI/CD pipelines executing builds without proper logging or documentation.

## Priority
**Priority Level: Medium**

Justification: While the technique poses significant risks by enabling adversaries to bypass traditional monitoring, its impact is mitigated when organizations have strong baseline detection and response frameworks in place. However, it remains a critical vector for evasion that warrants attention due to its potential for misuse.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Environment Setup:**
   - Deploy a test environment with Docker or another container runtime installed on the host.
   
2. **Simulate Unauthorized Build:**
   - Execute the command `docker build -t adversary_image .` from an account not typically authorized to perform such actions.

3. **Direct Layer Manipulation:**
   - Alter existing image layers directly in `/var/lib/docker/overlay2` or equivalent directory without using Docker CLI commands.

4. **Log Analysis:**
   - Verify that the build activity is logged and analyze logs for unauthorized access patterns.

## Response
When an alert fires, analysts should:
- Immediately isolate affected systems to prevent further unauthorized builds.
- Conduct a thorough review of container images built during the suspicious period.
- Assess whether compromised images have been deployed or run in any environments.
- Update security policies to enforce stricter controls on image building activities.

## Additional Resources
Additional references and context are currently unavailable. Further research and case studies could provide deeper insights into real-world exploitation scenarios and effective countermeasures.

---

This report outlines the ADS framework for detecting adversaries attempting to bypass security through container technologies, emphasizing practical steps for detection, validation, and response.