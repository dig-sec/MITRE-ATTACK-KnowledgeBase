# Alerting & Detection Strategy (ADS) Report

## Goal
The primary goal of this technique is to detect adversarial attempts to bypass security monitoring using container snapshots. By identifying such activities, organizations can maintain robust security postures and prevent attackers from exploiting these methods to conceal their actions.

## Categorization
- **MITRE ATT&CK Mapping:** T1578.001 - Create Snapshot
- **Tactic / Kill Chain Phases:** Defense Evasion
- **Platforms:** IaaS

For more details, refer to the [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1578/001).

## Strategy Abstract
The detection strategy involves monitoring container lifecycle events and anomalies within cloud environments. By leveraging logs from container orchestrators (e.g., Kubernetes), we can identify unusual snapshot creation patterns indicative of adversarial behavior.

### Data Sources:
- **Container Orchestrator Logs:** Monitoring tools like Kubernetes audit logs.
- **Snapshot Activity Logs:** Capturing all snapshot creation, deletion, and modification events.
- **Network Traffic Analysis:** Analyzing traffic between containers to detect unauthorized data movement.

### Patterns Analyzed:
- Unusual frequency of snapshot creation from a single container.
- Snapshots being created during off-hours or periods with low legitimate activity.
- Discrepancies in file system states pre-and post-snapshot creation, indicating potential tampering.

## Technical Context
Adversaries may execute this technique by leveraging container management tools to create snapshots that they can later restore. These snapshots could be used to revert a compromised environment back to a state favorable for the attacker or to exfiltrate data without detection.

### Adversary Emulation Details:
- **Commands Used:** 
  - `kubectl exec <pod-name> -- sh -c "cp -R /path/to/data /backup"`
  - `docker commit <container-id>`
  - `docker save <image-name> | gzip > image.tar.gz`

- **Test Scenarios:**
  1. Create a container instance with sensitive data.
  2. Execute snapshot creation and store it locally or externally.
  3. Restore the snapshot to observe if security controls are bypassed.

## Blind Spots and Assumptions
- Assumes baseline behavior of legitimate snapshot usage is well-understood.
- Limited detection capability in environments where containers are not centrally managed.
- Assumes access to comprehensive logging from all relevant cloud services.

## False Positives
Potential benign activities that might trigger false alerts include:
- Regular backup operations by IT teams that also use container snapshots.
- Automated testing scenarios within development pipelines that involve snapshot creation and deletion.
- Legitimate usage of snapshots during high-availability configurations or disaster recovery plans.

## Priority
**Severity: Medium**

Justification: While the technique is not trivial for an attacker to exploit, its ability to aid in defense evasion poses a significant risk. The medium priority reflects the need to balance detection sensitivity with operational realities and avoid overwhelming analysts with false positives.

## Validation (Adversary Emulation)
### Step-by-Step Instructions:
1. **Setup:** Deploy a test Kubernetes cluster or use an existing one.
2. **Create Test Pod:**
   - `kubectl run test-pod --image=<your-image> --restart=Never`
3. **Execute Commands to Create Snapshots:**
   - `kubectl exec test-pod -- sh -c "cp -R /app/data /snapshot"`
4. **Commit and Save the Container Image:**
   - `docker commit $(docker ps | grep <test-pod> | awk '{print $1}') snapshot-test`
5. **Analyze Logs:** Observe logs for unexpected snapshot creation patterns.

Note: None available as this is a theoretical validation framework.

## Response
Upon alert firing:
- Immediately isolate the affected container instance to prevent further exploitation.
- Conduct a forensic analysis of snapshot data and associated logs.
- Review access controls and privileges assigned to containers and users involved in snapshot activities.
- Update incident response plans to include specific procedures for handling such alerts.

## Additional Resources
At this time, additional references or context are not available. Future updates may incorporate more comprehensive resources as they become relevant.

---

This report provides a structured approach to detecting adversarial use of container snapshots using the ADS framework, enabling organizations to strengthen their security monitoring capabilities effectively.