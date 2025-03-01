# Palantir's Alerting & Detection Strategy: Multi-hop Proxy (T1090.003)

## Goal
The goal of this detection strategy is to identify adversarial attempts to bypass security monitoring through the use of multi-hop proxies. This approach allows attackers to obfuscate their Command and Control (C2) communications by routing traffic through multiple intermediary nodes.

## Categorization

- **MITRE ATT&CK Mapping:** T1090.003 - Multi-hop Proxy
- **Tactic / Kill Chain Phases:** Command and Control
- **Platforms:** Linux, macOS, Windows, Network
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1090/003)

## Strategy Abstract

The detection strategy focuses on identifying patterns indicative of multi-hop proxy usage across various data sources such as network traffic logs, host-based event logs, and DNS request logs. Key indicators include:

- Unusual sequences of IP addresses involved in network sessions.
- Anomalous changes in communication patterns or timing.
- Excessive use of encryption protocols not typical for the environment.

## Technical Context

Adversaries leverage multi-hop proxies to disguise their C2 infrastructure by routing traffic through multiple intermediaries. This complicates tracking and can evade detection systems that monitor direct IP communications. Common tools used include Tor and Psiphon, which anonymize internet activity across various nodes.

### Adversary Emulation Details:
- **Sample Commands:**
  - *Tor Usage:* `tor --socks-port 9050`
  - *Psiphon Usage (Mac):* `./psiphon3`

- **Test Scenarios:** 
  - Configure a Tor network with multiple relays and route traffic through it.
  - Set up Psiphon client on a test machine to simulate anonymized access.

## Blind Spots and Assumptions

- **Blind Spots:**
  - Difficulty in distinguishing between legitimate privacy-enhancing tools and malicious proxy use.
  - High false positive potential in environments with frequent network changes or diverse user roles.

- **Assumptions:**
  - The environment has a baseline of normal network behavior to detect anomalies effectively.
  - Network monitoring infrastructure is capable of capturing detailed traffic logs across all platforms.

## False Positives

Potential benign activities that could trigger alerts include:

- Legitimate use of Tor by privacy-conscious users.
- Internal systems configured for enhanced security measures using proxy layers.
- Routine software updates or network configuration changes involving multiple nodes.

## Priority
**High:** The severity is assessed as high due to the technique's effectiveness in obscuring adversary actions, making it a critical threat vector for maintaining secure and monitored environments.

## Validation (Adversary Emulation)

### Psiphon

1. Download and install Psiphon on a test machine.
2. Configure network settings to route traffic through Psiphon’s proxy server.
3. Monitor for unexpected changes in DNS requests or unusual IP patterns.

### Tor Proxy Usage - Windows

1. Install the Tor Browser Bundle from the official website.
2. Start Tor with `tor --fingerprint` and verify connection status.
3. Observe network traffic to detect routing through multiple nodes.

### Tor Proxy Usage - Debian/Ubuntu/FreeBSD

1. Update package list: `sudo apt update`
2. Install Tor: `sudo apt install tor`
3. Enable Tor service: `sudo systemctl start tor`
4. Verify the proxy with `curl --socks5 localhost:9050 https://check.torproject.org`

### Tor Proxy Usage - MacOS

1. Download and install the Tor Browser from its official site.
2. Launch the browser to initiate Tor routing.
3. Analyze network logs for multi-hop characteristics.

## Response

When an alert is triggered, analysts should:

1. Verify if the source of the traffic corresponds with known benign activity or privacy tools usage.
2. Investigate any anomalous patterns in IP sequences and timing deviations.
3. Correlate findings with other potential indicators of compromise (IoCs) within the environment.

## Additional Resources

Additional references and context are currently not available, but ongoing research into multi-hop proxy detection techniques is recommended to stay updated on evolving adversary methods.