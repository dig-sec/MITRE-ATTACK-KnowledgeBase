# Alerting & Detection Strategy: Detect Adversarial Use of WMI Event Subscription for Persistence on Windows Systems

## Goal
This strategy aims to detect adversarial attempts to establish persistence by using Windows Management Instrumentation (WMI) event subscriptions. Attackers may leverage this technique to execute malicious scripts or commands when specific events occur, facilitating ongoing access and control over the compromised system.

## Categorization

- **MITRE ATT&CK Mapping:** T1546.003 - Windows Management Instrumentation Event Subscription
- **Tactic / Kill Chain Phases:** Privilege Escalation, Persistence
- **Platforms:** Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1546/003)

## Strategy Abstract
The detection strategy focuses on identifying WMI event subscriptions that are configured to execute commands or scripts, which could indicate adversarial attempts at persistence. Data sources include system event logs and WMI repository data. The analysis involves searching for anomalous or unauthorized WMI event subscriptions, particularly those using `CommandLineEventConsumer` and `ActiveScriptEventConsumer`, as these consumers can execute arbitrary commands.

## Technical Context
Adversaries exploit the flexibility of WMI to listen for specific events on a Windows system and trigger actions in response. This technique involves creating WMI event subscriptions that use consumers like `CommandLineEventConsumer` or `ActiveScriptEventConsumer`. These consumers allow the execution of command-line scripts or PowerShell commands upon triggering an event.

### Execution Details
- **CommandLineEventConsumer:** Executes specified command line instructions.
- **ActiveScriptEventConsumer:** Runs a script, often PowerShell, when an event is triggered.

Adversaries may use tools like MOFComp.exe to compile and load Managed Object Format (MOF) files containing WMI subscription definitions. For example, they might execute `mofcomp mysubscription.mof` to register a persistent event handler on the system.

## Blind Spots and Assumptions
- **Blind Spots:** Limited visibility into legitimate administrative scripts that may use similar patterns but are benign.
- **Assumptions:** Assumes all detected WMI subscriptions not originating from approved sources or activities might be adversarial, which can overlook some authorized configurations.

## False Positives
Potential benign activities include:
- Legitimate administrative tasks using `CommandLineEventConsumer` for monitoring and maintenance.
- Valid software installations that configure WMI event subscriptions as part of their setup process.

## Priority
**High:** This technique poses a significant threat due to its stealth and potential impact on system persistence. Unauthorized access maintained through this method can lead to further exploitation, data exfiltration, or additional compromises within the network.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Persistence via WMI Event Subscription - CommandLineEventConsumer:**
   - Create a MOF file `mysubscription.mof` with an event subscription that triggers a benign command.
     ```mof
     instance of __EventFilter as $EventFilter
     {
         Name = "MyEventFilter";
         Query = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'";
     };

     instance of CommandLineEventConsumer as $CommandLineConsumer
     {
         Name = "MyCommandLineConsumer";
         Commandline = "echo Test Command >> C:\\temp\\test.txt";
     };

     instance of __FilterToConsumerBinding as $Binding
     {
         Filter = $EventFilter;
         Consumer = $CommandLineConsumer;
     };
     ```

2. **Persistence via WMI Event Subscription - ActiveScriptEventConsumer:**
   - Modify the MOF file to use an `ActiveScriptEventConsumer`:
     ```mof
     instance of __EventFilter as $EventFilter
     {
         Name = "MyEventFilter";
         Query = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'";
     };

     instance of ActiveScriptEventConsumer as $ScriptConsumer
     {
         Name = "MyActiveScriptConsumer";
         ScriptText =
             "echo Test PowerShell command >> C:\\temp\\test.txt";
         Language = "WQL";
     };

     instance of __FilterToConsumerBinding as $Binding
     {
         Filter = $EventFilter;
         Consumer = $ScriptConsumer;
     };
     ```

3. **Windows MOFComp.exe Load MOF File:**
   - Compile and register the MOF file:
     ```shell
     mofcomp mysubscription.mof
     ```
   - Verify persistence by triggering a process creation event or executing a scheduled task that matches the filter query.

## Response
When an alert for WMI event subscription is triggered, analysts should:

1. **Verify Source:** Determine if the source of the subscription is from known and authorized users or processes.
2. **Assess Impact:** Evaluate what commands or scripts are executed by these subscriptions to understand potential impact.
3. **Containment:** If malicious, isolate affected systems to prevent further spread.
4. **Remediation:** Remove unauthorized WMI event subscriptions and strengthen system monitoring policies.

## Additional Resources
- [Potential Suspicious MOFComp Execution](https://example.com/mofcomp-detection)
- [WMI Event Subscription Detection Guide](https://example.com/wmi-event-subscription-guide)

This strategy provides a comprehensive approach to identifying and mitigating the risk of adversarial use of WMI for persistence on Windows systems, helping organizations maintain robust security postures.