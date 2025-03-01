# Alerting & Detection Strategy: Detecting Adversarial Use of Unix Shells (T1059.004)

## **Goal**
This detection strategy aims to identify adversarial attempts to use Unix shells for executing commands and scripts on macOS and Linux platforms, which may be employed to bypass security monitoring systems.

## **Categorization**
- **MITRE ATT&CK Mapping:** T1059.004 - Unix Shell
- **Tactic / Kill Chain Phases:** Execution
- **Platforms:** macOS, Linux
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1059/004)

## **Strategy Abstract**
The strategy leverages various data sources such as system logs, command-line activity, and process monitoring to detect suspicious usage of Unix shells. Patterns analyzed include the creation and execution of shell scripts, invocation of uncommon or obfuscated commands, changes in login shell settings, and unusual environment variables.

### Data Sources:
- **System Logs:** Audit logs for process creations, file modifications.
- **Command-Line Activity Monitoring:** Tracking command history and usage patterns.
- **Process Monitoring:** Observing processes spawned by shell invocations.

## **Technical Context**
Adversaries often use Unix shells to execute commands, manipulate the environment, or escalate privileges. They may employ techniques such as using scripts hidden in uncommon directories, obfuscating commands with tools like `awk` or `cpan`, and leveraging SUID executables for privilege escalation.

### Real-World Execution:
Adversaries might download and execute bash shell scripts to automate malicious activities or use environment variable manipulation to bypass security controls. They may also utilize utilities such as LinEnum to gather system information stealthily.

## **Blind Spots and Assumptions**
- Assumes that all logs are consistently captured and stored, which might not be the case in some environments.
- Relies on predefined baseline activity patterns; new or sophisticated evasion techniques could go undetected.
- Requires comprehensive monitoring of various data sources, potentially impacting performance.

## **False Positives**
Potential benign activities that may trigger false alerts include:
- Legitimate use of shell scripts for routine tasks.
- System administration tools using shell scripting.
- Developers executing command-line utilities in development environments.

## **Priority**
**High:** The Unix Shell technique is commonly used by adversaries to execute commands and scripts, making it a high-priority detection target due to its potential impact on system security.

## **Validation (Adversary Emulation)**
### Step-by-Step Instructions:
1. **Create and Execute Bash Shell Script:**
   - Write a script (`malicious.sh`) with benign commands.
   - Execute using `bash malicious.sh`.

2. **Command-Line Interface:**
   - Directly execute suspicious commands like `sudo <command>`.

3. **Harvest SUID Executable Files:**
   - Identify and list SUID files with `find / -perm -4000 2>/dev/null`.

4. **LinEnum Tool Execution:**
   - Download and run LinEnum to enumerate system information.

5. **New Script File in the tmp Directory:**
   - Create a script file (`tmp/malicious.sh`) and execute it.

6. **What Shell is Running:**
   - Use `echo $SHELL` to determine the current shell.

7. **What Shells are Available:**
   - List shells with `cat /etc/shells`.

8. **Command Line Scripts:**
   - Run scripts directly from the command line.

9. **Obfuscated Command Line Scripts:**
   - Use tools like `awk`, `cpan` to obfuscate commands and execute them.

10. **Change Login Shell:**
    - Change shell using `chsh -s /bin/bash`.

11. **Environment Variable Scripts:**
    - Manipulate environment variables with `export VAR=value; <command>`.

12. **Detecting Pipe-to-Shell:**
    - Monitor for commands piped into a shell, e.g., `find . -type f | xargs rm`.

13. **Current Kernel Information Enumeration:**
    - Use tools like `uname -a` to gather kernel details.

14. **Shell Creation using awk Command:**
    - Create a shell with `awk 'BEGIN {system("/bin/sh")}'`.

15. **Creating Shell using cpan Command:**
    - Execute `cpan -e 'exec "/bin/bash";'`.

16. **emacs Spawning an Interactive System Shell:**
    - Launch emacs with the option to run commands.

## **Response**
Upon detecting suspicious shell activity, analysts should:
- Immediately isolate affected systems.
- Review logs for additional context and indicators of compromise.
- Verify the legitimacy of detected scripts and commands.
- Update detection rules based on findings to improve future response.

## **Additional Resources**
- [Curl Usage on Linux](https://curl.se/docs/manual.html)
- [Linux Shell Pipe to Shell](https://www.shellscript.sh/)
- [Suspicious Invocation of Shell via AWK - Linux](https://linux.die.net/man/1/awk)

By following this strategy, organizations can enhance their detection capabilities against adversarial use of Unix shells on macOS and Linux systems.