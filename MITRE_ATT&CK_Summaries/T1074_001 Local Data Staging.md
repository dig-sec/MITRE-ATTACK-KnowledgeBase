# Alerting & Detection Strategy (ADS) Report: Local Data Staging via Containers

## Goal
The goal of this detection strategy is to identify adversarial attempts that bypass security monitoring by using containers for local data staging on Linux, macOS, and Windows systems.

## Categorization
- **MITRE ATT&CK Mapping:** T1074.001 - Local Data Staging
- **Tactic / Kill Chain Phases:** Collection
- **Platforms:** Linux, macOS, Windows
- [MITRE ATT&CK Reference](https://attack.mitre.org/techniques/T1074/001)

## Strategy Abstract
The detection strategy leverages a combination of data sources such as system logs, process monitoring, network traffic analysis, and file integrity checks to identify patterns associated with local data staging via containers. Key indicators include unusual container activity, unexpected processes interacting with sensitive files or directories, and anomalous network connections.

### Data Sources:
- System Logs: Monitor for signs of unauthorized container deployment.
- Process Monitoring: Identify suspicious process execution related to container management tools.
- Network Traffic: Analyze for atypical data transfer patterns involving containers.
- File Integrity: Track changes in file permissions or contents within container environments.

## Technical Context
Adversaries may use containers to stage data locally by deploying lightweight, isolated environments that can be rapidly spun up and torn down. This helps them bypass traditional monitoring tools, which might not have visibility into these transient environments.

### Real-World Execution:
Adversaries execute this technique using popular containerization platforms such as Docker or Kubernetes. They may use containers to manipulate data stealthily before exfiltrating it. Commonly observed adversary tactics include:

- Deploying containers that mimic benign system processes.
- Utilizing scripts like `Discovery.sh` on Linux or `Discovery.bat` on Windows to stage data within a container environment.
- Leveraging PowerShell commands such as `Compress-Archive` for data manipulation and staging.

### Adversary Emulation:
- Use of `docker run --rm -it ubuntu /bin/bash` to launch ephemeral containers.
- Execution of scripts like `curl` on Linux or `Invoke-WebRequest` in PowerShell to interact with external resources from within the container.

## Blind Spots and Assumptions
- The detection strategy may not fully cover custom-built container orchestration tools developed by adversaries.
- Assumes that containers are deployed using standard platforms like Docker, potentially missing unconventional implementations.
- Limited visibility into encrypted data transfers could obscure some staging activities.

## False Positives
Potential false positives include:
- Legitimate IT operations involving container deployments for software development or testing purposes.
- Routine administrative tasks executed within containers by authorized users.
- Automated scripts that are part of legitimate backup or update processes.

## Priority
**High.** The technique's ability to evade traditional monitoring mechanisms makes it a critical threat vector, especially in environments with sensitive data handling requirements.

## Validation (Adversary Emulation)
To emulate this technique in a test environment:

1. **Stage Data from Discovery.bat**
   - Run `Discovery.bat` within a container using the command:
     ```bash
     docker run --rm -v C:\path\to\batch:C:\container\path mcr.microsoft.com/windows/servercore:ltsc2019 cmd /c "C:\container\path\Discovery.bat"
     ```

2. **Stage Data from Discovery.sh**
   - Execute `Discovery.sh` in a Linux container:
     ```bash
     docker run --rm -v /host/path/to/script:/container/path ubuntu /bin/bash -c "/container/path/Discovery.sh"
     ```

3. **Zip a Folder with PowerShell for Staging in Temp**
   - Use PowerShell within a Windows-based container:
     ```bash
     powershell.exe -Command "docker run --rm -v C:\host\folder:C:\container\folder mcr.microsoft.com/windows/servercore:ltsc2019 powershell -Command 'Compress-Archive -Path C:\container\folder\* -DestinationPath C:\temp\staged.zip'"
     ```

## Response
When an alert triggers:
- Immediately isolate the affected system to prevent further data staging or exfiltration.
- Review process logs and network activity for signs of unauthorized container operations.
- Conduct a thorough investigation into file modifications within known container paths.
- Collaborate with incident response teams to assess potential impacts on data integrity.

## Additional Resources
- Curl Usage on Linux: [Linux Curl Guide](https://curl.se/docs/manual.html)
- Linux Shell Pipe to Shell: [Bash Piping Techniques](https://www.tldp.org/LDP/Bash-Beginners-Guide/html/sect_10_03.html)
- Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet: [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.1)
- Usage Of Web Request Commands And Cmdlets: [Invoke-WebRequest Reference](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1)
- PowerShell Web Download: [PowerShell Downloader Techniques](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Download.ps1)
- Suspicious Invoke-WebRequest Execution: [Identifying Malicious Web Requests in PowerShell](https://cyberdefenders.com/suspicious-powershell-web-request-execution)