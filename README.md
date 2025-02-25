# Powershell Automated Windows Security Logging: Unified Forensic Security Analysis Suite
Powershell script that combines the three functionalities: basic forensic data collection, system logging (with analysis of successful logins), and a security report generator. All in one script. 

## DESCRIPTION
This script performs three security functions:
  1. Forensic Collection: Gathers system info, local users, processes, network connections, and recent system event logs.
  2. Syslog Analysis: Collects today’s successful login events (Event ID 4624) and outputs a summary.
  3. Security Report: Exports logs from several sources (System, Application, Security, and Sysmon) to CSV files and generates an HTML report.

The execution level is determined by the numeric parameter:
  - Level 1: Forensic Collection only.
  - Level 2: Forensic Collection and Syslog Analysis.
  - Level 3 (or unspecified): All three functions are executed.

## PS
This script is a capstone project for Security Blue Team: PowerShell Course. Some constructs used in this script were based on their powershell course.

## EXAMPLE
- Run all features (default Level = 3):
   ```bash
   .\AutomatedWindowsSecurityLog.ps1
   ```
- Run only forensic collection:
   ```bash
   .\AutomatedWindowsSecurityLog.ps1 -Level 1
   ```
- Run forensic + system logging/analysis:
   ```bash
   .\AutomatedWindowsSecurityLog.ps1 -Level 2
   ```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/C0deRhin0/Windows-Poweshell-Unified-Forensic-Security-Analysis-Suite.git
   ```

2. Navigate to the project directory:
   ```bash
   cd Windows-Poweshell-Unified-Forensic-Security-Analysis-Suite
   ```

3. Running the script:
   Refer to "Example" section

## License
This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- This project was inspired by and utilizes concepts from the Security Blue Team PowerShell course.
- Special thanks to the Security Blue Team for providing excellent training and resources.

## Contact

For any inquiries or support, please contact:

- **Author**: C0deRhin0 
- **GitHub**: [C0deRhin0](https://github.com/C0deRhin0)

---
