# Powershell Automated Windows Security Logging: Unified Forensic Security Analysis Suite
Powershell script that combines the three functionalities: basic forensic data collection, system logging (with analysis of successful logins), and a security report generator. All in one script. 

## DESCRIPTION
This script combines three security functions:
  1. Forensic Data Collection – gathers basic system, user, process, network, and event log info.
  2. System Logging & Analysis – collects today’s successful login events and performs a simple analysis.
  3. Security Report Generation – collects various logs (including Sysmon), parses/analyses them, and produces an HTML report.
  
## PS This script is a capstone project for Security Blue Team: PowerShell Course
  
The execution level is controlled by a single numeric parameter:
  - Level 1: Only forensic collection runs.
  - Level 2: Forensic plus system logging (with analysis) run.
  - Level 3 (or no parameter): All three features run.

## EXAMPLE
- Run all features (default Level = 3):
  .\AutomatedWindowsSecurityLog.ps1

- Run only forensic collection:
  .\AutomatedWindowsSecurityLog.ps1 -Level 1

- Run forensic + system logging/analysis:
  .\AutomatedWindowsSecurityLog.ps1 -Level 2

