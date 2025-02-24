<#
.SYNOPSIS
Powershell Automated Windows Security Logging – Unified Forensic & Security Analysis Suite

.DESCRIPTION
This script combines three security functions:
  1. Forensic Data Collection – gathers basic system, user, process, network, and event log info.
  2. System Logging & Analysis – collects today’s successful login events and performs a simple analysis.
  3. Security Report Generation – collects various logs (including Sysmon), parses/analyses them, and produces an HTML report.
  
.PS This script is a capstone project for Security Blue Team: PowerShell Course
  
The execution level is controlled by a single numeric parameter:
  - Level 1: Only forensic collection runs.
  - Level 2: Forensic plus system logging (with analysis) run.
  - Level 3 (or no parameter): All three features run.

.EXAMPLE
#Run all features (default Level = 3):
.\AutomatedWindowsSecurityLog.ps1

#Run only forensic collection:
.\AutomatedWindowsSecurityLog.ps1 -Level 1

#Run forensic + system logging/analysis:
.\AutomatedWindowsSecurityLog.ps1 -Level 2
#>

param(
    [Parameter(Position=0)]
    [int]$Level = 3
)

Write-Output "========================================================"
Write-Output "Powershell Automated Windows Security Logging – Unified Forensic & Security Analysis Suite"
Write-Output "Execution Level: $Level"
Write-Output "========================================================`n"

#-------------------------------------------
#Function: Forensic Data Collection
#-------------------------------------------
function Invoke-ForensicCollection {
    Write-Output "Starting Forensic Data Collection..."

    #Create directory for forensic files if it does not exist
    $forensicDir = "C:\Forensics"
    if (-not (Test-Path $forensicDir)) {
        New-Item -Path "C:\" -Name "Forensics" -ItemType "Directory" | Out-Null
    }

    #Collect system information
    Write-Output "Collecting system information..."
    $systemInfo = Get-ComputerInfo
    $systemInfo | Out-File -FilePath "$forensicDir\SystemInfo.txt"

    #Collect user information
    Write-Output "Collecting user information..."
    $userInfo = Get-LocalUser
    $userInfo | Out-File -FilePath "$forensicDir\UserInfo.txt"

    #Collect running processes
    Write-Output "Collecting running processes..."
    $processes = Get-Process
    $processes | Out-File -FilePath "$forensicDir\Processes.txt"

    #Collect network connections
    Write-Output "Collecting network connections..."
    $networkConnections = Get-NetTCPConnection
    $networkConnections | Out-File -FilePath "$forensicDir\NetworkConnections.txt"

    #Collect event logs (from System log)
    Write-Output "Collecting event logs..."
    $eventLogs = Get-EventLog -LogName System -Newest 100
    $eventLogs | Out-File -FilePath "$forensicDir\EventLogs.txt"

    Write-Output "Forensic data collection completed.`n"
}

#-------------------------------------------
#Function: System Logging and Analysis
#-------------------------------------------
function Invoke-SyslogCollectionAndAnalysis {
    Write-Output "Starting System Logging and Analysis..."

    $outputPath = "C:\SecurityLogs"
    #Create directory if it does not exist
    if (-not (Test-Path -Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }

    #Get current date and define time window for today
    $currentDate = Get-Date -Format "yyyyMMdd"
    $startTime = (Get-Date).Date
    $endTime = (Get-Date).Date.AddDays(1).AddSeconds(-1)

    #Define filter for Security log events with ID 4624 (successful login)
    $filterHashtable = @{
        LogName   = "Security"
        ID        = 4624
        StartTime = $startTime
        EndTime   = $endTime
    }

    #Collect the events and export them to XML
    $events = Get-WinEvent -FilterHashtable $filterHashtable
    if ($events) {
        $xmlFile = "$outputPath\$currentDate-SecurityLogs.xml"
        $events | Export-CliXml -Path $xmlFile
        Write-Host "Security logs for successful logins on $currentDate have been collected and saved to: $outputPath" -ForegroundColor Green
    }
    else {
        Write-Host "No security logs for successful logins found for $currentDate." -ForegroundColor Yellow
    }

    #--- Analyze the collected XML logs ---
    $inputPath = $outputPath
    if (-not (Test-Path -Path $inputPath)) {
        Write-Host "The specified input path does not exist." -ForegroundColor Red
        return
    }

    $xmlFiles = Get-ChildItem -Path $inputPath -Filter "*.xml"
    if ($xmlFiles.Count -eq 0) {
        Write-Host "No XML files found for analysis." -ForegroundColor Yellow
        return
    }

    #Initialize counter for successful login events
    $successfulLoginCount = 0

    foreach ($file in $xmlFiles) {
        [xml]$xmlContent = Get-Content -Path $file.FullName
        #Count events with ID 4624
        $count = ($xmlContent.Objs.Obj | Where-Object { $_.Props.I32.N -eq "Id" -and $_.Props.I32."#text" -eq "4624" }).Count
        $successfulLoginCount += $count
    }

    Write-Host "Total successful logins today: $successfulLoginCount" -ForegroundColor Green
    Write-Output "System logging and analysis completed.`n"
}

#-------------------------------------------
#Function: Security Report Generation
#-------------------------------------------
function Invoke-SecurityReportGeneration {
    Write-Output "Starting Security Report Generation..."

    $outputDir = "C:\SecurityLogs"
    #Ensure output directory exists
    if (-not (Test-Path -Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    #Define the log sources to collect and export as CSV
    $logSources = @("System", "Application", "Security")
    foreach ($source in $logSources) {
        $logs = Get-EventLog -LogName $source -Newest 1000
        $logs | Export-Csv -Path "$outputDir\$source.csv" -NoTypeInformation
    }

    #Sysmon logs
    $sysmonLogs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000
    $sysmonLogs | Export-Csv -Path "$outputDir\Sysmon.csv" -NoTypeInformation

    function Parse-Log {
        param([string]$logFile)
        $logData = Import-Csv -Path $logFile
        foreach ($entry in $logData) {
            $eventID = $entry.EventID
            $timeGenerated = $entry.TimeGenerated
            $message = $entry.Message
            Write-Output "EventID: $eventID, Time: $timeGenerated, Message: $message"
        }
    }

    function Analyze-Log {
        param([string]$logFile)
        $logData = Import-Csv -Path $logFile
        foreach ($entry in $logData) {
            $eventID = $entry.EventID
            $timeGenerated = $entry.TimeGenerated
            $message = $entry.Message
            if ($eventID -in 4625, 4648, 4688, 4689, 4768) {
                Write-Output "Potential Security Incident: EventID $eventID at $timeGenerated - $message"
            }
        }
    }

    function Generate-Report {
        param([string]$reportFile)
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Log Analysis Report</title>
</head>
<body>
    <h1>Security Log Analysis Report</h1>
    <table border="1">
        <tr>
            <th>EventID</th>
            <th>Time</th>
            <th>Message</th>
        </tr>
"@
        $logFiles = Get-ChildItem -Path $outputDir -Filter *.csv
        foreach ($logFile in $logFiles) {
            $logData = Import-Csv -Path $logFile.FullName
            foreach ($entry in $logData) {
                $eventID = $entry.EventID
                $timeGenerated = $entry.TimeGenerated
                $message = $entry.Message
                if ($eventID -in 4625, 4648, 4688, 4689, 4768) {
                    $html += "<tr><td>$eventID</td><td>$timeGenerated</td><td>$message</td></tr>"
                }
            }
        }
        $html += @"
    </table>
</body>
</html>
"@
        $html | Out-File -FilePath $reportFile
    }

    #Parse and analyze CSV log file
    $logFiles = Get-ChildItem -Path $outputDir -Filter *.csv
    foreach ($logFile in $logFiles) {
        Parse-Log -logFile $logFile.FullName
        Analyze-Log -logFile $logFile.FullName
    }

    #HTML report
    $reportFile = "C:\SecurityLogs\AnalysisReport.html"
    Generate-Report -reportFile $reportFile
    Write-Output "Security report generated at: $reportFile"
    Write-Output "Security Report Generation completed.`n"
}

#-------------------------------------------
#Main Execution Logic
#-------------------------------------------
#By default (Level = 3) all features are executed.
#Level 1: Only forensic; Level 2: Forensic + Syslog/Analysis; Level 3: All three.
if ($Level -ge 1) {
    Invoke-ForensicCollection
}
if ($Level -ge 2) {
    Invoke-SyslogCollectionAndAnalysis
}
if ($Level -eq 3) {
    Invoke-SecurityReportGeneration
}

Write-Output "`nAll selected tasks have been executed."
