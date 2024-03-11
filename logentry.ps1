param ([string]$LogMessage, [string]$LogFile)
    try {
        $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "$TimeStamp - $LogMessage"  
        Add-Content -Path $LogFile -Value $LogEntry
    }
    catch {
        Write-Error "Error occurred while writing to the log file: $_"
    }