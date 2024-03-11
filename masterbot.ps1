########################################################################################
    # Creating folder path constant 
    ########################################################################################
    $botFolderPath = (Resolve-Path "..\..").Path
    $confFolderPath = Join-Path -Path $botFolderPath -ChildPath "conf"
    $configFolderPath = Join-Path -Path $confFolderPath -ChildPath "Config"
    $configFilePath = Join-Path -Path $configFolderPath -ChildPath "config.json"
    $credsFolderPath = Join-Path -Path $confFolderPath -ChildPath "Creds"
    $licenseFolderPath = Join-Path -Path $confFolderPath -ChildPath "License"
    $inputFolderPath = Join-Path -Path $botFolderPath -ChildPath "input"
    $outputFolderPath = Join-Path -Path $botFolderPath -ChildPath "output"
    $logFolderPath = Join-Path -Path $botFolderPath -ChildPath "log"
    $scriptsFolderPath = Join-Path -Path $botFolderPath -ChildPath "scripts"
    $masterbotFolderPath = Join-Path -Path $scriptsFolderPath -ChildPath "MasterBot"
    $microbotFolderPath = Join-Path -Path $scriptsFolderPath -ChildPath "MicroBots"
    $serverList = Join-Path -Path $inputFolderPath -ChildPath "\serverList.txt"

    # Get data from config.json file
    $configFile = Get-content -Path $configFilePath |  ConvertFrom-Json

    # Define log microbot
    $logEntryMicroBotFilePath =  Join-Path -Path $microbotFolderPath -ChildPath "logentry.ps1"

  

    # Define key and license file path
    $secretkeyFIlePath = Join-Path -Path $credsFolderPath -ChildPath "secretkey.txt"
    $vectorkeyFilePath = Join-Path -Path $credsFolderPath -ChildPath "vectorkey.txt"
    $licenseFilePath = Join-Path -Path $licenseFolderPath -ChildPath "license.txt"

    # Output file destination
    $outputHTMLFilePath = Join-Path -Path $outputFolderPath -ChildPath $configFile.outputHTMLFileName
    $outputLogFilePath = Join-Path -Path $logFolderPath -ChildPath $configFile.logFileName

    ########################################################################################
    #################### Decrypting key and password ####################
    ########################################################################################

    function decryptkey {
        param (
            [string]$filePath
        )
        [Byte[]] $uniqueKey = (5, 7, 82, 19, 252, 25, 7, 88, 19, 253, 11, 254, 3, 10, 15, 20)
        $output = Get-Content $filePath -Raw | ConvertTo-SecureString -Key $uniqueKey
        $decryptedText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($output))
        return $decryptedText
    }

    ########################################################################################
    #################### Checking License ####################
    ########################################################################################
    $secretKey = decryptkey -filePath $secretkeyFilePath
    $vectorKey = decryptkey -filePath $vectorkeyFilePath
    

    $global:currentDate = Get-Date
    $encryptionKey = [System.Text.Encoding]::UTF8.GetBytes($secretKey)
    $ivBytes = [System.Text.Encoding]::UTF8.GetBytes($vectorKey)
    # Decrypt and Validate License from the file
    $encryptedLicenseInfo = Get-Content -Path $licenseFilePath -Encoding Byte
    $decryptedLicenseInfo = $null
    try {
        $decryptedLicenseInfo = [System.Security.Cryptography.Aes]::Create() | ForEach-Object {
            $_.Key = $encryptionKey
            $_.IV = $ivBytes
            $_.Mode = [System.Security.Cryptography.CipherMode]::CBC  # Use CBC mode
            $_.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $_.CreateDecryptor().TransformFinalBlock($encryptedLicenseInfo, 0, $encryptedLicenseInfo.Length)
        }
        if ($decryptedLicenseInfo) {
            $decryptedLicenseInfo = [System.Text.Encoding]::UTF8.GetString($decryptedLicenseInfo)
            $licenseData = $decryptedLicenseInfo | ConvertFrom-Json
            if ([DateTime]::Parse($licenseData.StartDate) -le $global:currentDate -and [DateTime]::Parse($licenseData.ExpiryDate) -ge $currentDate) { 
                $global:daysRemaining = [math]::Ceiling(([DateTime]::Parse($licenseData.ExpiryDate) - $global:currentDate ).Totaldays)
                Write-Host "Days Remaining: $daysRemaining"
                & $logEntryMicroBotFilePath "SUCCESS - License Validation Complete!! Valid From: $($licenseData.StartDate) Valid Until: $($licenseData.ExpiryDate)" -LogFile $outputLogFilePath
            }
            elseif ([DateTime]::Parse($licenseData.StartDate) -lt $global:currentDate) {
            }
        }
        else {
            Write-Host "License has expired."
            & $logEntryMicroBotFilePath "ERROR - License Expired!!" -LogFile $outputLogFilePath
            exit
        }
    } 
    catch {
        Write-Host "An error occurred while decrypting the license: $_append"
        & $logEntryMicroBotFilePath "ERROR -  While Loading License File!!" -LogFile $outputLogFilePath
        exit
    }



    #Fetching credentials from credential manager

    $userName = (Get-StoredCredential -Target "serverdetails").UserName
    $password = (Get-StoredCredential -Target "serverdetails").Password



    $credential = New-Object System.Management.Automation.PSCredential ($userName, $password)


    foreach ( $serverList1 in $serverList)

    { 

    $session = New-PSSession -ComputerName "$serverList1" -Credential $credential



    ########################################################################################
    #################### MasterBot ####################
    ########################################################################################

    # MasterBoT Code is here

    $result=Invoke-Command -Session $session -ScriptBlock {
# Connectivity Check (PING)
    function Test-DomainControllerConnectivity {
 
        $domainController = "CRLAB.CG"
   
        $pingResult = Test-Connection -ComputerName "$serverList1" -Count 2
   
     
        if ($pingResult) {
   
            return "Ping to $domainController was successful."
   
        } else {
   
            return "Error: Unable to ping $domainController. Check network connectivity."
   
        }
   
    }
     
    $DC_Connectivity = @($(Test-DomainControllerConnectivity))
    

    #Get-Services: We will get the following services: 'ntds', 'adws', 'dnscache', 'kdc', 'w32time', 'netlogon'
function Get-Srvc {
    # $computer = 'CRS-D1-ODC00003', 'CRS-D1-ODC00004' , 'FBO-D1-ODC00003', 'FBO-D1-ODC00004'
    # $computer = $hostname
 
   
    # Service names
    # $services = 'ntds', 'adws', 'dnscache', 'kdc', 'w32time', 'netlogon'
    $services = 'dnscache', 'w32time', 'netlogon'
    # Getthe service status from specified servers
    $get_servc = Get-Service $services -ComputerName "$serverList1" | Sort-Object MachineName, DisplayName | Select-Object MachineName, DisplayName, Status
 
    return $get_servc
}
$srvc = @($(Get-Srvc))

# Display information about each volume drive
 
#DC - Disc Space:
 
function Get-Drive_Stats{
 
    $disks =[math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName "$serverList1" ).FreeSpace / (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName "$serverList1").Size * 100,2)    
    
    return $disks
 
}
 
$Drive_Stats = @($(Get-Drive_Stats))

#DC Replication
 
function Get-DCReplication {
    $replsummary = repadmin /replsummary | ConvertTo-Html -Fragment
    $showrepl = repadmin /showrepl
 
    $repl = @($replsummary, $showrepl)
 
    return $repl
}
 
$DCReplication = @($(Get-DCReplication))

function Get-systemUptime{
 
 
   
    $uptime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    # $uptimeDuration = (Get-Date) - $uptime
 
    return $uptime
 
}
 
$sys_uptime = @($(Get-systemUptime))

#OS
function Get-OperatingSystem {
 
    $osVersion = Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem
 
    return $osVersion
   
}
 
$OS_Vers = @($(Get-OperatingSystem))


#FSMO Roles:
 
function Get-FSMORoles {
 
    $fsmo = netdom query fsmo
 
 
return $fsmo
}
 
$fsmo_roles = @($(Get-FSMORoles))
 
#Automatic Services:
 
function get-autoservices{
 
    $autoServices = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Service -ComputerName "$serverList1" -ErrorAction Stop | Where-Object {$_.StartMode -eq 'Auto' -and $ignore -notcontains $_.DisplayName -and $_.State -eq 'Running'} | ForEach-Object {$_.Displayname}
 
    return $autoServices
}
 
$autosrvc = @($(get-autoservices))
 
#Disk Management
 
function Get-VolumeReport{
 
    $volume = Get-Volume | Select-Object DriveLetter, FileSystemType, HealthStatus, OperationalStatus,
    @{Name = 'SizeRemaining (GB)';Expression = {'{0:N2}' -f ($_.SizeRemaining / 1GB) }},
    @{Name = 'Size (GB)';Expression = {'{0:N2}' -f ($_.Size / 1GB)}}
       
    return $volume
}
 
$diskmgmt = @($(Get-VolumeReport))
 
#Network Adapter
 
function Get_NWAdapter{
 
    $NWAdapter = @($(Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed))
 
    return $NWAdapter
}
 
$netadapter = @($(Get_NWAdapter))
 
#CPU Utilization:
 
function Get-CPUUtilization {
   
    $CPU = Get-WmiObject -Query "SELECT * FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'"
   
    $CPUUtilization = [Math]::Round($CPU.PercentProcessorTime, 2)
   
    return "$CPUUtilization%"
     
    }
   
$cpu_util = @($(Get-CPUUtilization))
 
#Memory Utilization:
 
function Get-MemoryUtilization {
   
    $CompObject =  Get-WmiObject -Class WIN32_OperatingSystem -ComputerName "$serverList1"
   
    $memory = $CompObject.TotalVisibleMemorySize - $CompObject.FreePhysicalMemory
    $memoryPercentage = [math]::Round(($memory * 100) / $CompObject.TotalVisibleMemorySize, 2)
   
    return "$memoryPercentage%"
 
}
 
$memory_util = ($(Get-MemoryUtilization))
 
#DNS Client Information:
 
function Get-DNSClientInformation {
 
    $dnsClientInfo = Get-DnsClient | select InterfaceAlias,InterfaceConnectionSpecificSuffixIndex,ConnectionSpecificSuffixSearchList,RegisterThisConnectionsAddress,UseSuffixWhenRegistering
 
    return $dnsClientInfo
}
 
$DNSClientInformation = @($(Get-DNSClientInformation))
 
#DNS Server Address
function Get-DNS_Server_Address {
 
    $dnsServerAddresses = Get-DnsClientServerAddress | Select InterfaceAlias,ServerAddresses
 
    return $dnsServerAddresses
}
 
$DNS_Server_Address = @($(Get-DNS_Server_Address))

#Adding Headers to the table
function Add-TableHeader {
    param($headers)
    "<tr>" + ($headers | ForEach-Object { "<th style='background-color: navy; color: white;'>$_</th>" }) + "</tr>"
}

 
 
# Convert everything to HTML and output to file
 
$htmlOutput = @"
<html>
<head>
<title> AD Health Check </title>
<style>
    table {
        border-collapse: collapse;
        width: auto;
        table-layout: auto;
    }
    th, td {
        border: 1px solid black;
        padding: 8px;
        text-align: left;
        word-wrap: break-word;
    }
</style>
</head>
<body>
<h2>Services Report</h2>
<table>
<tr>
$(Add-TableHeader "Machine Name,", "Display Name", "Status")
</tr>
"@
 
foreach ($service in $srvc) {
    $htmlOutput += @"
<tr>
<td>$($service.MachineName)</td>
<td>$($service.DisplayName)</td>
<td>$($service.Status)</td>
</tr>
"@
}
 
 
$htmlOutput += @"
</table>
 
<h2>Drive Statistics</h2>
<table>
<tr>
$(Add-TableHeader "Drive","Percentage")
</tr>
"@
 
foreach ($drives in $Drive_Stats) {
    $htmlOutput += @"
<tr>
<td> C: </td>
<td style="background-color: $(if ($drives -lt 85) {'#90EE90'} elseif ($drives -gt 90) {'red'} else {'amber'})">$drives%</td></tr>
"@
}
 
$htmlOutput += @"
</table>
<h2>DC Replication</h2>
<table>
 <tr>
 $(Add-TableHeader "Repl Summary")
 </tr>
"@
 
foreach ($rep in $DCReplication) {
    $htmlOutput += @"
<tr>
<td>$($replsummary)</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
<h2>Show-Repl</h2>
<table>
<tr>
$(Add-TableHeader "Show Repl")
</tr>
"@
 
foreach ($rep in $DCReplication) {
    $htmlOutput += @"
<tr>
<td>$($showrepl)</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
 
<h2>System Uptime</h2>
<table>
<tr>
$(Add-TableHeader "Uptime")
<th>$($sys_uptime)</th>
</tr>
</table>
</body>
</html>
"@
 
$htmlOutput += @"
</table>
<h2>OS</h2>
<table>
<tr>
$(Add-TableHeader "Name", "Operating System")
</tr>
"@
 
foreach ($os in $OS_Vers) {
    $htmlOutput += @"
<tr>
<td>$($os.Name)</td>
<td>$($os.OperatingSystem)</td>
</tr>
"@
 }

$htmlOutput += @"
</table>
<h2>FSMO Roles</h2>
<table>
<tr>
$(Add-TableHeader "Roles")
</tr>
"@
 
foreach ($role in $fsmo_roles) {
    $htmlOutput += @"
<tr>
<td>$($role)</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
<h2>Auto Services</h2>
<table>
<tr>
$(Add-TableHeader "Services")
</tr>
"@
 
foreach ($service in $autosrvc){
    $htmlOutput += @"
<tr>
<td>$($service)</td>
</tr>
"@
}
 
 
$htmlOutput += @"
</table>
<h2>Disk Management</h2>
<table>
<tr>
$(Add-TableHeader "Drive", "File System Type" , "Health Status", "Operational Status", "Size Remaining (GB)" ,"Size (GB)" )
</tr>
"@
 
# Add rows for each disk in Disk Management
foreach ($dis in $diskmgmt) {
    $htmlOutput += @"
<tr>
<td>$($dis.DriveLetter)</td>
<td>$($dis.FileSystemType)</td>
<td style=`"background-color: $(if ($dis.HealthStatus -eq 'Healthy') {'#90EE90'} else {'red'})">$($dis.HealthStatus) </td>
<td>$($dis.OperationalStatus)</td>
<td>$($dis.'SizeRemaining (GB)')</td>
<td>$($dis.'Size (GB)')</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
<h2>Network Adapter</h2>
<table>
<tr>
$(Add-TableHeader "Name", "Interface Description","if Index","Status","Mac Address","Link Speed")
</tr>
"@
 
foreach ($adapter in $netadapter) {
$htmlOutput += @"
<tr>
<td>$($adapter.Name)</td>
<td>$($adapter.InterfaceDescription)</td>
<td>$($adapter.ifIndex)</td>
<td>$($adapter.Status)</td>
<td>$($adapter.MacAddress)</td>
<td>$($adapter.LinkSpeed)</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
<h2>CPU Utilization</h2>
<table>
<tr>
$(Add-TableHeader "Utilization")
<td style="background-color: $(if ($cpu_util -lt 85) {'#90EE90'} elseif ($cpu_util -gt 90) {'red'} else {'amber'})">$cpu_util</td>
</tr>
"@
 
$htmlOutput += @"
</table>
<h2>Memory Utilization</h2>
<table>
<tr>
$(Add-TableHeader "Utilization")
<td style="background-color: $(if ($memory_util -lt 85) {'#90EE90'} elseif ($memory_util -gt 90) {'red'} else {'amber'})">$memory_util</td>
</tr>
"@
 
$htmlOutput += @"
</table>
<h2>DNS Client Information</h2>
<table>
<tr>
$(Add-TableHeader "Interface Alias", "Interface connection Specific Suffix Index", "Connection Specific Suffix Search List", "Register This Connection Address", "Use Suffix When Registering")
</tr>
"@
 
foreach ($DNS in $DNSClientInformation) {
    $htmlOutput += @"
<tr>
<td>$($DNS.InterfaceAlias)</td>
<td>$($DNS.InterfaceConnectionSpecificSuffixIndex)</td>
<td>$($DNS.ConnectionSpecificSuffixSearchList)</td>
<td>$($DNS.RegisterThisConnectionsAddress)</td>
<td>$($DNS.UseSuffixWhenRegistering)</td>
</tr>
"@
}
 
$htmlOutput += @"
</table>
 
<h2>DNS Server Address</h2>
<table>
<tr>
$(Add-TableHeader "Interface Alias", "Server Address")
</tr>
"@
 
foreach ($dnssvr in $DNS_Server_Address) {
    $htmlOutput += @"
<tr>
<td>$($dnssvr.InterfaceAlias)</td>
<td>$($dnssvr.ServerAddresses)</td>
</tr>
"@
}
$htmlOutput += @"
</table>
</body>
</html>
"@

return $htmlOutput




}

    $result | Out-File -FilePath " $outputFolderPath\HealthCHeckHtml.html"

    }




    ########################################################################################
    #################### Sending Mail ####################
    ########################################################################################
    <#try{
        [string]$bodyhtml = Get-Content $outputHTMLFilePath
        $emailPassword = ConvertTo-SecureString -String $emailPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $configFile.fromMail, $emailPassword
        Send-MailMessage -SmtpServer $configFile.smtpServer -Port $configFile.smtpPort -UseSsl -Credential $credential -Subject $configFile.subjectMail -Body $bodyhtml -BodyAsHtml -From $configFile.fromMail -To $configFile.toMail -Attachments $outputHTMLFilePath
        & $logEntryMicroBotFilePath "SUCCESS - Mail Sent Successfully To: $($configFile.toMail)" -LogFile $outputLogFilePath
    }
    catch{
        Write-Host "Error: $_"
        & $logEntryMicroBotFilePath "ERROR - Mail Sent Not Successfull" -LogFile $outputLogFilePath
    }#>