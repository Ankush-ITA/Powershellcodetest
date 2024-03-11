###############################################################################################################
# Language     :  PowerShell 5.0
# Filename     :  PSScriptAnalyzer-Integration
# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
# Description  :  Integrate PSScriptAnalyzer with 
# Version      :  1.0
# Repository   :  https://github.com/BornToBeRoot/GitHub-Actions_PSScriptAnalyzer
###############################################################################################################
#
#
# Changelog
###############################################################################################################
#
### 09.11.2020 ###
# - Initial Release
#

#Requires -RunAsAdministrator
#Requires -Version 5.0

<#
    .SYNOPSIS
    PSScriptAnalyzer integration for GitHub Actions.

    .DESCRIPTION    
    PSScriptAnalyzer integration for GitHub Actions.
    
    .EXAMPLE
    
    .LINK
    https://github.com/BornToBeRoot/GitHub-Actions_PSScriptAnalyzer
#>

[CmdletBinding()]
param(

)

# Install module from PSGallery
###############################################################################################################
Begin {
    Install-Module -Name PSScriptAnalyzer -Force
    Import-Module -Name PSScriptAnalyzer
    
    [System.Collections.ArrayList]$Results = @()
}

# Check every .ps1 and .psm1-file, exclude "Information"
###############################################################################################################
Process {
    foreach($File in Get-ChildItem -Path $PSScriptRoot -File -Recurse | Where-Object {[System.IO.Path]::GetExtension($_.Name) -match '^(\.ps1|\.psm1)$'})
    {
        $AnalyzerResult = (Invoke-ScriptAnalyzer -Path $File.FullName | Where-Object -FilterScript { $_.Severity -ne "Information" })
        
        if(($null -ne $AnalyzerResult) -and ($AnalyzerResult -ne 0))
        {
            [void]$Results.Add([pscustomobject] @{
                File = $File.FullName
                AnalyzerResult = $AnalyzerResult
            })        
        }
    }
}

# Format the output
###############################################################################################################
End {
    if($Results -ne 0)
    {
        foreach($Result in $Results)
        {
            $FileTrimmed = $Result.File.Substring($PSScriptRoot.Length + 1, $Result.File.Length - ($PSScriptRoot.Length + 1))
            Write-Information -MessageData "File: $FileTrimmed`n----------------------------------------------------------------------------------------------------" -InformationAction Continue
            $Result.AnalyzerResult | Select-Object -Property *,@{N='SuggestedCorrections_Description'; E={$_.SuggestedCorrections.Description}} -ExcludeProperty SuggestedCorrections | Format-List
        }

        Write-Error -Message "PSScriptAnalyzer found some issues. See the list above!"  

        exit 1
    }
    else 
    {
        Write-Information -MessageData "PSScriptAnalyzer is happy :)"   
    }
}
