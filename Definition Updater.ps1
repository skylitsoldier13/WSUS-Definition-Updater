$logFile = "C:\Logs\UpdateJob_$(Get-Date -f yyyyMMdd-HHmmss).txt"

$ProgramBlock = {

        #-------------------------------------#
        # *~*~*~*~*~ Configuration *~*~*~*~*~ #
        #-------------------------------------#

#The WSUS server to be used for hosting the program.
$WSUS_Server = Get-WsusServer -Name "KTPO-WSUS" -PortNumber 8530

#The path that the logs are saved at.
$ScriptUpdateLogPath = "C:\Script Logs"

#Pathing for the PSWindowsUpdate module. Copied to systems missing the module.
$ModuleSource = "\\ktpo-wsus\c$\Update Module\PSWindowsUpdate"
$ModuleDestination = "C:\Program Files\WindowsPowerShell\Modules"

#Credentials passed along to the Invoke-WU
#$AdminCredentials = Import-Clixml -Path C:\Users\mike.jurovcik\Desktop\Script\AdminCredentials.xml

        #-------------------------------------------#
        # *~*~*~*~*~ Initial Base Arrays *~*~*~*~*~ #
        #-------------------------------------------#

#The list of Computer Groups from WSUS to pull the system list from. Groups not used are commented out.
$TargetSystemGroups = @("Department Systems","Hilo Tablets","Info Screens","Kiosk Systems","PWS",
    "QVS","Surfaces","Team Lead",
    "Vista"
    #"Server No Updates","Servers","Not Approved"
)

#A list of systems to never run the program on to be used in the VerifyBlackList function.
$BlackList = @(
    "KTPO-MQC1","KTPO-MQC2","KTPO-MQC","KTPO-MQCA","KTPO-JBOSS-PRD","KTPO-JBOSS-PRD1","KTPO-JBOSS-PRD2","KTPO-SOS-PRD","KTPO-SOS-PRD1","KTPO-SOS-PRD2","KTPO-SOS-PRD3",
    "KTPO-PDS1","KTPO-PDS2","KTPO-PDSC","PDSSQL1","KTPO-ERP-PRD","KTPO-TRANS-PRD","KTPO-HIST-PRD","KTPO-DIREC-PRD","KTPO-VWSE-PRD","KTPO-VWPT-PRD","KTPO-VTPT-PRD",
    "KTPO-JBOSS-QUAL","KTPO-JBOSS-Q2","KTPO-SOS-QUAL","KTPO-SOS-QUAL1","KTPO-SOS-QUAL2","KTPO-SOS-QUAL3","KTPO-QUAL-DB","KTPO-QUAL-DB1","KTPO-QUAL-DBC","QTYSQL1",
    "KTPO-ERP-QUAL","KTPO-TRANS-QUAL","KTPO-HIST-QUAL","KTPO-DIREC-QUAL","KTPO-VWSE-QUAL","KTPO-VWPT-QUAL","KTPO-VTPT-QUAL"
)

        #-----------------------------------------------#
        # *~*~*~*~*~ Initial List Generation *~*~*~*~*~ #
        #-----------------------------------------------#

#The base list of computer names pulled by WSUS. These commands return a .ktpo.local name which will be cleaned later.
$RawWSUS_List = @(Get-WsusComputer -UpdateServer $WSUS_Server -ComputerTargetGroups $TargetSystemGroups -IncludeSubgroups)
$SystemsToUpdate = $RawWSUS_List.FullDomainName | Sort-Object -Descending


#
#This function controls the blacklist. This takes the systems list pulled from WSUS and compares it to the blacklist systems. If any
#systems are in the blacklist, it removes them from the update list.
#
function VerifyBlacklist{
    param($SystemsToUpdate,$BlackList)
    
    $BlackListMatch = @()  #Setting up the needed arrays for this function.
    $SystemsToRemove = @() #
    
    $CleanUpdateList = CleanNames -SystemsToUpdate $SystemsToUpdate #Send the update list to the CleanNames function for the proper list.
    $BlackListMatch = $CleanUpdateList | Where-Object {$_ -in $BlackList} #Get an array of all systems that are in the blacklist and update list.

    foreach($match in $BlackListMatch){ #Take every system in the BlackListMatch array, announce their presence, and add them to a new array.
        #Write-Output "$match is a blacklisted system found in the update list. Removing from update list..."
        $SystemsToRemove += $match
    }

    $FilteredSystemsToUpdate = $CleanUpdateList | Where-Object {$_ -notin $SystemsToRemove}#Remove the Blacklisted systems from the update list and hand the finished forward.
    return $FilteredSystemsToUpdate
}


#
#This function is meant to take the system list and remove the ".ktpo.local" from each system for a cleaner, better functioning script.
#
function CleanNames{
    param ($SystemsToUpdate)

    $CleanUpdateList = @()

    foreach($system in $SystemsToUpdate){
        $cleanname = $($system -split "\.")[0]
        $CleanUpdateList += $cleanname
    }
    return $CleanUpdateList
}

#
# This function only checks if a system is online and reachable. If the system isn't, we skip it.
#
function TestConnection {
    param ($system)

    $CouldConnect = Test-Connection -ComputerName $system -Count 1 -Quiet

    if ($CouldConnect){
        #Continue with the script.
    }  else {
        #Write-Output "[Error] $system cannot be reached."
        #Write-Output
        Continue
    }

}

#
#This function ensures that the WinRM script is running, which is essential for all remote script that involve invoking.
#
function TestWinRM {
    param ($system)

    $WinRM = Get-Service -ComputerName $system -Name WinRM

    $Timeout = 0 #imeout variable to ensure the do until loop doesnt go on forever.
    if($WinRM.Status -eq 'Stopped'){
        do {
            sc.exe "\\$system" start WinRM | Out-Null                           #Attempt to start WinRM
            start-Sleep -Seconds 1                                              #Sleep for one second.
            $Timeout++                                                          #
            $status = (Get-Service -ComputerName $system -Name WinRM).Status    #Get the status on the service again.
        } until ($status -eq 'Running' -or $Timeout -eq 15)                     #Exit if the process is now running, or the loop occured 15 times (15 seconds)
        if ($Timeout -eq 15){ #If the loop did timeout, inform the log and move to the next system.
            Write-Output "[Error] $system timed out while trying to start WinRM service."
            Continue
        }
        $WinRM = Get-Service -ComputerName $system -Name WinRM #Query the service one last time.
        if($WinRM.Status -eq 'Running'){
            #Continue with the script.
        }

    } else {
        #Write-Output -ForegroundColor Green "WinRM good."
        #Continue
    }
}

function TestUpdateModule{
    param($system)

    $ModuleSource = "C:\Update Module\PSWindowsUpdate"
    $ModuleDestination = "\\$system\c$\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate"

    if(-not(Test-Path $ModuleDestination)){
        #Write-Output "Folder not found"
        New-Item -ItemType Dir -Path $ModuleDestination
        Copy-Item $ModuleSource $ModuleDestination -Recurse -Force

        Invoke-Command -ComputerName $system -ScriptBlock{
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Continue
            $PS_Module = Get-InstalledModule PSWindowsUpdate | Out-Null -ErrorAction Continue

            if(!$PS_Module){
                $timeout = 0
                #Write-Output "PSWindowsUpdate module is not installed on target machine. Installing..."
                Start-Sleep -Seconds 2
                Install-Module PSWindowsUpdate -force -Scope AllUsers
                do {
                    $PS_Module = Get-InstalledModule PSWindowsUpdate
                    Start-Sleep -Seconds 1
                    $timeout++
                } until ($PS_Module -or $timeout -eq 10)

                if($timeout -eq 10){<#Write-Output "Module import failed."#>}

            } else {}
        } 
    } else {}    
}

#
#This is the main function that actually runs and controls the update processes.
#
function RunUpdates {
    param($system,$FirewallFix,$ScriptUpdateLogPath)

    #$AdminCredentials = Import-Clixml -Path C:\Users\mike.jurovcik\Desktop\Script\AdminCredentials.xml
    $AdminCredentials = Import-Clixml -Path "C:\Scripts\RemoteCreds.xml"

    #try{ #Try to invoke the command to run the update and reporting scripts.
        Invoke-Command -ComputerName $system -Credential $AdminCredentials -ScriptBlock {
            
            wuauclt /resetauthorization /detectnow
            wuauclt /reportnow

            $CurrentVersion = (Get-MpComputerStatus).AntivirusSignatureVersion #This is the current version of defender signatures.
            #Write-Output "Current Signature Version: $CurrentVersion"

            & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -removedefinitions -dynamicsignatures *>$null
            & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate *>$null
            $NewVersion = (Get-MpComputerStatus).AntivirusSignatureVersion

            #Write-Output "Signature version after update: $NewVersion"
            continue

        } #-ErrorAction Stop
    #} catch {
        if (-not $FirewallFix){
            #Write-Output "[Attention] Could ping the system but invoke failed. Verifying domain firewall..."
            $FixSuccess = FixFirewall -system $system

            if($FixSuccess){
                RunUpdates -system $system -FirewallFix $true
            } else {
                #Write-Output "[Error] Update retry failed. Moving to next system."
                Continue
            }
        }
   # }

    Set-Item WSMan:\localhost\Client\TrustedHosts -value "$system" -force -concatenate

    Invoke-WUJob -ComputerName $system -Credential $AdminCredentials -Script {
        #Write-Output "Hi im $env:computername"
        #Write-Output "$updates"
        Install-WindowsUpdate -ComputerName $env:computername -AcceptAll -ForceDownload -ForceInstall -IgnoreReboot -Verbose *>> "$ScriptUpdateLogPath\Update.txt"
        Get-WUJob -ComputerName $env:computername -TaskName PSWindowsUpdate
        Get-WindowsUpdateLog -LogPath "C:\Windows" -Verbose
    } -RunNow -Confirm:$false
    wuauclt /resetauthorization /detectnow
    wuauclt /reportnow
    #Write-Output "-------------------------------------------"
    #Write-Output
}

function FixFirewall {
    param ($system)
    
    try{
        psexec \\$system cmd /c "netsh firewall set opmode disable" *>$null
        PsExec.exe \\$system -s powershell.exe Enable-PSRemoting -Force *>$null
        try {

            Invoke-Command -ComputerName $system -ScriptBlock {
                #Write-Output "Firewall disable succeeded. Invoking is now successful."
                return $true
            } -ErrorAction Stop
        }
        catch {
            #Write-Output "[Error] Firewall disable ran, but still unable to Invoke. Stopping on this system..."
            #Write-Output
            Continue
        }
        #Write-Output "Domain firewall disable complete. Retrying update..."
        
    }
    catch{
        #Write-Output "[Error] Firewall disable failed..."
        return $false
    }
}

$FilteredSystemsToUpdate = VerifyBlacklist -SystemsToUpdate $SystemsToUpdate -BlackList $BlackList

foreach($system In $FilteredSystemsToUpdate){
    $ModuleDestination = "\\$system\c$\Program Files\WindowsPowerShell\Modules"
    $FirewallFix = $false
    #Write-Output
    #Write-Output "-------------------------------------------"
    #Write-Output "    >Starting on $system<" 

    TestConnection -system $system
    TestWinRM -system $system
    TestUpdateModule -system $system
    RunUpdates -system $system -FirewallFix $FirewallFix -ScriptUpdateLogPath $ScriptUpdateLogPath
}
}

& $ProgramBlock *>> $logfile

Out-File $logFile

