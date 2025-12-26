$RunDate = (Get-Date -f yyyyMMdd-HHmmss)
$FolderName = "Update Job $RunDate"
$FolderLocation = New-Item -ItemType Directory -Path "C:\Logs" -Name $FolderName | Out-Null
$FolderLocation

$LogPaths = @{
    UpdateJobLog = "C:\Logs\$FolderName\UpdateJob.txt"
    SystemStatusLog = "C:\Logs\$FolderName\SystemStatus.txt"
}


    #-------------------------------------#
    # *~*~*~*~*~ Configuration *~*~*~*~*~ #
    #-------------------------------------#

#The WSUS server to be used for hosting the program.
$WSUS_Server = Get-WsusServer -Name "KTPO-WSUS" -PortNumber 8530

#Pathing for the PSWindowsUpdate module. Copied to systems missing the module.
$ModuleSource = "\\ktpo-wsus\c$\Update Module\PSWindowsUpdate"
$ModuleDestination = "C:\Program Files\WindowsPowerShell\Modules"

$AllUpdateJobs = @()

$AdminCredentials = Import-Clixml -Path "C:\Scripts\RemoteCreds.xml"



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

    #SystemList1 = Raw system list pulled from WSUS.
    #SystemList2 = Sorted list of only the system names from WSUS.
    #SystemList3 = The list of systems that have had ".kuka.com" removed from the name.
    #SystemList4 = The version of the update list with the blacklisted systems removed.

#The base list of computer names pulled by WSUS. These commands return a .ktpo.local name which will be cleaned later.
$SystemList1 = @(Get-WsusComputer -UpdateServer $WSUS_Server -ComputerTargetGroups $TargetSystemGroups -IncludeSubgroups)
$SystemList2 = $SystemList1.FullDomainName | Sort-Object -Descending

#
#This function controls the blacklist. This takes the systems list pulled from WSUS and compares it to the blacklist systems. If any
#systems are in the blacklist, it removes them from the update list.
#
function GetNow{
    return get-date -f "yyyy.MM.dd hh:mm:ss"
}
function VerifyBlacklist{
    param($SystemList2,$BlackList,$LogPaths)
    
    $BlackListMatch = @()  #Setting up the needed arrays for this function.
    $SystemsToRemove = @() #
    
    $SystemList3 = CleanNames -SystemList2  $SystemList2 -LogPaths $LogPaths #Send the update list to the CleanNames function for the proper list.
    $BlackListMatch = $SystemList3 | Where-Object {$_ -in $BlackList} #Get an array of all systems that are in the blacklist and update list.

    foreach($match in $BlackListMatch){ #Take every system in the BlackListMatch array, announce their presence, and add them to a new array.
        Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : $match is a blacklisted system found in the update list. Removing from update list..."
        $SystemsToRemove += $match
    }

    $SystemList4 = $SystemList3 | Where-Object {$_ -notin $SystemsToRemove}#Remove the Blacklisted systems from the update list and hand the finished forward.
    $FinalSystemList = $SystemList4
    return $FinalSystemList
}

function CleanNames{
    param ($SystemList2,$LogPaths)

    $SystemList3 = @()

    foreach($system in $SystemList2){
        $cleanname = $($system -split "\.")[0]
        $SystemList3 += $cleanname
    }
    return $SystemList3
}

#
#This function is meant to take the system list and remove the ".ktpo.local" from each system for a cleaner, better functioning script.
#
function TestConnection {
    param ($system,$LogPaths)

    $CouldConnect = Test-Connection -ComputerName $system -Count 1 -Quiet

    if ($CouldConnect){
        Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : Good connection"
        return $true
    }  else {
        Add-Content -Path $LogPaths.SystemStatusLog -Value "[Warning] $(GetNow) : $system cannot be reached."
        Add-Content -Path $LogPaths.SystemStatusLog -Value ""
        return $false
    }
}

#
#This function ensures that the WinRM script is running, which is essential for all remote script that involve invoking.
#
function TestWinRM {
    param ($system,$LogPaths)

    $WinRM = Get-Service -ComputerName $system -Name WinRM

    if($WinRM.Status -eq 'Stopped'){
        $Timeout = 0 #imeout variable to ensure the do until loop doesnt go on forever.

        do {
            sc.exe "\\$system" start WinRM | Out-Null                           #Attempt to start WinRM
            start-Sleep -Seconds 1                                              #Sleep for one second.
            $Timeout++                                                          #
            $status = (Get-Service -ComputerName $system -Name WinRM).Status    #Get the status on the service again.
        } until ($status -eq 'Running' -or $Timeout -eq 15)                     #Exit if the process is now running, or the loop occured 15 times (15 seconds)
        if ($Timeout -eq 15){ #If the loop did timeout, inform the log and move to the next system.
            Add-Content -Path $LogPaths.SystemStatusLog -Value "[Error] $(GetNow) : $system timed out while trying to start WinRM service."
            return $false
        }
        $WinRM = Get-Service -ComputerName $system -Name WinRM #Query the service one last time.

        if($WinRM.Status -eq 'Running'){
            Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : WinRM Running"
            return $true
        }

    } elseif($WinRM.Status -eq 'Running') {
        Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : WinRM Running"
        return $true
    } else {
        Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : Issue Connecting to WinRM"
        return $false
    }
}

function TestUpdateModule{
    param($system,$LogPaths)

    $ModuleSource = "C:\Update Module\PSWindowsUpdate"
    $ModuleDestination = "\\$system\c$\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate"

    if(-not(Test-Path $ModuleDestination)){
        New-Item -ItemType Dir -Path $ModuleDestination
        Copy-Item $ModuleSource $ModuleDestination -Recurse -Force

        Invoke-Command -ComputerName $system -ScriptBlock{
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
            $PS_Module = Get-InstalledModule PSWindowsUpdate | Out-Null -ErrorAction SilentlyContinue

            if(!$PS_Module){
                $timeout = 0
                Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : PSWindowsUpdate module is not installed on $system. Installing..."
                Start-Sleep -Seconds 2
                Install-Module PSWindowsUpdate -force -Scope AllUsers
                do {
                    $PS_Module = Get-InstalledModule PSWindowsUpdate
                    Start-Sleep -Seconds 1
                    $timeout++
                } until ($PS_Module -or $timeout -eq 10)

                if($timeout -eq 10){
                    Add-Content -Path $LogPaths.SystemStatusLog -Value "[Error] $(GetNow) : Module import failed on $system."
                    return $false
                } else {
                    Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : PSWindowsUpdate module is good."
                    return $true
                }

            } else {
                Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : PSWindowsUpdate module is good."
                return $true
            }
        } 
    } else {
        Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : PSWindowsUpdate module is good."
        return $true
    }    
}


function Wait-ForRemoteTaskCompletion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$System,

        [Parameter(Mandatory=$true)]
        [string]$TaskName,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,

        [int]$WaitSeconds = 10,
        [int]$TimeoutMinutes = 60, # Set a maximum timeout to prevent infinite looping

        $LogPaths
    )

    $StartTime = Get-Date
    $TaskStillRunning = $true
    
    #Add-Content -Path $LogPaths.UpdateJobLog -Value "Monitoring remote task '$TaskName' on $System..."

    do {
        # Check for timeout
        if ((New-TimeSpan -Start $StartTime).TotalMinutes -ge $TimeoutMinutes) {
            Add-Content -Path $LogPaths.UpdateJobLog -Value "$(GetNow) : Task monitoring timed out after $TimeoutMinutes minutes on $System."
            break # Exit the loop
        }
        
        # 1. Invoke-Command to check the scheduled task status
        try {
            # Use Get-ScheduledTask as it is more reliable than Get-WUJob for existence check
            $TaskStatus = Invoke-Command -ComputerName $System -Credential $Credential -ScriptBlock {
                # Check for the task object's existence and state
                $Task = Get-ScheduledTask -TaskName $using:TaskName -ErrorAction SilentlyContinue
                
                if ($null -eq $Task) {
                    # Task is gone (completed and cleaned up)
                    return "GONE" 
                } elseif ($Task.State -eq 'Running') {
                    return "RUNNING"
                } else {
                    # Task is in 'Ready', 'Disabled', 'Queued', etc. (Consider it done working)
                    return "FINISHED"
                }
            } -ErrorAction Stop
            
            # 2. Evaluate the result from the remote machine
            if ($TaskStatus -ne "RUNNING") {
                $TaskStillRunning = $false
                #Add-Content -Path $LogPaths.UpdateJobLog -Value "Task status resolved: $TaskStatus"
            } else {
                #Add-Content -Path $LogPaths.UpdateJobLog -Value "Task is still running. Waiting $WaitSeconds seconds..."
                Start-Sleep -Seconds $WaitSeconds
            }

        }
        catch {
            Add-Content -Path $LogPaths.UpdateJobLog -Value "[Error] $(GetNow) : Issue querying task status on $System"
            $TaskStillRunning = $false # Treat a hard error as a reason to stop waiting
        }

    } while ($TaskStillRunning)
    
    #Add-Content -Path $LogPaths.UpdateJobLog -Value "Monitoring complete for $System."

}

$FinalSystemList = VerifyBlacklist -SystemList2 $SystemList2 -BlackList $BlackList -LogPaths $LogPaths

foreach($system In $FinalSystemList){

    Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : ---Beginning system checks on $system---"

    $ConnectionStatus = TestConnection -system $system -LogPaths $LogPaths
    if($ConnectionStatus -eq $false){Continue}
    $WinRM_Running = TestWinRM -system $system -LogPaths $LogPaths
    if ($WinRM_Running -eq $false){Continue}
    $InstalledModule = TestUpdateModule -system $system -LogPaths $LogPaths
    if ($InstalledModule -eq $false){Continue}

    Add-Content -Path $LogPaths.SystemStatusLog -Value "$(GetNow) : Beginning update process on $system..."
    Add-Content -Path $LogPaths.SystemStatusLog -Value ""
    Add-Content -Path $LogPaths.SystemStatusLog -Value ""

    $LocalTaskName = "UT - $system"
    $JobName = "UT - $system"

    $Job = Invoke-Command -ComputerName $system -Credential $AdminCredentials -ScriptBlock {
        param($LocalTaskName)

        $WUTaskNameFromLocal = $LocalTaskName

        $PreUpdateList = Get-WindowsUpdate
        $PreUpdateCount = $PreUpdateList.count

        $WU_job = Invoke-WUJob -TaskName $WUTaskNameFromLocal -Script{
            Install-WindowsUpdate -ComputerName $env:computername -AcceptAll -ForceDownload -ForceInstall -IgnoreReboot
        } -RunNow -Confirm:$false | Out-Null

        Wait-Job -Job $WU_job

        $PostUpdateList = Get-WindowsUpdate
        $PostUpdateCount = $PostUpdateList.count

        $RebootVariables = @()
        foreach ($path in $PathList){  
            $KeyExists = Test-Path -Path $path
            $RebootVariables += $KeyExists
        }

        $SessionManager = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $PendingRenameValue = Get-ItemProperty -Path $SessionManager -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        $RenamePending = ($null -ne $PendingRenameValue.PendingFileRenameOperations)
        $NeedsReboot += $RenamePending
        $PendingReboot = $NeedsReboot -contains $true

        [PSCustomObject]@{
            SystemName = $env:computername
            WUTaskName = $WUTaskNameFromLocal
            PreUpdateCount = $PreUpdateCount
            PostUpdateCount = $PostUpdateCount
            PendingReboot = $PendingReboot
        }
    } -ArgumentList $LocalTaskName -AsJob -JobName "UT - $system"
    $AllUpdateJobs += $Job
}

Add-Content -Path $LogPaths.UpdateJobLog -Value "[$(Get-Date -f yyyyMMdd-HHmmss)]Started $($AllUpdateJobs.count) update jobs"
Add-Content -Path $LogPaths.UpdateJobLog -Value "Monitoring update jobs..."
Add-Content -Path $LogPaths.UpdateJobLog -Value ""

do {
    $RunningJobs = ($AllUpdateJobs | Where-Object {$_.State -eq 'Running'}).count
    Add-Content -Path $LogPaths.UpdateJobLog -Value ("[$(Get-Date -f yyyyMMdd-HHmmss)] {0} jobs remaining" -f $RunningJobs)
    Start-Sleep -Seconds 30
} while ($RunningJobs -gt 0)

Add-Content -Path $LogPaths.UpdateJobLog -Value ""
Add-Content -Path $LogPaths.UpdateJobLog -Value "Completed all update jobs. Printing results..."
Add-Content -Path $LogPaths.UpdateJobLog -Value ""

foreach ($Job in $AllUpdateJobs){
    $JobName = $Job.Name
    $Results = Receive-Job -Job $Job -ErrorAction SilentlyContinue
    $TaskName = $Results.WUTaskName
    $PreUpdateCount = $Results.PreUpdateCount
    $PostUpdateCount = $Results.PostUpdateCount
    $PendingReboot = $Results.PendingReboot
    

    Wait-ForRemoteTaskCompletion -System $system -TaskName $TaskName -Credential $AdminCredentials -LogPaths $LogPaths

    Add-Content -Path $LogPaths.UpdateJobLog -Value "-------------------------------------------"
    Add-Content -Path $LogPaths.UpdateJobLog -Value "Final Results for $JobName"
    Add-Content -Path $LogPaths.UpdateJobLog -Value "Initial approved updates found: $PreUpdateCount"
    Add-Content -Path $LogPaths.UpdateJobLog -Value "Approved updates remaining after process: $PostUpdateCount"
    Add-Content -Path $LogPaths.UpdateJobLog -Value "Pending reboot status: $PendingReboot"
    Add-Content -Path $LogPaths.UpdateJobLog -Value ""
    Add-Content -Path $LogPaths.UpdateJobLog -Value ""
    
    # Cleanup the local job and the remote scheduled task
    Remove-Job -Job $Job -Force
    Invoke-Command -ComputerName $system -ScriptBlock {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    } -ErrorAction SilentlyContinue
}

Add-Content -Path $LogPaths.UpdateJobLog -Value "Update process completed"









