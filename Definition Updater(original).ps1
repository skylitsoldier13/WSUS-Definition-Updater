Clear-Host
$WSUS_Server = Get-WsusServer -Name "KTPO-WSUS" -PortNumber 8530

$TargetSystemGroups = @("Department Systems","Hilo Tablets","Info Screens","Kiosk Systems","PWS",
    "QVS","Surfaces","Team Lead",
    "Vista","Not Approved"
    #"Server No Updates","Servers"
)

#$UpdateDirectory = "C:\Definition Updates\mpam-fe.exe"

#$RawWSUS_List = @(Get-WsusComputer -UpdateServer $WSUS_Server -ComputerTargetGroups $TargetSystemGroups -IncludeSubgroups)

<#
foreach($system In $SystemsToUpdate){

    if($WinRM.Status -eq 'Running'){
    } else {
        sc.exe "\\$system" start WinRM
        Set-Service -ComputerName $system -StartupType Automatic -Name WinRM  
    }

    Invoke-Command -ComputerName $system -ScriptBlock {
        Set-MpPreference -SignatureUpdateCatchupInterval 24
        #gpupdate -force
        UsoClient StartScan
        wuauclt /resetauthorization /detectnow
        wuauclt /reportnow
        UsoClient StartDownload
        schtasks /run /tn "\Microsoft\Windows\WaaSMedic\PerformRemediation"
        & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -removedefinitions -dynamicsignatures
        & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate
    }
}
#>

function StopServices{
    Write-Host -ForegroundColor Blue "Stopping services on $env:COMPUTERNAME..."
    
    foreach($service in $Services){
        $TimeOut = 0
        
        if($service -match "WaaSMedicSvc"){
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name Start -Value 4
            do {
                Stop-Service $service
                Start-Sleep -Seconds 1
                $TimeOut++
                $status = (Get-Service -Name $service).status
            } until ($status -eq 'Stopped' -or $TimeOut -eq 15)
            if ($TimeOut -eq 15){
                    Write-Host -ForegroundColor DarkRed "Timed out stopping $service"
                    Continue
            }
            Write-Host "Medic Stopped"

        } elseif($service -match "CryptSvc"){
            $ServiceToStop = Get-Service -Name $service

            if ($ServiceToStop.Status -eq 'Running'){
                do {
                    net stop $service
                    Start-Sleep -Seconds 1
                    $TimeOut++
                    $status = (Get-Service -Name $service).status
                } until ($status -eq 'Stopped' -or $TimeOut -eq 15)
            }

            if ($ServiceToStop.Status -eq 'Stopped'){
                Write-Host -ForegroundColor Green "$service has been stopped."
                Continue
            }

            #$svc = Get-WmiObject Win32_Service -Filter "Name='CryptSvc'" | Out-Null
            <#if ($null -ne $scv){
                $SCV_State = (Get-WmiObject -Class Win32_Service -ComputerName $env:COMPUTERNAME -Filter "Name='CryptSvc'").State
                if ($SCV_State -eq 'Running' -or $SCV_State -eq "Running"){
                    do {
                        $svc.StopService() | Out-Null
                        Start-Sleep -Seconds 1
                        $TimeOut++
                        $SCV_State = (Get-WmiObject -Class Win32_Service -ComputerName $env:COMPUTERNAME -Filter "Name='CryptSvc'").State
                    } until ($SCV_State -eq 'Stopped' -or $SCV_State -eq "Stopped" -or $TimeOut -eq 15)
                    if ($TimeOut -eq 15){
                        Write-Host -ForegroundColor DarkRed "Timed out stopping $service"
                        Continue
                    }
                    Write-Host -ForegroundColor Green "$service has been stopped."
                    Continue
                } else {
                    Write-Host -ForegroundColor Green "$service is not currently running."
                }         
            } else {
                Write-Host -ForegroundColor Green "$service is not currently running."
                Continue
            } #>
        } else {

            $ServiceToStop = Get-Service -Name $service

            if ($ServiceToStop.Status -eq 'Running'){
                do {
                    Stop-Service -Name $service
                    $TimeOut++
                    $status = (Get-Service -Name $service).Status
                } until ($Status -eq 'Stopped' -or $TimeOut -eq 15)
                if ($TimeOut -eq 15){
                    Write-Host -ForegroundColor DarkRed "Timed out stopping $service"
                    Continue
                }
                Write-Host -ForegroundColor Green "$service has successfully stopped."
            } else {
                Write-Host -ForegroundColor Green "$service is not currently running."
            }
        }
    }
    Write-Host
}

function RenameOldDirectories{

    if (Test-Path "C:\Windows\SoftwareDistribution.old"){
        Remove-Item -Path "C:\Windows\SoftwareDistribution.old" -Recurse -Force
        Write-Host "Deleted previous .old file"
    }

    Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue
    
    $cmd = 'Rename-Item "C:\Windows\System32\catroot2" -NewName "catroot2.old" -Force'
    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $env:COMPUTERNAME -ArgumentList "powershell.exe -command $cmd"

    #Rename-Item -Path "C:\Windows\System32\catroot2" -NewName "catroot2.old"

    Write-Host
}

function RestartServices{
    Write-Host -ForegroundColor Blue "Starting services on $env:COMPUTERNAME..."
    
    foreach($service in $Services){
        $TimeOut = 0

        if ($service -match "wuauserv"){
            #Write-Host "wuauserv"
            #Start-Service -name $service
            Continue
        }
        
        if($service -match "WaaSMedicSvc"){
            Write-Host "WaaSMedicSvc"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name Start -Value 3
            do {
                Start-Service -name $service
                Start-Sleep -Seconds 1
                $TimeOut++
                $status = (Get-Service -Name $service).Status
            } until ($status -eq 'Running' -or $TimeOut -eq 15)
            if ($TimeOut -eq 15){
                    Write-Host -ForegroundColor DarkRed "Timed out starting $service"
                    Continue
            }
            Write-Host -ForegroundColor Green "Successfully started $service"
            Continue


        } elseif ($service -match "CryptSvc"){
            $svc = Get-WmiObject Win32_Service -Filter "Name='CryptSvc'" | Out-Null
                #$SCV_State = (Get-WmiObject -Class Win32_Service -ComputerName $env:COMPUTERNAME -Filter "Name='CryptSvc'").State
            if ($null -eq $scv -or $scv -eq 'Stopped'){
                    #$svc.StartService() | Out-Null
                    Write-Host -ForegroundColor Green "$service has Started."
                    Continue
            } else {
                    Write-Host -ForegroundColor Green "$service is not currently running."
            }         
        } else {

            $ServiceToStart = Get-Service -Name $service

            if ($ServiceToStart.Status -eq 'Stopped'){
                do {
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 1
                    $TimeOut++
                    $status = (Get-Service -Name $service).Status
                } until ($status -eq 'Running' -or $TimeOut -eq 15)
                if ($TimeOut -eq 15){
                    Write-Host -ForegroundColor DarkRed "Timed out starting $service"
                    Continue
                }
                Write-Host -ForegroundColor Green "$service has successfully started."
            } else {
                Write-Host -ForegroundColor Green "$service is already running."
            }
        }
    }
    Write-Host
}

$FunctionBlock = @(
    ${function:StopServices}.Ast.Extent.Text
    ${function:RenameOldDirectories}.Ast.Extent.Text
    ${function:RestartServices}.Ast.Extent.Text
) -join "`n`n"

$RawWSUS_List = "KTPO-MJUROVCIK"

function Main{
    param ($RawWSUS_List, $FunctionBlock)
    

    foreach ($entry in $RawWSUS_List){
        $DomainName = "KTPO-andon-c13" #$entry.FullDomainName

        if (Test-Connection -ComputerName $DomainName -Count 1 -Quiet){

            $WinRM = Get-Service -ComputerName $DomainName -Name WinRM

            if($WinRM.Status -eq 'Running'){
                Write-Host -ForegroundColor Green "WinRM running on $DomainName"
            } else {
                Write-Host -ForegroundColor Green "Starting WinRM on $DomainName"
                sc.exe "\\$DomainName" start WinRM
                Start-Sleep -Seconds 3
                Set-Service -ComputerName $DomainName -StartupType Automatic -Name WinRM  
            }

            Invoke-Command -ComputerName $DomainName -ScriptBlock {
                param($FunctionBlock)

                $Services = (
                    "WaaSMedicSvc","wuauserv","CryptSvc","bits","msiserver"
                )

                .([scriptblock]::Create($FunctionBlock))
                
                StopServices
            
                RenameOldDirectories

                RestartServices

                wuauclt.exe /detectnow /reportnow
                $updateSession = new-object -com "Microsoft.Update.Session"; 
                $updateSession.CreateupdateSearcher().Search($criteria).Updates
                & "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -dynamicsignatures
                & "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate
                wuauclt.exe /reportnow

                pause

            } -ArgumentList $FunctionBlock

        } else {
            Write-Host -ForegroundColor DarkRed "Count not connect to $DomainName"
        }
    }
}  
        
Main -RawWSUS_List $RawWSUS_List -FunctionBlock $FunctionBlock

<#
        $CurrentVersion = Get-CimInstance -ComputerName $DomainName `
            -Namespace root\Microsoft\Windows\Defender `
            -ClassName MSFT_MpComputerStatus |
            Select-Object AntivirusSignatureVersion

        $SplitVersion = ($CurrentVersion -split "=")[-1]
        [string]$CleanVersion = ($SplitVersion -split "}")[0]
        Write-Host "Current definition version is $CleanVersion"



        if(Test-Path "\\$DomainName\c$\Security Definitions\mpam-fe.exe"){
            Write-Host -ForegroundColor Green "$DomainName already has file. Skipping copy"
        } elseif ((Test-Path "\\$DomainName\c$\Security Definitions") -and (-not (Test-Path "\\$DomainName\c$\Security Definitions\mpam-fe.exe"))){
            Write-Host -ForegroundColor Green "$DomainName has the folder but no file. Starting file copy"
            Copy-Item $UpdateDirectory "\\$DomainName\c$\Security Definitions"
        } else {
            Write-Host -ForegroundColor Green "$DomainName creating folder then beginning copy."
            New-Item -ItemType Directory -Path "\\$DomainName\c$\Security Definitions"
            Copy-Item $UpdateDirectory "\\$DomainName\c$\Security Definitions"     
        }

        if(-not (Test-Path "\\$DomainName\c$\Security Definitions\mpam-fe.exe")){
            Write-Host -ForegroundColor DarkRed "Copy failed on $DomainName."
            Continue
            Write-Host
            Write-Host
            #End
        }

        $WinRM = Get-Service -ComputerName $DomainName -Name WinRM

        if($WinRM.Status -eq 'Running'){
            Write-Host -ForegroundColor Green "WinRM running on $DomainName"
        } else {
            Write-Host -ForegroundColor Green "Starting WinRM on $DomainName"
            sc.exe "\\$DomainName" start WinRM
            Start-Sleep -Seconds 3
            Set-Service -ComputerName $DomainName -StartupType Automatic -Name WinRM  
        }

        Invoke-Command -ComputerName $DomainName -ScriptBlock {
            param ($DomainName, $CleanVersion)
            Write-Host -ForegroundColor Green "Starting process on $DomainName"
            $TimeOut = Start-Process "C:\Security Definitions\mpam-fe.exe" -ArgumentList "/run" -PassThru
            if (-not $TimeOut.WaitForInputIdle(30000)){
                Write-Host "$DomainName timed out. Killing process"
                Continue
            }
            
            UsoClient StartScan
            wuauclt /resetauthorization /detectnow
            wuauclt /reportnow

            
            [string]$NewVersion = (Get-MpComputerStatus).AntivirusSignatureVersion
            if ($NewVersion -notmatch $CleanVersion){
                Write-Host -ForegroundColor Green "Process complete on $DomainName"
                Write-Host -ForegroundColor Green "$DomainName went from $CleanVersion to $NewVersion"
            } elseif ($NewVersion -match $CleanVersion) {
                Write-Host -ForegroundColor Yellow "$DomainName definitons stayed the same version. Hopefully already up to date"
            } else {
                Write-Host -ForegroundColor DarkRed "Not sure what happened with $DomainName"
            }
            Write-Host
            Write-Host
            ##End

        } -ArgumentList $DomainName, $CleanVersion
    }
    Write-Host "Cant reach $DomainName."
    Write-Host
    Write-Host
    
}
}
#>


