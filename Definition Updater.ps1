$WSUS_Server = Get-WsusServer -Name "KTPO-WSUS" -PortNumber 8530
$CurrentSystem = $env:COMPUTERNAME

if($WSUS_Server) {Write-Host "Got server"}
Get-WsusComputer -UpdateServer $WSUS_Server -ComputerTargetGroups "All Computers" | Sort-Object -Descending
$GroupsToIgnore