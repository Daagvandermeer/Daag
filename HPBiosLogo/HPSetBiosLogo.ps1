###########################################################
#### Script Created by Daag van der Meer            #######
#### To Setup default company logo on Startup       #######
###########################################################


Start-Transcript -Path "$env:TEMP\$($(Split-Path $PSCommandPath -Leaf).ToLower().Replace(".ps1",".log"))" | Out-Null
 


 
if (Test-Path -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Firmware") {
    Write-Output "HP.ClientManagement folder already exists @ $env:ProgramFiles\WindowsPowerShell\Modules\HP.Firmware"
    Write-Output "Deleting the folder..."
    Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Firmware" -Recurse -Force
}

if (Test-Path -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Private") {
    Write-Output "HP.Private folder already exists @ $env:ProgramFiles\WindowsPowerShell\Modules\HP.Private"
    Write-Output "Deleting the folder..."
    Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Private" -Recurse -Force
}

if (Test-Path -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.ClientManagement") {
    Write-Output "HP.ClientManagement folder already exists @ $env:ProgramFiles\WindowsPowerShell\Modules\HP.ClientManagement"
    Write-Output "Deleting the folder..."
    Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.ClientManagement" -Recurse -Force
}
if (Test-Path -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Utility") {
    Write-Output "HP.Utility folder already exists @ $env:ProgramFiles\WindowsPowerShell\Modules\HP.Utility"
    Write-Output "Deleting the folder..."
    Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Utility" -Recurse -Force
}


 
Write-Output "Copying HP.Firmware module to: $env:ProgramFiles\WindowsPowerShell\Modules\HP.Firmware"
Copy-Item -Path "$PSScriptRoot\HP.Firmware\" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Firmware" -Recurse -Force

Write-Output "HP.Private module to: $env:ProgramFiles\WindowsPowerShell\Modules\HP.Private"
Copy-Item -Path "$PSScriptRoot\HP.Private\" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Private" -Recurse -Force

Write-Output "HP.ClientManagement module to: $env:ProgramFiles\WindowsPowerShell\Modules\HP.ClientManagement"
Copy-Item -Path "$PSScriptRoot\HP.ClientManagement\" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\HP.ClientManagement" -Recurse -Force

Write-Output "HP.Utility module to: $env:ProgramFiles\WindowsPowerShell\Modules\HP.Utility"
Copy-Item -Path "$PSScriptRoot\HP.Utility\" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\HP.Utility" -Recurse -Force


try {
    Import-Module "HP.Firmware" -Force -Verbose -ErrorAction Stop
}
catch {
    Write-Output "Error importing module: $_"
    exit 1
}
 
 Set-HPFirmwareBootLogo -File "$PSScriptRoot\Logo.jpg" -Password ""




