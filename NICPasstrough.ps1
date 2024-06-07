###########################################################
#### Script Created by Daag van der Meer            #######
#### Used because USB-C Dock nic Passtrough not working ###
###########################################################

$LocalMACName = "Intel(R) Ethernet Connection (16) I2*"
$USBMACName = "Lenovo USB Ethernet"
$ApprovedModel = "HP EliteBook 640 14 inch G10 Notebook PC"
$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"


$GetModel = Get-WmiObject -Class Win32_computersYSTEM | Select-Object -ExpandProperty Model

If ($ApprovedModel -ne $GetModel) { exit}

If ($ApprovedModel -eq $GetModel)
{
$LocalMAC = Get-NetAdapter -InterfaceDescription $LocalMACName |Select-Object -ExpandProperty MacAddress
$USBC = Get-NetAdapter -InterfaceDescription $USBMACName |Select-Object -ExpandProperty MacAddress

If ($LocalMAC -ne $USBC)
{

$regkeys = Get-ChildItem -Path $key | Select-Object -ExpandProperty Name

Foreach ($regkey in $regkeys)
{
$regkey = $regkey -replace 'HKEY_LOCAL_MACHINE','HKLM:'
$Search = Get-ItemProperty -Path $regkey |Select-Object -ExpandProperty DriverDesc


$LocalMAC = $LocalMAC -replace '-',''


If ($Search -eq $USBMACName)
{New-ItemProperty -Path $regkey -name NetworkAddress -Value $LocalMAC}


}

}
If ($LocalMAC -eq $USBC){ Write-host MAC is equal}
}