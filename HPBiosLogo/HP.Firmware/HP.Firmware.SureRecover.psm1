# 
#  Copyright 2018-2024 HP Development Company, L.P.
#  All Rights Reserved.
# 
# NOTICE:  All information contained herein is, and remains the property of HP Development Company, L.P.
# 
# The intellectual and technical concepts contained herein are proprietary to HP Development Company, L.P
# and may be covered by U.S. and Foreign Patents, patents in process, and are protected by 
# trade secret or copyright law. Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained from HP Development Company, L.P.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
#requires -Modules "HP.Private" 


[Flags()] enum DeprovisioningTarget{
  AgentProvisioning = 1
  OSImageProvisioning = 2
  ConfigurationData = 4
  TriggerRecoveryData = 8
  ScheduleRecoveryData = 16
}


# Converts a BIOS value to a boolean
function ConvertValue {
  param($value)
  if ($value -eq "Enable" -or $value -eq "Yes") { return $true }
  $false
}


<#
.SYNOPSIS
  Retrieves the current state of the HP Sure Recover feature

.DESCRIPTION
  This command retrieves the current state of the HP Sure Recover feature.

  Refer to the New-HPSureRecoverConfigurationPayload command for more information on how to configure HP Sure Recover.

.PARAMETER All
  If specified, the output includes the OS Recovery Image and the OS Recovery Agent configuration.

.NOTES
  - Requires HP BIOS with HP Sure Recover support.
  - This command requires elevated privileges.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK 
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.EXAMPLE
  Get-HPSureRecoverState
#>
function Get-HPSureRecoverState
{
  [CmdletBinding(HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPSureRecoverState")]
  param([switch]$All)
  $mi_result = 0
  $data = New-Object -TypeName surerecover_state_t
  $c = '[DfmNativeSureRecover]::get_surerecover_state' + (Test-OSBitness) + '([ref]$data,[ref]$mi_result);'
  $result = Invoke-Expression -Command $c
  Test-HPPrivateCustomResult -result 0x80000711 -mi_result $mi_result -Category 0x05 -Verbose:$VerbosePreference

  $fixed_version = "$($data.subsystem_version[0]).$($data.subsystem_version[1])"
  if ($fixed_version -eq "0.0") {
    Write-Verbose "Patched SureRecover version 0.0 to 1.0"
    $fixed_version = "1.0"
  }
  $SchedulerIsDisabled = ($data.schedule.window_size -eq 0)

  $RecoveryTimeBetweenRetries = ([uint32]$data.os_flags -shr 8) -band 0x0f
  $RecoveryNumberOfRetries = ([uint32]$data.os_flags -shr 12) -band 0x07
  if ($RecoveryNumberOfRetries -eq 0)
  {
    $RecoveryNumberOfRetries = "Infinite"
  }
  $imageFailoverIsConfigured = [bool]$data.image_failover

  $obj = [ordered]@{
    Version = $fixed_version
    Nonce = $data.Nonce
    BIOSFlags = ($data.os_flags -band 0xff)
    ImageIsProvisioned = (($data.flags -band 2) -ne 0)
    AgentFlags = ($data.re_flags -band 0xff)
    AgentIsProvisioned = (($data.flags -band 1) -ne 0)
    RecoveryTimeBetweenRetries = $RecoveryTimeBetweenRetries
    RecoveryNumberOfRetries = $RecoveryNumberOfRetries
    Schedule = New-Object -TypeName PSObject -Property @{
      DayOfWeek = $data.schedule.day_of_week
      hour = [uint32]$data.schedule.hour
      minute = [uint32]$data.schedule.minute
      WindowSize = [uint32]$data.schedule.window_size
    }
    ConfigurationDataIsProvisioned = (($data.flags -band 4) -ne 0)
    TriggerRecoveryDataIsProvisioned = (($data.flags -band 8) -ne 0)
    ScheduleRecoveryDataIsProvisioned = (($data.flags -band 16) -ne 0)
    SchedulerIsDisabled = $SchedulerIsDisabled
    ImageFailoverIsConfigured = $imageFailoverIsConfigured
  }

  if ($all.IsPresent)
  {
    $ia = [ordered]@{
      Url = (Get-HPBIOSSettingValue -Name "OS Recovery Image URL")
      Username = (Get-HPBIOSSettingValue -Name "OS Recovery Image Username")
      #PublicKey = (Get-HPBiosSettingValue -name "OS Recovery Image Public Key")
      ProvisioningVersion = (Get-HPBIOSSettingValue -Name "OS Recovery Image Provisioning Version")
    }

    $aa = [ordered]@{
      Url = (Get-HPBIOSSettingValue -Name "OS Recovery Agent URL")
      Username = (Get-HPBIOSSettingValue -Name "OS Recovery Agent Username")
      #PublicKey = (Get-HPBiosSettingValue -name "OS Recovery Agent Public Key")
      ProvisioningVersion = (Get-HPBIOSSettingValue -Name "OS Recovery Agent Provisioning Version")
    }

    $Image = New-Object -TypeName PSObject -Property $ia
    $Agent = New-Object -TypeName PSObject -Property $aa

    $obj.Add("Image",$Image)
    $osFailover = New-Object System.Collections.Generic.List[PSCustomObject]
    if ($imageFailoverIsConfigured) {
      try {
        $osFailoverIndex = Get-HPSureRecoverFailoverConfiguration -Image 'os'
        $osFailover.Add($osFailoverIndex)
      }
      catch {
        Write-Warning "Error reading OS Failover configuration $($Index): $($_.Exception.Message)"
      }
      $obj.Add("ImageFailover",$osFailover)
    }

    $obj.Add("Agent",$Agent)
  }
  return New-Object -TypeName PSCustomObject -Property $obj
}

<#
.SYNOPSIS
  Retrieves the current HP Sure Recover failover configuration

.DESCRIPTION
  This command retrieves the current configuration of the HP Sure Recover failover feature.

.PARAMETER Image
  Specifies whether this command will create a configuration payload for a Recovery Agent image or a Recovery OS image. However, only the value 'os' is supported for now.

.NOTES
  - Requires HP BIOS with HP Sure Recover and Failover support.
  - This command requires elevated privileges.

.EXAMPLE
  Get-HPSureRecoverFailoverConfiguration -Image os
#>
function Get-HPSureRecoverFailoverConfiguration
{
  [CmdletBinding(HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPSureRecoverFailoverConfiguration")]
  param(
    [ValidateSet("os")]
    [Parameter(Mandatory = $false,Position = 0)]
    [string]$Image = 'os'
  )

  $mi_result = 0
  $data = New-Object -TypeName surerecover_failover_configuration_t
  $index = 1
  $c = '[DfmNativeSureRecover]::get_surerecover_failover_configuration' + (Test-OSBitness) + '([bool]$False,[int]$index,[ref]$data,[ref]$mi_result);'
  try {
    $result = Invoke-Expression -Command $c
    Test-HPPrivateCustomResult -result $result -mi_result $mi_result -Category 0x05 -Verbose:$VerbosePreference
  }
  catch {
    Write-Error "Failover is not configured properly. Error: $($_.Exception.Message)"
  }

  return [PSCustomObject]@{
    Index = $Index
    Version = $data.version
    Url = $data.url
    Username = $data.username
  }
}

<#
.SYNOPSIS
  Retrieves information about the HP Sure Recover embedded reimaging device

.DESCRIPTION
  This command retrieves information about the embedded reimaging device for HP Sure Recover.

.NOTES
  The embedded reimaging device is an optional hardware feature, and if not present, the field Embedded Reimaging Device is false.

.NOTES
  - Requires HP BIOS with HP Sure Recover support
  - Requires Embedded Reimaging device hardware option
  - This command requires elevated privileges.

.LINK
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.EXAMPLE
  Get-HPSureRecoverReimagingDeviceDetails
#>
function Get-HPSureRecoverReimagingDeviceDetails
{
  [CmdletBinding(HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPSureRecoverReimagingDeviceDetails")]
  param()
  $result = @{}

  try {
    [int]$ImageVersion = Get-HPBIOSSettingValue -Name "OS Recovery Image Version"
    $result.Add("ImageVersion",$ImageVersion)

  }
  catch {}

  try {
    [int]$DriverVersion = Get-HPBIOSSettingValue -Name "OS Recovery Driver Version"
    $result.Add("DriverVersion",$DriverVersion)
  }
  catch {}

  $result.Add("Embedded Reimaging Device",(Test-Path variable:ImageVersion) -and (Test-Path variable:DriverVersion))
  $result
}

<#
.SYNOPSIS
  Creates a payload to configure the HP Sure Recover OS or Recovery image

.DESCRIPTION
  This command creates a payload to configure a custom HP Sure Recover OS or Recovery image. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 

  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter.
  This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER Image
  Specifies whether this command will create a configuration payload for a Recovery Agent image or a Recovery OS image. The value must be either 'agent' or 'os'.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key as a PFX file. If the PFX file is protected by a password (recommended), the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate as an X509Certificate object

.PARAMETER ImageCertificateFile
  Specifies the path to the image signing certificate as a PFX file. If the PFX file is protected by a password (recommended), the ImageCertificatePassword parameter should also be provided. Depending on the Image switch, this will be either the signing key file for the Agent or the OS image.
  ImageCertificateFile and PublicKeyFile are mutually exclusive.

.PARAMETER ImageCertificatePassword
  Specifies the image signing key file password, if required

.PARAMETER ImageCertificate
  Specifies the image signing key certificate as an X509Certificate object. Depending on the Image parameter, this value will be either the signing key certificate for the Agent or the OS image.

.PARAMETER PublicKeyFile
  Specifies the image signing key as the path to a base64-encoded RSA key (a PEM file).
  ImageCertificateFile and PublicKeyFile are mutually exclusive.

.PARAMETER PublicKey
  Specifies the image signing key as an array of bytes, including modulus and exponent.
  This option is currently reserved for internal use.

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER Version
  Specifies the operation version. Each new configuration payload must increment the last operation payload version, as available in the public WMI setting 'OS Recovery Image Provisioning Version'. If this parameter is not provided, this command will read the public wmi setting and increment it automatically.

.PARAMETER Username
  Specifies the username for accessing the url specified in the Url parameter, if any.

.PARAMETER Password
  Specifies the password for accessing the url specified in the Url parameter, if any.

.PARAMETER Url
  Specifies the url from where to download the image. If not specified, the default HP.COM location will be used. 

.PARAMETER OutputFile
  Specifies the file to write output to instead of writing the output to the pipeline

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/)

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.NOTES
  - Requires HP BIOS with HP Sure Recover support 

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)  

.EXAMPLE
   $payload = New-HPSureRecoverImageConfigurationPayload -SigningKeyFile "$path\signing_key.pfx" -Image OS -ImageKeyFile  `
                 "$path\os.pfx" -username my_http_user -password `s3cr3t`  -url "http://my.company.com"
   ...
   $payload | Set-HPSecurePlatformPayload
#>
function New-HPSureRecoverImageConfigurationPayload
{
  [CmdletBinding(DefaultParameterSetName = "SKFileCert_OSFilePem",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverImageConfigurationPayload")]
  param(
    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $true,Position = 0)]
    [ValidateSet("os","agent")]
    [string]$Image,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $true,Position = 1)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $true,Position = 1)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $true,Position = 1)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $true,Position = 1)]
    [System.IO.FileInfo]$SigningKeyFile,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 2)]
    [string]$SigningKeyPassword,

    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $true,Position = 3)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningKeyCertificate,


    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $true,Position = 1)]
    [Alias("ImageKeyFile")]
    [System.IO.FileInfo]$ImageCertificateFile,

    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 2)]
    [Alias("ImageKeyPassword")]
    [string]$ImageCertificatePassword,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $true,Position = 6)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $true,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $true,Position = 1)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$ImageCertificate,


    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $true,Position = 7)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $true,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $true,Position = 1)]
    [System.IO.FileInfo]$PublicKeyFile,


    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $true,Position = 8)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $true,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $true,Position = 1)]
    [byte[]]$PublicKey,


    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 2)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),


    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 3)]
    [uint16]$Version,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 4)]
    [string]$Username,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 12)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 5)]
    [string]$Password,

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 13)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 6)]
    [uri]$Url = "",

    [Parameter(ParameterSetName = "SKFileCert_OSBytesCert",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesCert",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKFileCert_OSFileCert",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFileCert",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKFileCert_OSBytesPem",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKBytesCert_OSBytesPem",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKFileCert_OSFilePem",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "SKBytesCert_OSFilePem",Mandatory = $false,Position = 14)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 7)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $true,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $true,Position = 9)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $true,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $true,Position = 8)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $true,Position = 9)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $true,Position = 10)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $true,Position = 9)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $true,Position = 9)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning_OSBytesCert",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFileCert",Mandatory = $false,Position = 11)]
    [Parameter(ParameterSetName = "RemoteSigning_OSBytesPem",Mandatory = $false,Position = 10)]
    [Parameter(ParameterSetName = "RemoteSigning_OSFilePem",Mandatory = $false,Position = 10)]
    [switch]$CacheAccessToken
  )

  Write-Verbose "Creating SureRecover Image provisioning payload"


  if ($PublicKeyFile -or $PublicKey) {
    $osk = Get-HPPrivatePublicKeyCoalesce -File $PublicKeyFile -key $PublicKey -Verbose:$VerbosePreference
  }
  else {
    $osk = Get-HPPrivateX509CertCoalesce -File $ImageCertificateFile -password $ImageCertificatePassword -cert $ImageCertificate -Verbose:$VerbosePreference
  }

  $OKBytes = $osk.Modulus

  $opaque = New-Object opaque4096_t
  $opaqueLength = 4096
  $mi_result = 0

  if (-not $Version) {
    if ($image -eq "os")
    {
      $Version = [uint16](Get-HPBIOSSettingValue "OS Recovery Image Provisioning Version") + 1
    }
    else {
      $Version = [uint16](Get-HPBIOSSettingValue "OS Recovery Agent Provisioning Version") + 1
    }
    Write-Verbose "New version number is $version"
  }

  $cmd = '[DfmNativeSureRecover]::get_surerecover_provisioning_opaque' + (Test-OSBitness) + '($Nonce, $Version, $OKBytes,$($OKBytes.Count),$Username, $Password, $($Url.ToString()), [ref]$opaque, [ref]$opaqueLength,  [ref]$mi_result);'
  $result = Invoke-Expression -Command $cmd
  Test-HPPrivateCustomResult -result $result -mi_result $mi_result -Category 0x05

  $payload = $opaque.raw[0..($opaqueLength - 1)]

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning_OSBytesCert" -or $PSCmdlet.ParameterSetName -eq "RemoteSigning_OSFileCert" -or $PSCmdlet.ParameterSetName -eq "RemoteSigning_OSBytesPem" -or $PSCmdlet.ParameterSetName -eq "RemoteSigning_OSFilePem") {
    $sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SigningKeyPassword -cert $SigningKeycertificate -Verbose:$VerbosePreference
    $sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }

  [byte[]]$out = $sig + $payload

  Write-Verbose "Building output document"
  $output = New-Object -TypeName PortableFileFormat
  $output.Data = $out

  if ($Image -eq "os") {
    $output.purpose = "hp:surerecover:provision:os_image"
  }
  else {
    $output.purpose = "hp:surerecover:provision:recovery_image"
  }

  Write-Verbose "Provisioning version will be $version"
  $output.timestamp = Get-Date

  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }
}



<#
.SYNOPSIS
  Creates a payload to deprovision HP Sure Recover

.DESCRIPTION
  This command creates a payload to deprovision the HP Sure Recover feature. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 

  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter. This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload command. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key as a PFX file. If the PFX file is protected by a password (recommended), the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required.

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate as an X509Certificate object. 

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER RemoveOnly
  This parameter allows deprovisioning only specific parts of the Sure Recover subsystem. If not specified, the entire SureRecover is deprovisoned. Possible values are one or more of the following:

  - AgentProvisioning   - remove the Agent provisioning
  - OSImageProvisioning - remove the OS Image provisioning
  - ConfigurationData - remove HP SureRecover configuration data 
  - TriggerRecoveryData - remove the HP Sure Recover trigger definition
  - ScheduleRecoveryData - remove the HP Sure Recover schedule definition

.PARAMETER OutputFile
    Specifies the file to write output to instead of writing the output to the pipelineing output to the specified file, instead of writing it to the pipeline.

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/)

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.NOTES
  - Requires HP BIOS with HP Sure Recover support

.EXAMPLE
  New-HPSureRecoverDeprovisionPayload -SigningKeyFile sk.pfx
#>
function New-HPSureRecoverDeprovisionPayload
{
  [CmdletBinding(DefaultParameterSetName = "SF",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverDeprovisionPayload")]
  param(
    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 0)]
    [System.IO.FileInfo]$SigningKeyFile,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 1)]
    [string]$SigningKeyPassword,

    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 0)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningKeyCertificate,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 0)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 1)]
    [DeprovisioningTarget[]]$RemoveOnly,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 2)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 3)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 4)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 5)]
    [switch]$CacheAccessToken
  )

  Write-Verbose "Creating SureRecover deprovisioning payload"
  if ($RemoveOnly) {
    [byte]$target = 0
    $RemoveOnly | ForEach-Object { $target = $target -bor $_ }
    Write-Verbose "Will deprovision only $([string]$RemoveOnly)"
  }
  else
  {
    [byte]$target = 31 # all five bits
    Write-Verbose "No deprovisioning filter specified, will deprovision all SureRecover"
  }

  $payload = [BitConverter]::GetBytes($nonce) + $target

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning") {
    $sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SigningKeyPassword -cert $SigningKeycertificate -Verbose:$VerbosePreference
    $sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }

  Write-Verbose "Building output document"
  $output = New-Object -TypeName PortableFileFormat
  $output.Data = $sig + $payload
  $output.purpose = "hp:surerecover:deprovision"
  $output.timestamp = Get-Date

  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }
}



<#
.SYNOPSIS
    Creates a payload to configure the HP Sure Recover schedule

.DESCRIPTION
  This command creates a payload to configure a HP Sure Recover schedule. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 
  
  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter. This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload command. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key, as a PFX file. If the PFX file is protected by a password (recommended),
  the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required.

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate, as an X509Certificate object. 

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER DayOfWeek
  Specifies the day of the week for the schedule

.PARAMETER Hour
  Specifies the hour value for the schedule

.PARAMETER Minute
  Specifies the minute of the schedule

.PARAMETER WindowSize
  Specifies the windows size for the schedule activation in minutes, in case the exact configured schedule is
  missed. By default, the window is zero. The value may not be larger than 240 minutes (4 hours).

.PARAMETER Disable
  If specified, this command creates a payload to disable HP Sure Recover schedule.

.PARAMETER OutputFile
  Specifies the file to write output to instead of writing the output to the pipelineing output to the specified file, instead of writing it to the pipeline.

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/)

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.NOTES
  - Requires HP BIOS with HP Sure Recover support

.EXAMPLE
  New-HPSureRecoverSchedulePayload -SigningKeyFile sk.pfx -DayOfWeek Sunday -Hour 2

.EXAMPLE
  New-HPSureRecoverSchedulePayload -SigningKeyFile sk.pfx -Disable
#>
function New-HPSureRecoverSchedulePayload
{
  [CmdletBinding(DefaultParameterSetName = "SF",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverSchedulePayload")]
  param(

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "DisableSF",Mandatory = $true,Position = 0)]
    [System.IO.FileInfo]$SigningKeyFile,

    [Parameter(ValueFromPipeline,ParameterSetName = "SB",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "DisableSB",Mandatory = $true,Position = 0)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningKeyCertificate,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 1)]
    [Parameter(ParameterSetName = "DisableSF",Mandatory = $false,Position = 1)]
    [string]$SigningKeyPassword,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 1)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 0)]
    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $false,Position = 0)]
    [Parameter(ParameterSetName = "DisableSF",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "DisableSB",Mandatory = $false,Position = 1)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 1)]
    [surerecover_day_of_week]$DayOfWeek = [surerecover_day_of_week]::Sunday,

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 2)]
    [ValidateRange(0,23)]
    [uint32]$Hour = 0,

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 5)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 3)]
    [ValidateRange(0,59)]
    [uint32]$Minute = 0,

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 6)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 4)]
    [ValidateRange(1,240)]
    [uint32]$WindowSize = 0,

    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $true,Position = 1)]
    [Parameter(ParameterSetName = "DisableSF",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "DisableSB",Mandatory = $true,Position = 2)]
    [switch]$Disable,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "DisableSF",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "DisableSB",Mandatory = $false,Position = 3)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 6)]
    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $true,Position = 3)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 7)]
    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $true,Position = 4)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 8)]
    [Parameter(ParameterSetName = "DisableRemoteSigning",Mandatory = $false,Position = 5)]
    [switch]$CacheAccessToken
  )

  Write-Verbose "Creating SureRecover scheduling payload"
  $schedule_data = New-Object -TypeName surerecover_schedule_data_t

  Write-Verbose "Will set the SureRecover scheduler"
  $schedule_data.day_of_week = $DayOfWeek
  $schedule_data.hour = $Hour
  $schedule_data.minute = $Minute
  $schedule_data.window_size = $WindowSize

  $schedule = New-Object -TypeName surerecover_schedule_data_payload_t
  $schedule.schedule = $schedule_data
  $schedule.Nonce = $Nonce

  $cmd = New-Object -TypeName surerecover_schedule_payload_t
  $cmd.Data = $schedule
  [byte[]]$payload = (Convert-HPPrivateObjectToBytes -obj $schedule -Verbose:$VerbosePreference)[0]

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning" -or $PSCmdlet.ParameterSetName -eq "DisableRemoteSigning") {
    $cmd.sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SigningKeyPassword -cert $SigningKeycertificate -Verbose:$VerbosePreference
    $cmd.sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }

  Write-Verbose "Building output document"
  $output = New-Object -TypeName PortableFileFormat

  $output.Data = (Convert-HPPrivateObjectToBytes -obj $cmd -Verbose:$VerbosePreference)[0]
  $output.purpose = "hp:surerecover:scheduler"
  $output.timestamp = Get-Date


  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }
}


<#
.SYNOPSIS
  Creates a payload to configure HP Sure Recover

.DESCRIPTION
  This command create a payload to configure HP Sure Recover. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 

  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter.
  This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload command. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key as a PFX file. If the PFX file is protected by a password (recommended), the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required.

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate as an X509Certificate object.

.PARAMETER SigningKeyModulus
  The Secure Platform Management signing key modulus

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER BIOSFlags
  Specifies the imaging flags to set. Please note that this parameter was previously named OSImageFlags.
  None = 0 
  NetworkBasedRecovery = 1 => Enable network based recovery
  WiFi = 2 => Enable WiFi
  PartitionRecovery = 4 => Enable partition based recovery
  SecureStorage = 8 => Enable recovery from secure storage device
  SecureEraseUnit = 16 => Secure Erase Unit before recovery
  RollbackPrevention = 64 => Enforce rollback prevention 

.PARAMETER AgentFlags
  Specifies the agent flags to set:
  None = 0 => OEM OS release with in-box drivers
  DRDVD = 1 => OEM OS release with optimized drivers 
  CorporateReadyWithoutOffice = 2 => Corporate ready without office
  CorporateReadyWithOffice = 4 => Corporate ready with office
  InstallManageabilitySuite = 16 => Install current components of the Manageability Suite included on the DRDVD
  InstallSecuritySuite = 32 => Install current components of the Security Suite included on the DRDVD 
  RollbackPrevention = 64 => Enforce rollback prevention

.PARAMETER OutputFile
  Specifies the file to write output to instead of writing the output to the pipelineing output to the specified file, instead of writing it to the pipeline.

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/)

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.NOTES
  - Requires HP BIOS with HP Sure Recover support

.EXAMPLE
  New-HPSureRecoverConfigurationPayload -SigningKeyFile sk.pfx -BIOSFlags WiFi -AgentFlags DRDVD

.EXAMPLE
  New-HPSureRecoverConfigurationPayload -SigningKeyFile sk.pfx -BIOSFlags WiFi,SecureStorage -AgentFlags DRDVD,RollbackPrevention
#>
function New-HPSureRecoverConfigurationPayload
{
  [CmdletBinding(DefaultParameterSetName = "SF",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverConfigurationPayload")]
  param(

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 0)]
    [System.IO.FileInfo]$SigningKeyFile,

    [Parameter(ValueFromPipeline,ParameterSetName = "SB",Mandatory = $true,Position = 0)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningKeyCertificate,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 1)]
    [string]$SigningKeyPassword,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 0)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 1)]
    [Alias("OSImageFlags")]
    [surerecover_os_flags]$BIOSFlags,

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 5)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 2)]
    [surerecover_re_flags]$AgentFlags,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 3)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 4)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 5)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 6)]
    [switch]$CacheAccessToken
  )

  $data = New-Object -TypeName surerecover_configuration_payload_t
  $data.os_flags = [uint32]$BIOSFlags
  $data.re_flags = [uint32]$AgentFlags
  $data.arp_counter = $Nonce

  $cmd = New-Object -TypeName surerecover_configuration_t
  $cmd.Data = $data

  [byte[]]$payload = (Convert-HPPrivateObjectToBytes -obj $data -Verbose:$VerbosePreference)[0]

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning") {
    $cmd.sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SigningKeyPassword -cert $SigningKeycertificate
    $cmd.sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }

  Write-Verbose "Building output document"
  $output = New-Object -TypeName PortableFileFormat
  $output.Data = (Convert-HPPrivateObjectToBytes -obj $cmd -Verbose:$VerbosePreference)[0]
  $output.purpose = "hp:surerecover:configure"
  $output.timestamp = Get-Date


  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }

}

<#
.SYNOPSIS
  Creates a payload to configure HP Sure Recover OS or Recovery image failover

.DESCRIPTION
  This command creates a payload to configure HP Sure Recover OS or Recovery image failover. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 

  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter. This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload command. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER Image
  Specifies whether this command will create a configuration payload for a Recovery Agent image or a Recovery OS  image. For now, only 'os' is supported.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key, as a PFX file. If the PFX file is protected by a password (recommended),
  the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required.

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate as an X509Certificate object.

.PARAMETER Version
  Specifies the operation version. Each new configuration payload must increment the last operation payload version, as available in the Get-HPSureRecoverFailoverConfiguration. If this parameter is not provided, this command will read from current system and increment it automatically.

.PARAMETER Username
  Specifies the username for accessing the url specified in the Url parameter, if any.

.PARAMETER Password
  Specifies the password for accessing the url specified in the Url parameter, if any.

.PARAMETER Url
  Specifies the URL from where to download the image. An empty URL can be specified to deprovision Failover.

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER OutputFile
  Specifies the file to write output to instead of writing the output to the pipelineing output to the specified file, instead of writing it to the pipeline.

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/) 

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.NOTES
  - Requires HP BIOS with HP Sure Recover support

.EXAMPLE
  New-HPSureRecoverFailoverConfigurationPayload -SigningKeyFile sk.pfx -Version 1 -Url ''

.EXAMPLE
  New-HPSureRecoverFailoverConfigurationPayload -SigningKeyFile sk.pfx -Image os -Version 1 -Nonce 2 -Url 'http://url.com/' -Username 'user' -Password 123
#>
function New-HPSureRecoverFailoverConfigurationPayload
{
  [CmdletBinding(DefaultParameterSetName = "SF",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverFailoverConfigurationPayload")]
  param(

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 0)]
    [System.IO.FileInfo]$SigningKeyFile,

    [Parameter(ValueFromPipeline,ParameterSetName = "SB",Mandatory = $true,Position = 0)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningKeyCertificate,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 1)]
    [string]$SigningKeyPassword,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 1)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 0)]
    [ValidateSet("os")]
    [string]$Image = "os",

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 1)]
    [uint16]$Version,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 2)]
    [string]$Username,

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 3)]
    [string]$Password,

    [Parameter(ParameterSetName = "SF",Mandatory = $true,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $true,Position = 2)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 4)]
    [uri]$Url = "",

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 5)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),

    [Parameter(ParameterSetName = "SF",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "SB",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 6)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 7)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $true,Position = 8)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning",Mandatory = $false,Position = 9)]
    [switch]$CacheAccessToken
  )

  if (-not $Version) {
    try {
      $Version = (Get-HPSureRecoverFailoverConfiguration -Image $Image).Version + 1
    }
    catch {
      # It is not possible to get current version if failover is not configured yet, assigning version 1
      $Version = 1
    }
    Write-Verbose "New version number is $version"
  }

  $opaque = New-Object opaque4096_t
  $opaqueLength = 4096
  $mi_result = 0
  [byte]$index = 1

  $cmd = '[DfmNativeSureRecover]::get_surerecover_failover_opaque' + (Test-OSBitness) + '($Nonce, $Version, $index, $Username, $Password, $($Url.ToString()), [ref]$opaque, [ref]$opaqueLength, [ref]$mi_result);'
  $result = Invoke-Expression -Command $cmd
  Test-HPPrivateCustomResult -result $result -mi_result $mi_result -Category 0x05

  [byte[]]$payload = $opaque.raw[0..($opaqueLength - 1)]

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning") {
    $sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SigningKeyPassword -cert $SigningKeycertificate
    $sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }

  [byte[]]$out = $sig + $payload

  Write-Verbose "Building output document"
  $output = New-Object -TypeName PortableFileFormat
  $output.Data = $out
  $output.purpose = "hp:surerecover:failover:os_image"
  $output.timestamp = Get-Date

  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }

}

<#
.SYNOPSIS
  Creates a payload to trigger HP Sure Recover events

.DESCRIPTION
  This command creates a payload to trigger HP Sure Recover. There are three signing options to choose from:
  - Signing Key File (and Password) using -SigningKeyFile and -SigningKeyPassword parameters 
  - Signing Key Certificate using -SigningKeyCertificate parameter
  - Remote Signing using -RemoteSigningServiceKeyID and -RemoteSigningServiceURL parameters 

  Please note that using a Key File with Password in PFX format is recommended over using an X509 Certificate object because a private key in a certificate is not password protected.

  This command writes the created payload to the pipeline or to the file specified in the OutputFile parameter. This payload can then be passed to the Set-HPSecurePlatformPayload command.

  Security note: Payloads should only be created on secure servers. Once created, the payload may be transferred to a client and applied via the Set-HPSecurePlatformPayload command. Creating the payload and passing it to the Set-HPSecurePlatformPayload command via the pipeline is not a recommended production pattern.

.PARAMETER SigningKeyFile
  Specifies the path to the Secure Platform Management signing key as a PFX file. If the PFX file is protected by a password (recommended), the SigningKeyPassword parameter should also be provided.

.PARAMETER SigningKeyPassword
  Specifies the Secure Platform Management signing key file password, if required.

.PARAMETER SigningKeyCertificate
  Specifies the Secure Platform Management signing key certificate as an X509Certificate object

.PARAMETER Nonce
  Specifies a Nonce. If nonce is specified, the Secure Platform Management subsystem will only accept commands with a nonce greater or equal to the last nonce sent. This approach helps to prevent replay attacks. If not specified, the nonce is inferred from the current local time. The current local time as the nonce works in most cases. However, this approach has a resolution of seconds, so when performing parallel operations or a high volume of operations, it is possible for the same counter to be interpreted for more than one command. In these cases, the caller should use its own nonce derivation and provide it through this parameter.

.PARAMETER Set
  If specified, this command sets the trigger information. This parameter is used by default and optional.

.PARAMETER Cancel
  If specified, this command clears any existing trigger definition.

.PARAMETER ForceAfterReboot
  Specifies how many reboots to count before applying the trigger. If not specified, the value defaults to 1 (next reboot).    

.PARAMETER PromptPolicy
  Specifies the prompting policy. If not specified, it will default to prompt before recovery, and on error.

.PARAMETER ErasePolicy
  Specifies the erase policy for the imaging process

.PARAMETER OutputFile
  Specifies the file to write output to instead of writing the output to the pipelineing output to the specified file, instead of writing it to the pipeline.

.PARAMETER RemoteSigningServiceKeyID
  Specifies the Signing Key ID to be used

.PARAMETER RemoteSigningServiceURL
  Specifies the (Key Management Service) KMS server URL (I.e.: https://<KMSAppName>.azurewebsites.net/)

.PARAMETER CacheAccessToken
  If specified, the access token is cached in msalcache.dat file and user credentials will not be asked again until the credentials expire.
  This parameter should be specified for caching the access token when performing multiple operations on the KMS server. 
  If access token is not cached, the user must re-enter credentials on each call of this command.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)

.NOTES
  - Requires HP BIOS with HP Sure Recover support

.EXAMPLE
  New-HPSureRecoverTriggerRecoveryPayload -SigningKeyFile sk.pfx
#>
function New-HPSureRecoverTriggerRecoveryPayload
{
  [CmdletBinding(DefaultParameterSetName = "SF_Schedule",HelpUri = "https://developers.hp.com/hp-client-management/doc/New-HPSureRecoverTriggerRecoveryPayload")]
  param(

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $true,Position = 0)]
    [Parameter(ParameterSetName = "SF_Cancel",Mandatory = $true,Position = 0)]
    [string]$SigningKeyFile,

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 1)]
    [Parameter(ParameterSetName = "SF_Cancel",Mandatory = $false,Position = 1)]
    [string]$SigningKeyPassword,

    [Parameter(ValueFromPipeline,ParameterSetName = "SB_Schedule",Mandatory = $true,Position = 0)]
    [Parameter(ValueFromPipeline,ParameterSetName = "SB_Cancel",Mandatory = $true,Position = 0)]
    [byte[]]$SigningKeyCertificate,

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SF_Cancel",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "SB_Cancel",Mandatory = $false,Position = 3)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 0)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $false,Position = 0)]
    [uint32]$Nonce = [math]::Floor([decimal](Get-Date (Get-Date).ToUniversalTime() -UFormat "%s").Replace(',','.')),

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 1)]
    [switch]$Set,

    [Parameter(ParameterSetName = "SF_Cancel",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "SB_Cancel",Mandatory = $true,Position = 4)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $true,Position = 1)]
    [switch]$Cancel,

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 2)]
    [ValidateRange(1,7)]
    [byte]$ForceAfterReboot = 1,

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 3)]
    [surerecover_prompt_policy]$PromptPolicy = "PromptBeforeRecovery,PromptOnError",

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 8)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 4)]
    [surerecover_erase_policy]$ErasePolicy = "None",

    [Parameter(ParameterSetName = "SF_Schedule",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SB_Schedule",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SF_Cancel",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "SB_Cancel",Mandatory = $false,Position = 9)]
    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 5)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $false,Position = 2)]
    [System.IO.FileInfo]$OutputFile,

    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $true,Position = 6)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $true,Position = 3)]
    [string]$RemoteSigningServiceKeyID,

    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $true,Position = 7)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $true,Position = 4)]
    [string]$RemoteSigningServiceURL,

    [Parameter(ParameterSetName = "RemoteSigning_Schedule",Mandatory = $false,Position = 8)]
    [Parameter(ParameterSetName = "RemoteSigning_Cancel",Mandatory = $false,Position = 5)]
    [switch]$CacheAccessToken
  )

  $data = New-Object -TypeName surerecover_trigger_payload_t
  $data.arp_counter = $Nonce
  $data.bios_trigger_flags = 0

  $output = New-Object -TypeName PortableFileFormat

  if ($Cancel.IsPresent)
  {
    Write-Verbose "Creating payload to cancel trigger"
    $output.purpose = "hp:surerecover:trigger"
    $data.bios_trigger_flags = 0
    $data.re_trigger_flags = 0
  }
  else {
    Write-Verbose ("Creating payload to set trigger")
    $output.purpose = "hp:surerecover:trigger"
    $data.bios_trigger_flags = [uint32]$ForceAfterReboot
    $data.re_trigger_flags = [uint32]$PromptPolicy
    $data.re_trigger_flags = ([uint32]$ErasePolicy -shl 4) -bor $data.re_trigger_flags
  }

  $cmd = New-Object -TypeName surerecover_trigger_t
  $cmd.Data = $data

  [byte[]]$payload = (Convert-HPPrivateObjectToBytes -obj $data -Verbose:$VerbosePreference)[0]

  if ($PSCmdlet.ParameterSetName -eq "RemoteSigning_Schedule" -or $PSCmdlet.ParameterSetName -eq "RemoteSigning_Cancel") {
    $cmd.sig = Invoke-HPPrivateRemoteSignData -Data $payload -CertificateId $RemoteSigningServiceKeyID -KMSUri $RemoteSigningServiceURL -CacheAccessToken:$CacheAccessToken -Verbose:$VerbosePreference
  }
  else {
    $sk = Get-HPPrivateX509CertCoalesce -File $SigningKeyFile -password $SIgningKeyPassword -cert $SigningKeycertificate -Verbose:$VerbosePreference
    $cmd.sig = Invoke-HPPrivateSignData -Data $payload -Certificate $sk.Full -Verbose:$VerbosePreference
  }
  Write-Verbose "Building output document with nonce $([BitConverter]::GetBytes($nonce))"

  $output.Data = (Convert-HPPrivateObjectToBytes -obj $cmd -Verbose:$VerbosePreference)[0]
  Write-Verbose "Sending document of size $($output.data.length)"
  $output.timestamp = Get-Date

  if ($OutputFile) {
    Write-Verbose "Will output to file $OutputFile"
    $f = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $output | ConvertTo-Json -Compress | Out-File -FilePath $f -Encoding utf8
  }
  else {
    $output | ConvertTo-Json -Compress
  }
}


<#
.SYNOPSIS
  Invokes the WMI command to trigger the BIOS to perform a service event on the next boot

.DESCRIPTION
  This command invokes the WMI command to trigger the BIOS to perform a service event on the next boot. If the hardware option is not present, this command will throw a NotSupportedException exception. 

  The BIOS will then compare SR_AED to HP_EAD and agent will compare SR_Image to HP_Image and update as necessary. The CloudRecovery.exe is the tool that performs the actual update.

.LINK 
  [Blog post: HP Secure Platform Management with the HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library)

.LINK
  [Blog post: Provisioning and Configuring HP Sure Recover with HP Client Management Script Library](https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library)
  
  
.NOTES
  - Requires HP BIOS with HP Sure Recover support
  - Requires Embedded Reimaging device hardware option

.EXAMPLE
  Invoke-HPSureRecoverTriggerUpdate
#>
function Invoke-HPSureRecoverTriggerUpdate
{
  [CmdletBinding(HelpUri = "https://developers.hp.com/hp-client-management/doc/Invoke-HPSureRecoverTriggerUpdate")]
  param()

  $mi_result = 0
  $cmd = '[DfmNativeSureRecover]::raise_surerecover_service_event_opaque' + (Test-OSBitness) + '($null, $null, [ref]$mi_result);'
  $result = Invoke-Expression -Command $cmd
  Test-HPPrivateCustomResult -result $result -mi_result $mi_result -Category 0x05
}


# SIG # Begin signature block
# MIIoHQYJKoZIhvcNAQcCoIIoDjCCKAoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvS58sg3OwWFs4
# tP8v0GthjuVAOtdzB8Q2tfYjSYjFuaCCDYowggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggbSMIIEuqADAgECAhAJvPMqSNxAYhV5FFpsbzOhMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjQwMjE1MDAwMDAwWhcNMjUwMjE4
# MjM1OTU5WjBaMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAG
# A1UEBxMJUGFsbyBBbHRvMRAwDgYDVQQKEwdIUCBJbmMuMRAwDgYDVQQDEwdIUCBJ
# bmMuMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApbF6fMFy6zhGVra3
# SZN418Cp2O8kjihQCU9tqPO9tkzbMyTsgveLJVnXPJNG9kQPMGUNp+wEHcoUzlRc
# YJMEL9fhfzpWPeSIIezGLPCdrkMmS3fdRUwFqEs7z/C6Ui2ZqMaKhKjBJTIWnipe
# rRfzGB7RoLepQcgqeF5s0DBy4oG83dqcRHo3IJRTBg39tHe3mD5uoGHn5n366abX
# vC+k53BVyD8w8XLppFVH5XuNlXMq/Ohf613i7DRb/+u92ZiAPVPXXnlxUE26cuDb
# OfJKN/bXPmvnWcNW3YHVp9ztPTQZhX4yWYXHrAI2Cv6HxUpO6NzhFoRoBTkcYNbA
# 91pf1Vagh/MNcA2BfQYT975/Vlvj9cfEZ/NwZthZuHa3rdrvCKhhjw7YU2QUeaTJ
# 0uaX4g6B9PFNqAASYLach3CDJiLmYEfus/utPh57mk0q27yL25fXo/PaMDXiDNIi
# 7Wuz7A+sPsbtdiY8zvEIRQ+XJXtKAlD4tqG9YzlTO6ZoQX/rAgMBAAGjggIDMIIB
# /zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQURH4F
# u5yEAuElYWUbyGRYkNLLrA8wPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEF
# BQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIH
# gDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmlu
# Z1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hB
# Mzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
# NDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQAD
# ggIBAFiCyuI6qmaQodDyMNpp0l7eIXFgJ4JI59o59PleFj4rcyd/+F4iI7u5if8G
# rV5Kn3s3tK9vfJO8SpqtEh7lL4e69z6v3ohcy4uy2hsjKQ/fFcDo9pQYDGmDVjCa
# D5qSVEIBlJHBe5NKEJAgUE0kaMjLzbi2+8DKJlNtvZ+hatuPl9fMnmU+VbQh7JhZ
# yJdz8Ay0tcQ9lC8HAX5Ah/pU+Vtv+c8gMSxjS1aWXoGCa1869IVi2O6qx7MuX12U
# 1eIpB9XxYr7HSebvg2G7Gz6nCh7u+4k7m3hJu9EStUIN2JII5260+E60uDWoHEhx
# tHbdueFQxJrTKnhplOSaaPFCVBDkWG83ZzN9N3z/45w1pBUNBiPJdRQJ58MhBYQe
# Zl90heMBL8QNQk2i0E5gHNT9pJiCR9+mvJkRxEVgUn+16ZpVnI6kzhThV9qBaWVF
# h83X4UWc/nwHKIuu+4x4fmkYc79A3MrsHflZIO8jOy0GC/xBnZTQ8s5b9Tb2UkHk
# w692Ypl7War3W7M37JCAPC/A7M4CwQYjdjG43zs5m36auYVaTvRLKtZVLzcj8oZX
# 4vqhlZ8+jCPXFiuDfoBXiTckTLpv/eHQ6q7Aoda+qARWPPE1U2v5r/lpKVqIx7B4
# PdFZAUf5MtG/Bj7LVXvXjW8ABIJv7L4cI2akn6Es0dmvd6PsMYIZ6TCCGeUCAQEw
# fTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hB
# Mzg0IDIwMjEgQ0ExAhAJvPMqSNxAYhV5FFpsbzOhMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIK4oTdlj
# XqbITLtekErFm7gSNSXxKqeoMC0PyLwfdY5dMA0GCSqGSIb3DQEBAQUABIIBgGJ1
# 5Dq2ssy+Mk71bvGBcYOOSSwRg3O+Pvtq0P2odKKP7fDz8wyXbhrnS3B1PmWJUNTZ
# i4/rt+kJP0N7Q95bfP3xsm0201MEr7VVlodTYNylxqZU4XZMeEZPzDHmxd1Ye2K+
# RVQqqYViEVqqWnvnPztDgJ89QTXR8Bm/RSpp9i/GI2lLVm4Mt1b97AMwXeR9Kceb
# mYpcMyUUrA3PJ3qGxyYO7km7kSTwvBxQ5UsSj8Vh6yfoCXy5K2GGjgznY5poPvqm
# cDCQ/DHulZFqnYIOOViiW6ejDGHmthsbHKWRTqZrCtTywNrOH5buMEvk8Ndpnq9o
# zh8f0WC22tz3bPYz9VkjCC12AASdmrpTXg3V2BX4Pn+RT4ZNK44RiVNiH82XjhoT
# UTs9nOup531UwHHU2T3HJButq68Vnk6wZnk7klvwOhsrfyPdyMTl/ZVf3+xRrJn/
# 73vqhK+lqF1h+ISBeVoeJ6/woue3zYg2cV5vkxHgQAsGE8tlxnGWmQZtQQMNC6GC
# Fz8wghc7BgorBgEEAYI3AwMBMYIXKzCCFycGCSqGSIb3DQEHAqCCFxgwghcUAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG
# /WwHATAxMA0GCWCGSAFlAwQCAQUABCBugHOwEQco3NvOfgqgpGKWTph/yHkdYbHo
# 5DI0dguUHQIQEAc4ghGSkHrPni7JT2vnVxgPMjAyNDAyMjgxOTU1NDdaoIITCTCC
# BsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAwYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBD
# QTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGlt
# ZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjU0WH
# HYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0QKYoe
# YmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/LB6Yw
# aMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55DxtmUuPI
# 1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rVlc7v
# CBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0xmWVH
# VZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxmg4ho
# Yru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqrUBXJ
# s8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk+tfE
# ayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7wtsfV
# x95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEoEyFJ
# UX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYDVR0P
# AQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW
# 2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj3tXj
# STBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQ
# BggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0
# MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3qXSKS
# 7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdoSXej
# 65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzYmHZP
# VrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND45Ul3
# CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZqA0Xe
# 2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFLjDLD
# iOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC3D0y
# 33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsUDH6u
# vP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69zOuhJ
# RrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO9OzT
# F/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2QgESv
# gBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQEL
# BQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBS
# b290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTep
# l1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt
# +FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r
# 07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dh
# gxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfA
# csW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpH
# IEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJS
# lRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0
# z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y
# 99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBID
# fV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXT
# drnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsF
# AAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoN
# qilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8V
# c40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJods
# kr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6sk
# HibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82H
# hyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HN
# T7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8z
# OYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIX
# mVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZ
# E/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSF
# D/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIEdaAD
# AgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0y
# MjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4Smn
# PVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6f
# qVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O
# 7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZ
# Vu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4F
# fYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLm
# qaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMre
# Sx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/ch
# srIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+U
# DCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xM
# dT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUb
# AgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAO
# BgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0f
# BD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNz
# dXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEM
# BQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLt
# pIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouy
# XtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jS
# TEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAc
# AgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2
# h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQg
# VHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OU
# nQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqG
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDAyMjgxOTU1NDdaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3OqorJxk8ZnM9AMC8GCSqGSIb3DQEJ
# BDEiBCBQ5+dGOdRZJ6/cU6X2gPfahSlHvroXMfELNMD7kPDVMTA3BgsqhkiG9w0B
# CRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZvgoraVZquMxavTRqa1Ax4KDAN
# BgkqhkiG9w0BAQEFAASCAgBAG9vu9lM+Ss4fQovOoGJgoSzGjQ76ycRm+CgZynsu
# QDqL75sSWDADIEjBt+OeU6yKy78ZNJsIYYwdt1UjrlbFlMrZHLfvhTBUWplssnRr
# a7Rbs5MYJDP6kyw5LuE6kG58QP382oA50Ots3N9tMXLzMuSlzmx/oX47beQdoAnP
# LT/vjrhc84mBxdbj3rmbPWVGT/JmpIpsPeTL+T7kJAwoDKfGNzV7nQC1AnO9DwyE
# WQsrjyPnd2kD0aqTgXOAeJWUG231VPuQjA9jq6Knp+jiSf7yrl/E+4Ne12JAEDoo
# lwGqV+UGN4lAqAUEiyR9oKOcmV4HkP2UCL5ugky40Xriwyx9fchm0axxMyopXqam
# gwDUwXXmmySXbGlKMEw8t36G3WqSKV3Kjrp9UNKahX1CVVmuMFc2Hw0gkTKjHQ8K
# gzCIJLGx/qym/nZM7qwKWWFrJn/CvC6IyXIEQjyXm45r5i+4IYmuYGzWId2dKlGz
# ZE/IgcYi1oGSn3xt+T7A17h0iGdf5R8PUFQFWY2/eNmrhy5klXrMBTqbqS3IvYNQ
# ujBWEpdoXB30zB2tI9Lgo+y8nOFJYK6JKmMNmaqQEVyBJGRFSzC7ejQzO5+b3lUL
# P+d0let8RHmM3fjaxGTKoisttLZsaQgCHugDHogPKgdnhNxb0Tho7+CO1vh4bBBq
# 2Q==
# SIG # End signature block
