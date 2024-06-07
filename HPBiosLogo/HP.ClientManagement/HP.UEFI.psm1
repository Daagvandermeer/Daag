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
#

Set-StrictMode -Version 3.0

$interop = @'
using System;
using System.Runtime.InteropServices;

public enum PrivilegeState {
    Enabled,
    Disabled
};

public class Native
{
    [DllImport("kernel32.dll", ExactSpelling = true,  SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern UInt32 GetFirmwareEnvironmentVariableExW(string Name, string NamespaceGuid, [Out] Byte[] Buffer, UInt32 bufferSize, [Out] out UInt32 Attributes);

    [DllImport("kernel32.dll", ExactSpelling = true,  SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern UInt32 SetFirmwareEnvironmentVariableExW(string Name, string NamespaceGuid, Byte[] Buffer, UInt32 bufferSize, UInt32 Attributes);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TokenPrivileges NewState, int BufferLength, ref TokenPrivileges PreviousState, ref int ReturnLength);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, IntPtr pid);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true,  CharSet = CharSet.Unicode)]
    internal static extern bool LookupPrivilegeValueW(string SystemName, string PrivilegeName, ref long LUID);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr ObjectHandle);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokenPrivileges
    {
        public int PrivilegeCount; // always 1 here, we do one at a time
        public long LUID;
        public int Attributes;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    internal const int PROCESS_QUERY_INFORMATION = 0x00000400;

    public static int EnablePrivilege(long Pid, string Privilege, out PrivilegeState PreviousState, PrivilegeState NewState)
    {
        bool ret;
        TokenPrivileges newTokenPriv;
        TokenPrivileges previousTokenPriv = new TokenPrivileges();
        int previousTokenPrivSize = 0;
        IntPtr ProcHandle = new IntPtr(Pid);
        IntPtr TokenHandle = IntPtr.Zero;

        PreviousState = PrivilegeState.Disabled;

        ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, ProcHandle);
        if (ProcHandle.ToInt64() == 0L) {
            return Marshal.GetLastWin32Error();
        }

        ret = OpenProcessToken(ProcHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref TokenHandle);
        if (!ret) {
            return Marshal.GetLastWin32Error();
        }

        newTokenPriv.PrivilegeCount = 1;
        newTokenPriv.LUID = 0;
        newTokenPriv.Attributes = (NewState == PrivilegeState.Disabled) ? SE_PRIVILEGE_DISABLED : SE_PRIVILEGE_ENABLED;

        ret = LookupPrivilegeValueW(null, Privilege, ref newTokenPriv.LUID);
        if (!ret) {
            CloseHandle(TokenHandle);
            return Marshal.GetLastWin32Error();
        }

        ret = AdjustTokenPrivileges(TokenHandle, false, ref newTokenPriv, 256, ref previousTokenPriv, ref previousTokenPrivSize);
        if (!ret) {
            CloseHandle(TokenHandle);
            return Marshal.GetLastWin32Error();
        } else {
            PreviousState = (previousTokenPriv.Attributes == SE_PRIVILEGE_ENABLED) ? PrivilegeState.Enabled : PrivilegeState.Disabled;
        }

        CloseHandle(TokenHandle);
        return 0;
    }
}

'@

Add-Type $interop -Passthru

[Flags()] enum UEFIVariableAttributes{
  VARIABLE_ATTRIBUTE_NON_VOLATILE = 0x00000001
  VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS = 0x00000002
  VARIABLE_ATTRIBUTE_RUNTIME_ACCESS = 0x00000004
  VARIABLE_ATTRIBUTE_HARDWARE_ERROR_RECORD = 0x00000008
  VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS = 0x00000010
  VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
  VARIABLE_ATTRIBUTE_APPEND_WRITE = 0x00000040
}


<#
    .SYNOPSIS
    Retrieves a UEFI variable value

    .DESCRIPTION
    This command retrieves the value of a UEFI variable. 

    .PARAMETER Name
    Specifies the name of the UEFI variable to read

    .PARAMETER Namespace
    Specifies a custom namespace. The namespace must be in the format of a UUID, surrounded by curly brackets.

    .PARAMETER AsString
    If specified, this command will return the value as a string rather than a byte array. Note that the commands in this library support UTF-8 compatible strings. Other applications may store strings that are not compatible with this translation, in which
    case the caller should retrieve the value as an array (default) and post-process it as needed.

    .EXAMPLE
    PS>  Get-HPUEFIVariable -GlobalNamespace -Name MyVariable

    .EXAMPLE
    PS>  Get-HPUEFIVariable -Namespace "{21969aa8-681f-46be-90f0-6019ce9b0ee7}"  -Name MyVariable

    .NOTES
    - The process calling these commands must be able to acquire 'SeSystemEnvironmentPrivilege' privileges for the operation to succeed. For more information, refer to "Modify firmware environment values" in the linked documentation below.
    - This command is not supported on legacy mode, only on UEFI mode.
    - This command requires elevated privileges.

    .OUTPUTS
    This command returns a custom object that contains the variable value and its attributes.

    .LINK
    [UEFI Specification 2.3.1 Section 7.2](https://www.uefi.org/specifications)

    .LINK
    [Modify firmware environment values](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-firmware-environment-values)
#>
function Get-HPUEFIVariable
{
  [CmdletBinding(DefaultParameterSetName = 'NsCustom',HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPUEFIVariable")]
  [Alias("Get-UEFIVariable")]
  param(
    [Parameter(Position = 0,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Name,

    [Parameter(Position = 1,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Namespace,

    [Parameter(Position = 2,Mandatory = $false,ParameterSetName = "NsCustom")]
    [switch]$AsString
  )

  if (-not (Test-IsElevatedAdmin)) {
    throw [System.Security.AccessControl.PrivilegeNotHeldException]"elevated administrator"
  }

  $PreviousState = [PrivilegeState]::Enabled;
  Set-HPPrivateEnablePrivilege -ProcessId $PID -PreviousState ([ref]$PreviousState) -State ([PrivilegeState]::Enabled)

  $size = 1024 # fixed max size
  $result = New-Object Byte[] (1024)
  [uint32]$attr = 0

  Write-Verbose "Querying UEFI variable $Namespace/$Name"
  Get-HPPrivateFirmwareEnvironmentVariableExW -Name $Name -Namespace $Namespace -Result $result -Size $size -Attributes ([ref]$attr)

  $r = [pscustomobject]@{
    Value = ''
    Attributes = [UEFIVariableAttributes]$attr
  }
  if ($asString.IsPresent) {
    $enc = [System.Text.Encoding]::UTF8
    $r.Value = $enc.GetString($result)
  }
  else {
    $r.Value = [array]$result
  }

  if ($PreviousState -eq [PrivilegeState]::Disabled) {
    Set-HPPrivateEnablePrivilege -ProcessId $PID -PreviousState ([ref]$PreviousState) -State ([PrivilegeState]::Disabled)
  }
  $r
}

<#
    .SYNOPSIS
    Sets a UEFI variable value

    .DESCRIPTION
    This command sets the value of a UEFI variable. If the variable does not exist, this command will create the variable. 

    .PARAMETER Name
    Specifies the name of the UEFI variable to update or create

    .PARAMETER Namespace
    Specifies a custom namespace. The namespace must be in the format of a UUID, surrounded by curly brackets.

    .PARAMETER Value
    Specifies the new value for the UEFI variable. Note that a NULL value will delete the variable.

    The value may be a byte array (type byte[],  recommended), or a string which will be converted to UTF8 and stored as a byte array.

    .PARAMETER Attributes
    Specifies the attributes for the UEFI variable. For more information, see the UEFI specification linked below.

    Attributes may be:

    - VARIABLE_ATTRIBUTE_NON_VOLATILE: The firmware environment variable is stored in non-volatile memory (e.g. NVRAM). 
    - VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS: The firmware environment variable can be accessed during boot service. 
    - VARIABLE_ATTRIBUTE_RUNTIME_ACCESS:  The firmware environment variable can be accessed at runtime. Note  Variables with this attribute set, must also have VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS set. 
    - VARIABLE_ATTRIBUTE_HARDWARE_ERROR_RECORD:  Indicates hardware related errors encountered at runtime. 
    - VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS: Indicates an authentication requirement that must be met before writing to this firmware environment variable. 
    - VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS: Indicates authentication and time stamp requirements that must be met before writing to this firmware environment variable. When this attribute is set, the buffer, represented by pValue, will begin with an instance of a complete (and serialized) EFI_VARIABLE_AUTHENTICATION_2 descriptor. 
    - VARIABLE_ATTRIBUTE_APPEND_WRITE: Append an existing environment variable with the value of pValue. If the firmware does not support the operation, then SetFirmwareEnvironmentVariableEx will return ERROR_INVALID_FUNCTION.

    .EXAMPLE
    PS>  Set-HPUEFIVariable -Namespace "{21969aa8-681f-46be-90f0-6019ce9b0ee7}" -Name MyVariable -Value 1,2,3

    .EXAMPLE
    PS>  Set-HPUEFIVariable -Namespace "{21969aa8-681f-46be-90f0-6019ce9b0ee7}" -Name MyVariable -Value "ABC"

    .NOTES
    - It is not recommended that the attributes of an existing variable are updated. If new attributes are required, the value should be deleted and re-created.
    - The process calling these commands must be able to acquire 'SeSystemEnvironmentPrivilege' privileges for the operation to succeed. For more information, refer to "Modify firmware environment values" in the linked documentation below.
    - This command is not supported on legacy BIOS mode, only on UEFI mode.
    - This command requires elevated privileges.

    .LINK
    [UEFI Specification 2.3.1 Section 7.2](https://www.uefi.org/specifications)

    .LINK
    [Modify firmware environment values](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-firmware-environment-values)
#>

function Set-HPUEFIVariable
{
  [CmdletBinding(DefaultParameterSetName = 'NsCustom',HelpUri = "https://developers.hp.com/hp-client-management/doc/Set-HPUEFIVariable")]
  [Alias("Set-UEFIVariable")]
  param(
    [Parameter(Position = 0,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Name,

    [Parameter(Position = 1,Mandatory = $true,ParameterSetName = "NsCustom")]
    $Value,

    [Parameter(Position = 2,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Namespace,

    [Parameter(Position = 3,Mandatory = $false,ParameterSetName = "NsCustom")]
    [UEFIVariableAttributes]$Attributes = 7
  )

  if (-not (Test-IsElevatedAdmin)) {
    throw [System.Security.AccessControl.PrivilegeNotHeldException]"elevated administrator"
  }

  $err = "The Value must be derived from base types 'String' or 'Byte[]' or Byte"

  [byte[]]$rawvalue = switch ($Value.GetType().Name) {
    "String" {
      $enc = [System.Text.Encoding]::UTF8
      $v = @($enc.GetBytes($Value))
      Write-Verbose "String value representation is $v"
      [byte[]]$v
    }
    "Int32" {
      $v = [byte[]]$Value
      Write-Verbose "Byte value representation is $v"
      [byte[]]$v
    }
    "Object[]" {
      try {
        $v = [byte[]]$Value
        Write-Verbose "Byte array value representation is $v"
        [byte[]]$v
      }
      catch {
        throw $err
      }
    }
    default {
      throw "Value type $($Value.GetType().Name): $err" 
    }
  }


  $PreviousState = [PrivilegeState]::Enabled
  Set-HPPrivateEnablePrivilege -ProcessId $PID -PreviousState ([ref]$PreviousState) -State ([PrivilegeState]::Enabled)

  $len = 0
  if ($rawvalue) { $len = $rawvalue.Length }

  if (-not $len -and -not ($Attributes -band [UEFIVariableAttributes]::VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS -or
      $Attributes -band [UEFIVariableAttributes]::VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS -or
      $Attributes -band [UEFIVariableAttributes]::VARIABLE_ATTRIBUTE_APPEND_WRITE)) {
    # Any attribute different from 0x40, 0x10 and 0x20 combined with a value size of zero removes the UEFI variable.
    # Note that zero is not a valid attribute, see [UEFIVariableAttributes] enum
    Write-Verbose "Deleting UEFI variable $Namespace/$Name"
  }
  else {
    Write-Verbose "Setting UEFI variable $Namespace/$Name to value $rawvalue (length = $len), Attributes $([UEFIVariableAttributes]$Attributes)"
  }

  Set-HPPrivateFirmwareEnvironmentVariableExW -Name $Name -Namespace $Namespace -RawValue $rawvalue -Len $len -Attributes $Attributes

  if ($PreviousState -eq [PrivilegeState]::Disabled) {
    Set-HPPrivateEnablePrivilege -ProcessId $PID -PreviousState ([ref]$PreviousState) -State ([PrivilegeState]::Disabled)
  }
}

function Set-HPPrivateEnablePrivilege
{
  [CmdletBinding()]
  param(
    $ProcessId,
    [ref]$PreviousState,
    $State
  )

  try {
    $enablePrivilege = [Native]::EnablePrivilege($PID,"SeSystemEnvironmentPrivilege",$PreviousState,$State)
  }
  catch {
    $enablePrivilege = -1 # non-zero means error
    Write-Verbose "SeSystemEnvironmentPrivilege failed: $($_.Exception.Message)"
  }

  if ($enablePrivilege -ne 0) {
    $err = [System.ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw [UnauthorizedAccessException]"Current user cannot acquire UEFI variable access permissions: $err ($enablePrivilege)"
  }
  else {
    $newStateStr = if ($State -eq [PrivilegeState]::Enabled) { "Enabling" } else { "Disabling" }
    $prevStateStr = if ($PreviousState.Value -eq [PrivilegeState]::Enabled) { "enabled" } else { "disabled" }
    Write-Verbose "$newStateStr application privilege; it was $prevStateStr before"
  }
}

function Set-HPPrivateFirmwareEnvironmentVariableExW
{
  [CmdletBinding()]
  param(
    $Name,
    $Namespace,
    $RawValue,
    $Len,
    $Attributes
  )

  try {
    $setVariable = [Native]::SetFirmwareEnvironmentVariableExW($Name,$Namespace,$RawValue,$Len,$Attributes)
  }
  catch {
    $setVariable = 0 # zero means error
    Write-Verbose "SetFirmwareEnvironmentVariableExW failed: $($_.Exception.Message)"
  }

  if ($setVariable -eq 0) {
    $err = [System.ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error();
    throw "Could not write UEFI variable: $err. This function is not supported on legacy BIOS mode, only on UEFI mode.";
  }
}

function Get-HPPrivateFirmwareEnvironmentVariableExW
{
  [CmdletBinding()]
  param(
    $Name,
    $Namespace,
    $Result,
    $Size,
    [ref]$Attributes
  )

  try {
    $getVariable = [Native]::GetFirmwareEnvironmentVariableExW($Name,$Namespace,$Result,$Size,$Attributes)
  }
  catch {
    $getVariable = 0 # zero means error
    Write-Verbose "GetFirmwareEnvironmentVariableExW failed: $($_.Exception.Message)"
  }

  if ($getVariable -eq 0)
  {
    $err = [System.ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error();
    throw "Could not read UEFI variable: $err. This function is not supported on legacy BIOS mode, only on UEFI mode.";
  }
}

<#
    .SYNOPSIS
    Removes a UEFI variable

    .DESCRIPTION
    This command removes a UEFI variable from a well-known or user-supplied namespace. 

    .PARAMETER Name
    Specifies the name of the UEFI variable to remove

    .PARAMETER Namespace
    Specifies a custom namespace. The namespace must be in the format of a UUID, surrounded by curly brackets.
    
    .EXAMPLE
    PS>  Remove-HPUEFIVariable -Namespace "{21969aa8-681f-46be-90f0-6019ce9b0ee7}" -Name MyVariable

    .NOTES
    - The process calling these commands must be able to acquire 'SeSystemEnvironmentPrivilege' privileges for the operation to succeed. For more information, refer to "Modify firmware environment values" in the linked documentation below.
    - This command is not supported on legacy mode, only on UEFI mode.
    - This command requires elevated privileges.

    .LINK
    [Modify firmware environment values](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-firmware-environment-values)

#>
function Remove-HPUEFIVariable
{
  [CmdletBinding(DefaultParameterSetName = 'NsCustom',HelpUri = "https://developers.hp.com/hp-client-management/doc/Remove-HPUEFIVariable")]
  [Alias("Remove-UEFIVariable")]
  param(
    [Parameter(Position = 0,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Name,

    [Parameter(Position = 1,Mandatory = $true,ParameterSetName = "NsCustom")]
    [string]$Namespace
  )
  Set-HPUEFIVariable @PSBoundParameters -Value "" -Attributes 7
}

# SIG # Begin signature block
# MIIoHgYJKoZIhvcNAQcCoIIoDzCCKAsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCVhk6Ny9XcOLwC
# 7kyTDJiqVLD57zW6b0EUoDJCyopVbqCCDYowggawMIIEmKADAgECAhAIrUCyYNKc
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
# PdFZAUf5MtG/Bj7LVXvXjW8ABIJv7L4cI2akn6Es0dmvd6PsMYIZ6jCCGeYCAQEw
# fTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hB
# Mzg0IDIwMjEgQ0ExAhAJvPMqSNxAYhV5FFpsbzOhMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDWtJWaj
# BcdkwhooEFcojXpFOJ55fzi9uielkdxZEVyaMA0GCSqGSIb3DQEBAQUABIIBgDwn
# PzKkPgYhs8phE78/11gS6Elj9dsuX6kYLr80vdNIvaEwPh50BCdDl3V5WeRRlOq2
# rKY5AOm303AeVarhfQd9vDJDsYSzpDIKw1mnlBmDhsNsLxHL8sv+B6xvA1wWDLUU
# HX/JlFWE6csupdE1MFikLoXs/1q+ey8VX+UsLMWNlfJ7CjlDCUKWBbBqZZh+/U0+
# 7PMUA16jis+bnqCKlAcG6u7fH/TxnPGtAY7Nxz+2pvYI7RCEugkx65c0Pk8vm1hm
# 1DtZ5FwUw/qUvoEMp4T66V/ewobyxvLEEw0vSSOMQ6Yu00JjVAwiATzq9mBnH1e7
# 18adernqX2v236fvMEQH1fG+GkrV66I7i+aUimnlRp3TjVGTkfHjfUqd1l2b42Lq
# a2zjbbxBtta4ru8b9F5AktuFy0V1hjgW/Tlr41lnXBnrrxWCtDf6GHHf+OZAgFUo
# xVKWeXYrcRTyZPVdW09KH7HuyR3tfD+ckM+cTXePRWA+i+2PLLsoQjohSA8MRKGC
# F0Awghc8BgorBgEEAYI3AwMBMYIXLDCCFygGCSqGSIb3DQEHAqCCFxkwghcVAgED
# MQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG
# /WwHATAxMA0GCWCGSAFlAwQCAQUABCC8i3LYgFYCdJOXqOECllD6sfjWBNX37LKb
# IqHAcEj4LgIRAKwnN7XhilNLzQI540XA+CkYDzIwMjQwMjI4MTk1NTQ3WqCCEwkw
# ggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEBCwUAMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRp
# bWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo1NF
# hx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82qsmrdECmK
# HmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQgfLPywem
# MGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUueQ8bZlLj
# yNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfjRCtK1ZXO
# 7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w7nZ9MZll
# R1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVRzapMZoOI
# aGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387RXoyqq1AV
# ybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8SdlalJPrX
# xGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFHCoz+8LbH
# 1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4MsiK8rxKBMh
# SVF+BmbTO77665E42FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGHMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6
# FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVWqWUxo97V
# 40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCB
# kAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNy
# dDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/LLOTN6l0i
# kuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29wmE3aEl3
# o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOnvTcM2Jh2
# T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2eqUTQ+OVJ
# dwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWhpVgmagNF
# 3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH7doRS4wy
# w4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4SF/Kwtw9
# Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWggBHLFAx+
# rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVsrquvczro
# SUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtasFyIjTvTs
# 0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g29mtkIBE
# r4AQQYowggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEB
# CwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQg
# Um9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3
# qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOW
# bfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt
# 69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3
# YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECn
# wHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6Aa
# RyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTy
# UpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8U
# NM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCON
# WPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBAS
# A31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp61
# 03a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CK
# Daopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbP
# FXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaH
# bJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxur
# JB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/N
# h4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNB
# zU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77Qpf
# MzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1Oby
# F5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B
# 2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqk
# hQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIFjTCCBHWg
# AwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcN
# MjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEp
# pz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+
# n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYykt
# zuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw
# 2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6Qu
# BX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC
# 5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK
# 3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3
# IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEP
# lAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98
# THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3l
# GwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1Ud
# HwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEB
# DAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi
# 7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqL
# sl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo
# 0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVg
# HAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnw
# toeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3ICAQEwdzBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/z
# lJ0IOaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjQwMjI4MTk1NTQ3WjArBgsqhkiG
# 9w0BCRACDDEcMBowGDAWBBRm8CsywsLJD4JdzqqKycZPGZzPQDAvBgkqhkiG9w0B
# CQQxIgQgYmAwlZ6ZASjjIy/FlvwGKxzRasCtu+E7i+2cu3W+yBIwNwYLKoZIhvcN
# AQkQAi8xKDAmMCQwIgQg0vbkbe10IszR1EBXaEE2b4KK2lWarjMWr00amtQMeCgw
# DQYJKoZIhvcNAQEBBQAEggIAlywnVwKtDzQ/S1ECuhXM6OZFn/edjxTjwYlbu2re
# D7uMQ1ywyCCR3IoCLVgx6u7CtzaMfF6e18A9Us8p0+GXE/J3WmmIh/kSnq3bxzJy
# aJqRbCk/PpwYUN+dX8l+6TprDejFhfBYdIgqr2m3Y1DRAC8fsS+RNYYeQzxCc0q+
# lNkx2smsGPAnYJUo6JJrs2af/c8uOXTIbufJF+Y+mig3vmnL3bJZWoRUJyAXUXHe
# s4uBszsNrkMEdqKRoMpzsDV6s/U6q6Qm4WOPWiwQDRtoYHbrZPNbxewrpmKcBZeG
# gERbO2mswGEXQyhAJODYH2Xw54pZOV2vIYsLE+NFPs307rDxesPGuzV/fo8/y/Hr
# JwPW9d1tD+2PfA9pl1KhCDt19yXOqTQuf9kO7xymGqL9oBvPsmN/D6M/WaiivEP7
# Emj0VFvaWQpb8HV0SwRm/olX8NN9LxKTF1EWFGkWLFI7uKsmlqToD+XZ3cdGLkdl
# CJWyIJctx7FpUdrQ1M1Es3T85bguQgeRzvEWh/+PTPxUvmfiCVWB82ikw7k+nx4l
# odvU0YKboeLUAbRuIJidiRLUxxsTSN0AYRx3LKBDFq5Bq+pF7dL4Ld9kHrI62wpm
# Q2cBpgvQfI0SBvwz93uvTIN4mQ61TsyZnqeoK4T2hy4d9MtN5ZAysjwTlLmoLUsf
# W5Q=
# SIG # End signature block
