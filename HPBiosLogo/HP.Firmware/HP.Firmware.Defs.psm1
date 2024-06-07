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
$env:PATH += ";$PSScriptRoot"
Add-Type -TypeDefinition @'
    using System;
    using System.IO;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;

//  HP SUREVIEW
public enum sureview_status_t : byte {
    sureview_off = 0xff,
    sureview_on = 0xfe,
    sureview_forced_on = 0xfc,
    sureview_unsupported = 0xfa,
    sureview_unknown = 0
};

[Flags]
public enum sureview_capabilities_t : byte{
    touch_ui = 0x01
};


public enum  sureview_desired_state_t : byte {
    sureview_desired_off = 0,
    sureview_desired_on = 1,
    sureview_desired_on_max = 2
} ;


[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct sureview_state_t
{
     [MarshalAs(UnmanagedType.U1)] public sureview_status_t status; // of type sureview_status_t
     [MarshalAs(UnmanagedType.U1)] public  byte visibility;
     [MarshalAs(UnmanagedType.U1)] public  sureview_capabilities_t capabilities; // of type sureview_capabilities_t
};


public  static  class DfmNativeSureView
{
    [DllImport("dfmbios32.dll", EntryPoint = "get_sureview_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_sureview_state32([In,Out] ref sureview_state_t data, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "get_sureview_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_sureview_state64([In,Out] ref sureview_state_t data, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "set_sureview_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_sureview_state32([In] sureview_desired_state_t on, [In] byte visibility, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "set_sureview_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_sureview_state64([In] sureview_desired_state_t on, [In] byte visibility, [In,Out] ref int extended_result);
 }

// GENERAL FIRMWARE
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct opaque4096_t
{
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 4096)]  public byte[] raw;
};

public enum authentication_t : uint
{
    auth_t_anonymous = 0,
    auth_t_password = 1,
    auth_t_beam = 2
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
public struct authentication_data_t {
    [MarshalAs(UnmanagedType.U2)] public ushort password_size;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string password;

};
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct bios_credential_t
{
    [MarshalAs(UnmanagedType.U4)] public authentication_t authentication;
    [MarshalAs(UnmanagedType.Struct)] public authentication_data_t data;
}

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate void ProgressCallback(UInt32 location, UInt32 value1, UInt32 value2, UInt32 state);


 //  AUDIT LOG and LOGO

   public enum audit_log_severity_t : uint
    {
        logged_severity_reserved = 0,
        logged_severity_unknown = 1,
        logged_severity_normal = 2,
        logged_severity_low = 3,
        logged_severity_medium = 4,
        logged_severity_high = 5,
        logged_severity_critical = 6,
    }


    public enum powerstate_t : uint
    {
        S0 = 0,
        S3 = 1,
        S4S5 = 2,
        RESERVED = 3
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct timestamp_t
    {
        public Int16 year;
        public Int16 month;
        public Int16 day_of_week;
        public Int16 day;
        public Int16 hour;
        public Int16 minute;
        public Int16 second;
        public Int16 millisecond;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct bios_log_entry_t
    {
        [MarshalAs(UnmanagedType.U1)] public byte status;
        [MarshalAs(UnmanagedType.U4)] public UInt32 message_number;
        [MarshalAs(UnmanagedType.Struct)] public  timestamp_t timestamp;
        [MarshalAs(UnmanagedType.U4)] public UInt32 timestamp_is_exact;
        [MarshalAs(UnmanagedType.U4)] public powerstate_t system_state_at_event;
        [MarshalAs(UnmanagedType.U4)] public UInt32 source_id;
        [MarshalAs(UnmanagedType.U4)] public UInt32 event_id;
        [MarshalAs(UnmanagedType.U4)] public audit_log_severity_t severity;
        [MarshalAs(UnmanagedType.U1)] public byte data_0;
        [MarshalAs(UnmanagedType.U1)] public byte data_1;
        [MarshalAs(UnmanagedType.U1)] public byte data_2;
        [MarshalAs(UnmanagedType.U1)] public byte data_3;
        [MarshalAs(UnmanagedType.U1)] public byte data_4;
    }

    public  static  class DfmNativeBios
    {
        [DllImport("dfmbios32.dll", EntryPoint = "get_audit_logs", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 get_audit_logs_32([Out] bios_log_entry_t[] results, [In,Out] ref UInt32 buffer_size, [In,Out] ref UInt32 records_count, [Out] out UInt32 extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "get_audit_logs", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 get_audit_logs_64([Out] bios_log_entry_t[] results, [In,Out] ref UInt32 buffer_size, [In,Out] ref UInt32 records_count, [Out] out UInt32 extended_result);
        [DllImport("dfmbios32.dll", EntryPoint = "query_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 query_enterprise_logo32([Out] out UInt32 installed, [Out] out UInt32 state, [Out] out UInt32 extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "query_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 query_enterprise_logo64([Out] out UInt32 installed, [Out] out UInt32 state, [Out] out UInt32 extended_result);
        [DllImport("dfmbios32.dll", EntryPoint = "set_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 set_enterprise_logo32([In] string filename, [In] ref bios_credential_t credentials, [Out] out UInt32 extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "set_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 set_enterprise_logo64([In] string filename, [In] ref bios_credential_t credentials, [Out] out UInt32 extended_result);


        [DllImport("dfmbios32.dll", EntryPoint = "clear_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 clear_enterprise_logo32([In] ref bios_credential_t credentials, [Out] out UInt32 extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "clear_enterprise_logo", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 clear_enterprise_logo64([In] ref bios_credential_t credentials, [Out] out UInt32 extended_result);

        [DllImport("dfmbios64.dll", EntryPoint = "flash_hp_device", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 flash_hp_device64([In] string firmware_file, [In] ref bios_credential_t credentials, [Out] out UInt32 mi_result, [MarshalAs(UnmanagedType.FunctionPtr)]  ProgressCallback callback, [In] string filename_hint, [In] string efi_path, [In] byte[] authorization, [In] UInt32 auth_len, [In] bool delayed, [In] bool no_wait);
        [DllImport("dfmbios32.dll", EntryPoint = "flash_hp_device", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 flash_hp_device32([In] string firmware_file, [In] ref bios_credential_t credentials, [Out] out UInt32 mi_result,[MarshalAs(UnmanagedType.FunctionPtr)]   ProgressCallback callback, [In] string filename_hint, [In] string efi_path, [In] byte[] authorization, [In] UInt32 auth_len, [In] bool delayed, [In] bool no_wait);

        [DllImport("dfmbios64.dll", EntryPoint = "online_flash_supported", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 online_flash_supported64([Out] out UInt32 mi_result);
        [DllImport("dfmbios32.dll", EntryPoint = "online_flash_supported", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 online_flash_supported32([Out] out UInt32 mi_result);

        [DllImport("dfmbios64.dll", EntryPoint = "write_authorization_to_file", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 write_authorization_to_file64([In] byte[] authorization, [In] UInt32 auth_len, [In] string efi_path);
        [DllImport("dfmbios32.dll", EntryPoint = "write_authorization_to_file", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern Int32 write_authorization_to_file32([In] byte[] authorization, [In] UInt32 auth_len, [In] string efi_path);

        [DllImport("dfmbios32.dll", EntryPoint = "get_flash_file_information", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern UInt32 get_flash_file_information32([In] string firmware_file, [Out] out  UInt32 is_capsule, [Out] out UInt32 is_for_current_platform);
        [DllImport("dfmbios64.dll", EntryPoint = "get_flash_file_information", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern UInt32 get_flash_file_information64([In] string firmware_file, [Out] out  UInt32 is_capsule, [Out] out UInt32 is_for_current_platform);

        [DllImport("dfmbios32.dll", EntryPoint = "encrypt_password_to_file", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern UInt32 encrypt_password_to_file32([In] ref bios_credential_t credentials, [In] string firmware_file);
        [DllImport("dfmbios64.dll", EntryPoint = "encrypt_password_to_file", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern UInt32 encrypt_password_to_file64([In] ref bios_credential_t credentials, [In] string firmware_file);
     }

// HP SECURE PLATFORM

  public enum provisioning_state_t : byte
    {
        NotConfigured = 0,
        Provisioned = 1,
        ProvisioningInProgress = 2
    };

    [Flags]
    public enum secureplatform_features_t : uint
    {
    None = 0,
        SureRun = 1,
        SureRecover = 2,
        Auth = 3,
        SureAdmin = 4
    };

  public struct PortableFileFormat {
    public DateTime timestamp;
    public string purpose;
        public byte[] Data;
        public byte[] Meta1;
        public byte[] Meta2;
        public byte[] Meta3;
        public byte[] Meta4;
  };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct provisioning_data_t
    {
        [MarshalAs(UnmanagedType.U1)] public provisioning_state_t state;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=2)] public byte[] subsystem_version; // major minor
        [MarshalAs(UnmanagedType.U2)] public ushort reserved;
        [MarshalAs(UnmanagedType.U4)] public secureplatform_features_t features_in_use;
        [MarshalAs(UnmanagedType.U4)] public UInt32 arp_counter;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] kek_mod;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)] public byte[] sk_mod;
    };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct  sk_provisioning_payload_t {
        [MarshalAs(UnmanagedType.U4)]  public uint counter;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] mod;
      } ;



    public  static  class DfmNativeSecurePlatform
    {
        [DllImport("dfmbios32.dll", EntryPoint = "sp_get_provisioning", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_secureplatform_provisioning32([In,Out] ref provisioning_data_t data, [In,Out] ref int extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_get_provisioning", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_secureplatform_provisioning64([In,Out] ref provisioning_data_t data, [In,Out] ref int extended_result);

        [DllImport("dfmbios32.dll", EntryPoint = "sp_get_ek_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_ek_provisioning_data32([In] byte[] key, [In] int key_length, [In]  string password, [In]  int password_length,   [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_get_ek_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_ek_provisioning_data64([In] byte[] key, [In] int key_length, [In]  string password, [In]  int password_length,  [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);

        [DllImport("dfmbios32.dll", EntryPoint = "sp_set_ek_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int set_ek_provisioning32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_set_ek_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int set_ek_provisioning64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

        [DllImport("dfmbios32.dll", EntryPoint = "sp_set_sk_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int set_sk_provisioning32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_set_sk_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int set_sk_provisioning64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    };

    // HP SureRecover

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct sk_provisioning_t {
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] sig;
      public sk_provisioning_payload_t data;
  };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_configuration_t {
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] sig;
      public surerecover_configuration_payload_t data;
  };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_configuration_payload_t
  {
    [MarshalAs(UnmanagedType.U4)] public UInt32 arp_counter;
    [MarshalAs(UnmanagedType.U4)] public surerecover_os_flags os_flags;
    [MarshalAs(UnmanagedType.U4)] public surerecover_re_flags re_flags;
  };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_trigger_t {
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] sig;
      public surerecover_trigger_payload_t data;
  };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_trigger_payload_t
  {
    [MarshalAs(UnmanagedType.U4)] public UInt32 arp_counter;
    [MarshalAs(UnmanagedType.U4)] public UInt32 bios_trigger_flags;
    [MarshalAs(UnmanagedType.U4)] public UInt32 re_trigger_flags;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] reserved;
  };

    [Flags]
    public enum surerecover_day_of_week : byte
    {
    Sunday = 1,
    Monday = 2,
        Tuesday = 4,
        Wednesday = 8,
        Thursday = 16,
    Friday = 32,
    Saturday = 64,
    EveryWeek = 128
    };

    [Flags]
    public enum surerecover_os_flags : uint
    {
      None = 0,
      NetworkBasedRecovery = 1,
      WiFi = 2,
      PartitionRecovery = 4,
      SecureStorage = 8,
      SecureEraseUnit = 16,
      RollbackPrevention = 64,
    };


  [Flags]
  public enum surerecover_prompt_policy : uint
  {
    None = 0,
    PromptBeforeRecovery = 1,
    PromptOnError = 2,
    PromptAfterRecover = 4
  };

  [Flags]
  public enum surerecover_erase_policy : uint
  {
    None = 0,
    EraseSecureStorage = 16,
    EraseSystemDrives = 32
  };


    [Flags]
    public enum surerecover_re_flags : uint
    {
      None = 0,
      DRDVD = 1,
      CorporateReadyWithoutOffice = 2,
      CorporateReadyWithOffice = 4,
      InstallManageabilitySuite = 16,
      InstallSecuritySuite = 32,
      RollbackPrevention = 64,
    };


   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct surerecover_schedule_data_t
  {
    [MarshalAs(UnmanagedType.U1)] public surerecover_day_of_week  day_of_week;
    [MarshalAs(UnmanagedType.U1)] public byte hour;
    [MarshalAs(UnmanagedType.U1)] public byte minute;
    [MarshalAs(UnmanagedType.U1)] public byte window_size;
  };


   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct surerecover_schedule_data_payload_t
  {
    [MarshalAs(UnmanagedType.U4)] public UInt32  nonce;
    public surerecover_schedule_data_t schedule;
  };
   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct surerecover_schedule_payload_t
  {
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] sig;
      public surerecover_schedule_data_payload_t data;
  };


  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_state_t
  {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=2)] public byte[] subsystem_version; // major minor
    [MarshalAs(UnmanagedType.U4)] public UInt32 nonce;
    [MarshalAs(UnmanagedType.U4)] public surerecover_os_flags os_flags;
    [MarshalAs(UnmanagedType.U4)] public surerecover_re_flags re_flags;
    public surerecover_schedule_data_t schedule;
    [MarshalAs(UnmanagedType.U4)] public UInt32 flags;
    [MarshalAs(UnmanagedType.U2)] public UInt16 image_failover;
    [MarshalAs(UnmanagedType.U2)] public UInt16 agent_failover;
  };

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public struct surerecover_failover_configuration_t
  {
    [MarshalAs(UnmanagedType.U2)] public UInt16 version;
    [MarshalAs(UnmanagedType.BStr)] public string username;
    [MarshalAs(UnmanagedType.BStr)] public string url;
  };

  public  static  class DfmNativeSureRecover
    {

    [DllImport("dfmbios32.dll", EntryPoint = "sp_get_osr_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_state32([In,Out] ref surerecover_state_t data, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_get_osr_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_state64([In,Out] ref surerecover_state_t data, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_get_osr_failover", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_failover_configuration32([In] bool agent, [In] byte index, [In,Out] ref surerecover_failover_configuration_t data, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_get_osr_failover", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_failover_configuration64([In] bool agent, [In] byte index, [In,Out] ref surerecover_failover_configuration_t data, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_deprovision_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_deprovision_opaque32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_deprovision_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_deprovision_opaque64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_os_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_osr_provisioning32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_os_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_osr_provisioning64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_re_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_re_provisioning32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_re_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_re_provisioning64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_failover_os_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_osr_failover32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_failover_os_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_osr_failover64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_schedule_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_schedule32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_schedule_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_schedule64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_get_osr_provisioning_opaque", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_provisioning_opaque32([In] UInt32 nonce, [In] UInt16 version, [In] byte[] ok, [In] UInt32 ok_size, [In] string username, [In] string password, [In] string url,   [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_get_osr_provisioning_opaque", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_provisioning_opaque64([In] UInt32 nonce, [In] UInt16 version, [In] byte[] ok, [In] UInt32 ok_size, [In] string username, [In] string password, [In] string url,   [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_get_osr_failover_opaque", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_failover_opaque32([In] UInt32 nonce, [In] UInt16 version, [In] byte index, [In] string username, [In] string password, [In] string url, [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_get_osr_failover_opaque", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerecover_failover_opaque64([In] UInt32 nonce, [In] UInt16 version, [In] byte index, [In] string username, [In] string password, [In] string url, [In,Out] ref opaque4096_t data, [In,Out] ref int data_len, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_configuration_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_configuration32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_configuration_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_configuration64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_set_osr_trigger_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_trigger32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_set_osr_trigger_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surerecover_trigger64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);

    [DllImport("dfmbios32.dll", EntryPoint = "sp_osr_raise_service_event_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int raise_surerecover_service_event_opaque32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    [DllImport("dfmbios64.dll", EntryPoint = "sp_osr_raise_service_event_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int raise_surerecover_service_event_opaque64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);


    }

  public enum sr_activation_state_t : uint
  {
    Deactivated = 0,
    Activated = 1,
    PermanentlyDisabled = 2,
    Suspended = 3,
    ActivatedNoManifest = 4,
    SecurePlatformNotProvisioned = 5,
    ActivationInProgress = 6,
    RecoveryMode = 7
  }

  [Flags]
  public enum sr_config_t : uint
  {
    None = 0,
    HibernateOnHeartbearTimeout = 1
  }

  [Flags]
  public enum sr_capabilities_t : uint
  {
    None = 0,
    ManifestEncryptionSupported = 1
  }


    // HP SureRun
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct surerun_state_t
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=2)] public byte[]  subsystem_version;
        [MarshalAs(UnmanagedType.U4)] public sr_activation_state_t  activation_state;
        [MarshalAs(UnmanagedType.U4)] public UInt32  flags;
        [MarshalAs(UnmanagedType.U4)] public sr_capabilities_t  capabilities;
        [MarshalAs(UnmanagedType.U4)] public UInt32  max_manifest_size;
        [MarshalAs(UnmanagedType.U4)] public UInt32  command_counter;
        [MarshalAs(UnmanagedType.U4)] public sr_config_t  config_flags;
    [MarshalAs(UnmanagedType.BStr)] public string manifest;
    [MarshalAs(UnmanagedType.U4)] public UInt32 manifest_size;
    [MarshalAs(UnmanagedType.U4)] public UInt32 manifest_was_retrieved;
    };

    public struct surerun_manifestinfo_t {
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 256)]  public byte[] sig;
      public surerun_manifestinfo_payload_t data;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct surerun_manifestinfo_payload_t
    {
        [MarshalAs(UnmanagedType.U4)]  public uint counter;
        [MarshalAs(UnmanagedType.U2)]  public ushort total_size;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 32)]  public byte[] hash;
    }

    public static class DfmNativeSureRun
    {
        [DllImport("dfmbios32.dll", EntryPoint = "sp_get_sr_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerun_state32([In,Out] ref surerun_state_t data, [In,Out] ref int extended_result, bool include_manifest);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_get_sr_state", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_surerun_state64([In,Out] ref surerun_state_t data, [In,Out] ref int extended_result, bool include_manifest);

        [DllImport("dfmbios32.dll", EntryPoint = "sp_set_sr_manifest_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surererun_manifest32([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
        [DllImport("dfmbios64.dll", EntryPoint = "sp_set_sr_manifest_opaque", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_surererun_manifest64([In] byte[] data, [In] int data_size, [In,Out] ref int extended_result);
    };

    public static class DfmNativeQRCode
    {
        [DllImport("dfmbios32.dll", EntryPoint = "create_qrcode", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int create_qrcode32([In] string data, [In,Out] byte[] qr);
        [DllImport("dfmbios64.dll", EntryPoint = "create_qrcode", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int create_qrcode64([In] string data, [In,Out] byte[] qr);

        [DllImport("dfmbios32.dll", EntryPoint = "get_console_font_height", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_console_font_height32();
        [DllImport("dfmbios64.dll", EntryPoint = "get_console_font_height", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_console_font_height64();

        [DllImport("dfmbios32.dll", EntryPoint = "get_console_font_width", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_console_font_width32();
        [DllImport("dfmbios64.dll", EntryPoint = "get_console_font_width", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_console_font_width64();

        [DllImport("dfmbios32.dll", EntryPoint = "get_screen_scale", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern float get_screen_scale32();
        [DllImport("dfmbios64.dll", EntryPoint = "get_screen_scale", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern float get_screen_scale64();
    }

    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public class Win32Window : IWin32Window
    {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        private IntPtr _hWnd;
        private int _data;

        public int Data
        {
            get { return _data; }
            set { _data = value; }
        }

        public Win32Window(IntPtr handle)
        {
            _hWnd = handle;
        }

        public IntPtr Handle
        {
            get { return _hWnd; }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SureAdminSignatureBlockHeader
    {
        public byte Version;
        public UInt16 NameLength;
        public UInt16 ValueLength;
        public byte OneTimeUse;
        public UInt32 Nonce;
        public byte Reserved;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I1, SizeConst = 16)]
        public byte[] Target;
    }

    // hp retail

    public enum RetailSmartDockMode : uint
    {
        Fast = 0,
        Pin = 1,
        FastSecure = 2,
        PinSecure = 3,
        Application = 4,
        Unknown = 0xffffffff
    }

    public enum RetailSmartDockState : uint
    {
        Undocked = 0,
        Docked = 1,
        Jammed = 2,
        Unknown = 0xffffffff
    }

    public enum RetailSmartDockHubState  : uint
    {
        None = 0,
        AdvancedConnectivtyBase = 1,
        BasicConnectivityBase = 2,
        Unknown = 0xffffffff
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RetailInformation {
        public UInt32 IsSupported;
        public UInt32 Mode;
        public UInt32 DockState;
        public UInt32 HubState;
        public UInt32 Timeout;
        public UInt32 PinSize;
        public UInt32 BaseLockoutTimer;
        public UInt32 RelockTimer;
        public UInt32 DockCounter;
        public UInt32 UndockCounter;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Pin;
     }






    public  static  class DfmNativeRetail
    {

            [DllImport("dfmbios32.dll", EntryPoint = "get_retail_dock_configuration", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
            public static extern int get_retail_dock_configuration_32(ref RetailInformation data, [Out] out UInt32 extended_result);
            [DllImport("dfmbios64.dll", EntryPoint = "get_retail_dock_configuration", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
            public static extern int get_retail_dock_configuration_64(ref RetailInformation data, [Out] out UInt32 extended_result);

            [DllImport("dfmbios32.dll", EntryPoint = "set_retail_dock_configuration", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
            public static extern int set_retail_dock_configuration_32(ref RetailInformation data, [Out] out UInt32 extended_result);
            [DllImport("dfmbios64.dll", EntryPoint = "set_retail_dock_configuration", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
            public static extern int set_retail_dock_configuration_64(ref RetailInformation data, [Out] out UInt32 extended_result);


    }

'@ -ReferencedAssemblies 'System.Windows.Forms.dll'






# SIG # Begin signature block
# MIIoHQYJKoZIhvcNAQcCoIIoDjCCKAoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDp44WN+mWqMoAR
# S3Vag6w16ZMlWy7ukP6QO8NZfc8v4KCCDYowggawMIIEmKADAgECAhAIrUCyYNKc
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB9geUs0
# u4CJfl0Qf2b3p4sPa2vGJJOF9TJ7MHEr7jRJMA0GCSqGSIb3DQEBAQUABIIBgCQ1
# noE/+hPR8txiuer75I0JXiGKFiTelmt4WN+1Y20o7NNY4ZQjGU8IDgf6Vp0X+i7O
# te80LjB+zuRdYFVdCziXA4A5JyFk/0XV+7JiDm1aR1k1kcR3npPTpCS0ns5RfxmN
# oeiYCtXct45bKIFnUT5ZEA2czAtS1DJHne4jg/GjMlIClvkY4rt9lrmtzbJGaO4I
# JVwOBMihbPLqyk0DcezvuGrptYonBXKKeC0XSlNh2eOmALnfRpLeJePJXVROtuYp
# Lg21EVjtt/bQn3l0bWZgMlk5AcwjywbCDHMHGyIPANxAip12F8GAkjbsauMjdvk8
# QU7DHE6seG0ss6+m0TXLOCcZWY8VHHvXP5rVjaWTH7H/ossh6hvmbHdXgnqhcZbh
# rYuZb8BvrZOJOz+5CWrCveRFpWtu928N67RPesOyxZ0IaQaJYGZwHJCWjpMIYKOn
# 6iDkvHl2EuC5yysOoYUziRoABoc6HKKKpGTbHAbLE8Ea8t6EFNSUbtM9h0MIgaGC
# Fz8wghc7BgorBgEEAYI3AwMBMYIXKzCCFycGCSqGSIb3DQEHAqCCFxgwghcUAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG
# /WwHATAxMA0GCWCGSAFlAwQCAQUABCBy7GRz0dNEKtKi1XHkk32mjchi8F7I3Ij+
# UdFC1zG4IwIQVChJ8kvF1clJhKruPNKHDhgPMjAyNDAyMjgxOTU1NDdaoIITCTCC
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
# BDEiBCBdvSJV7fjUZigh09C2LW0R+A8HJBLgj7qxbg4fuU/0VjA3BgsqhkiG9w0B
# CRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZvgoraVZquMxavTRqa1Ax4KDAN
# BgkqhkiG9w0BAQEFAASCAgBJ79PSzNvGqW0vcpVbrf9QQe5SM/aXx6OHh6LICeKZ
# eH39z/MCnBBoe684SfdLfEmKz6IgV6Y2K3zxgWj5McdsnyUJVywH/itopQs3bgDH
# QMcCfKVN/I8kUuD/inJ27+hlPKPOYHbLkgp0FsVCdevo+ljwCBkMuc1BixOHMlb7
# Pi5ClDbjwhe99JSlQsS9dyMs1sPvVXGhEyNG+cRvsmoOjxCBCRjQbMnnlDD754rw
# rxCKMnsXz+iRxIrzyeQBalP83GUpYyo7W4OqFmT6Bu0H2xYx8JQoVQ7OJxwVsyfK
# kvDVGMH6vkq680hA0PJnfLAzHXAfugTNe8wSGK9OqEQZYsWkDcmCa9cppalEC8HB
# lvc85UTwdI/ZWDrxd1qPagwNH7OJkWFMZP3tIPuMnikXhiOcuKB4D7XM6HIUZ5Mh
# FRWCHmJQtFc+Lf46pUBTeHKJczxLWVeUECQlydlYNxv5i6wD/i4l4PLKVEb4JzMd
# MiI4tnlNfNSJD2WxucSrqxG7cAfPk8Odx0GXX6JhRw5mTtJzpl372qdIC7T3onLd
# qLMKcXlTyEXDVPVYeSbLhUOeNzSuBSfvfKpC+AbxbDxiQ8A8bAhzVf/kQ3XzoaK8
# uS2itcZ+p+LLCqvF82KuteR+/SywGbgNwUif63PoYeW29WhFzbUpONs6OO+08Ia2
# pQ==
# SIG # End signature block
