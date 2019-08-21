namespace AmsiSandbox.GroupPolicyCom
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.InteropServices;
    using System.Text;

    [ComImport]
    [Guid("EA502722-A23D-11d1-A7D3-0000F87571E3")]
    internal class GPClass
    {
    }

    [ComImport]
    [Guid("EA502723-A23D-11d1-A7D3-0000F87571E3")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IGroupPolicyObject
    {
        [SuppressMessage("Microsoft.Naming", "CA1716:IdentifiersShouldNotMatchKeywords")]
        uint New(
            [MarshalAs(UnmanagedType.LPWStr)] string domainName,
            [MarshalAs(UnmanagedType.LPWStr)] string displayName,
            uint flags);

        [SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly")]
        uint OpenDSGPO(
            [MarshalAs(UnmanagedType.LPWStr)] string path,
            uint flags);

        uint OpenLocalMachineGPO(
            uint flags);

        uint OpenRemoteMachineGPO(
            [MarshalAs(UnmanagedType.LPWStr)] string computerName,
            uint flags);

        uint Save(
            [MarshalAs(UnmanagedType.Bool)] bool machine,
            [MarshalAs(UnmanagedType.Bool)] bool add,
            [MarshalAs(UnmanagedType.LPStruct)] Guid extension,
            [MarshalAs(UnmanagedType.LPStruct)] Guid app);

        uint Delete();

        uint GetName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder name,
            int maxLength);

        uint GetDisplayName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder name,
            int maxLength);

        uint SetDisplayName(
            [MarshalAs(UnmanagedType.LPWStr)] string name);

        uint GetPath(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path,
            int maxPath);

        uint GetDSPath(
            uint section,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path,
            int maxPath);

        uint GetFileSysPath(
            uint section,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path,
            int maxPath);

        uint GetRegistryKey(
            uint section,
            out IntPtr key);

        uint GetOptions(out uint options);

        uint SetOptions(
            uint options,
            uint mask);

        uint GetType(
            out IntPtr gpoType
        );

        uint GetMachineName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder name,
            int maxLength);

        uint GetPropertySheetPages(
            out IntPtr pages);
    }

    public struct GroupPolicyObjectOptions
    {
        public readonly bool UserEnabled;
        public readonly bool MachineEnabled;

        public GroupPolicyObjectOptions(bool userEnabled = true, bool machineEnabled = true)
        {
            UserEnabled = userEnabled;
            MachineEnabled = machineEnabled;
        }
        public GroupPolicyObjectOptions(uint flag)
        {
            UserEnabled = (flag & disableUserFlag) == 0;
            MachineEnabled = (flag & disableMachineFlag) == 0;
        }

        private const uint disableUserFlag = 0x00000001;
        private const uint disableMachineFlag = 0x00000002;

        internal uint Flag
        {
            get
            {
                uint flag = 0x00000000;
                if (!UserEnabled)
                    flag |= disableUserFlag;
                if (!MachineEnabled)
                    flag |= disableMachineFlag;
                return flag;
            }
        }

        internal uint Mask
        {
            get
            {
                // We always change everything
                return disableUserFlag
                       | disableMachineFlag;
            }
        }
    }

    public enum GroupPolicySection
    {
        Root = 0,
        User = 1,
        Machine = 2,
    }
}