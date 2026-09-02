using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDisplayConfigGetDeviceInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PacketPtr = Instance.WinHelper.GetArg(0);

            if (PacketPtr == 0 || !Instance.IsRegionMapped(PacketPtr, Win32kDisplayConfig.HeaderSize))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            uint Type = Instance.ReadMemoryUInt(PacketPtr);
            uint Size = Instance.ReadMemoryUInt(PacketPtr + 4);
            uint Id = Instance.ReadMemoryUInt(PacketPtr + 16);

            if (Type == Win32kDisplayConfig.DeviceInfoGetSourceName)
            {
                if (Size != Win32kDisplayConfig.SourceDeviceNameSize
                    || Id != Win32kDisplayConfig.SourceId
                    || !Instance.IsRegionMapped(PacketPtr, Size))
                {
                    return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);
                }

                if (!Win32kDisplayConfig.WriteSourceName(Instance, PacketPtr))
                    return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
            }

            if (Type == Win32kDisplayConfig.DeviceInfoGetTargetName)
            {
                if (Size != Win32kDisplayConfig.TargetDeviceNameSize
                    || Id != Win32kDisplayConfig.TargetId
                    || !Instance.IsRegionMapped(PacketPtr, Size))
                {
                    return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);
                }

                if (!Win32kDisplayConfig.WriteTargetName(Instance, PacketPtr))
                    return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
            }

            return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);
        }
    }
}
