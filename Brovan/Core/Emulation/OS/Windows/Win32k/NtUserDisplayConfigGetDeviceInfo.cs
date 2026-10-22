using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDisplayConfigGetDeviceInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PacketPtr = Instance.WinHelper.GetArg(0);

            Span<byte> Header = stackalloc byte[Win32kDisplayConfig.HeaderSize];
            if (PacketPtr == 0 || !Instance.ReadMemory(PacketPtr, Header))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            uint Type = BinaryPrimitives.ReadUInt32LittleEndian(Header);
            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(4));
            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(16));

            if (Type == Win32kDisplayConfig.DeviceInfoGetDisplayInfo)
            {
                DxgkAdapter Adapter = Win32kDxgk.FindByLuid(Header.Slice(8));
                bool WithSource = Id != Win32kDisplayConfig.NoSource;

                if (Size != Win32kDisplayConfig.DisplayInfoSize || Adapter == null || (WithSource && Id >= Adapter.SourceCount)
                    || !Win32kDisplayConfig.WriteDisplayInfo(Instance, PacketPtr, Adapter, WithSource))
                {
                    return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);
                }

                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
            }

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
