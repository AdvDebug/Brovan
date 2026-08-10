using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    /// <summary>
    /// user32 hands the kernel a buffer whose leading DWORD is the caller's cb, with DISPLAY_DEVICEW's fields
    /// starting right after it, and copies cb - 4 bytes back into the caller's structure.
    /// </summary>
    internal class NtUserEnumDisplayDevices : IWinSyscall
    {
        private const int DisplayDeviceSize = 0x348;
        private const int OffsetDeviceName = 0x04;
        private const int OffsetDeviceString = 0x44;
        private const int OffsetStateFlags = 0x144;
        private const int OffsetDeviceId = 0x148;
        private const int OffsetDeviceKey = 0x248;

        private const int DeviceNameCharacters = 32;
        private const int DeviceStringCharacters = 128;

        private const uint DisplayDeviceActive = 0x00000001;
        private const uint DisplayDeviceAttached = 0x00000002;
        private const uint DisplayDevicePrimaryDevice = 0x00000004;
        private const uint DisplayDeviceVgaCompatible = 0x00000010;

        private const string AdapterName = @"\\.\DISPLAY1";
        private const string AdapterString = "Brovan Display Adapter";
        private const string AdapterId = @"PCI\VEN_0000&DEV_0000&SUBSYS_00000000&REV_00";
        private const string AdapterKey = @"\Registry\Machine\System\CurrentControlSet\Control\Video\{00000000-0000-0000-0000-000000000000}\0000";
        private const string MonitorName = @"\\.\DISPLAY1\Monitor0";
        private const string MonitorString = "Generic PnP Monitor";
        private const string MonitorId = @"MONITOR\Default_Monitor\{4d36e96e-e325-11ce-bfc1-08002be10318}\0001";
        private const string MonitorKey = @"\Registry\Machine\System\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}\0001";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DevicePtr = Instance.WinHelper.GetArg(0);
            uint DeviceIndex = Instance.WinHelper.GetArg32(1);
            ulong DisplayDevicePtr = Instance.WinHelper.GetArg(2);

            if (DisplayDevicePtr == 0 || !Instance.IsRegionMapped(DisplayDevicePtr, OffsetStateFlags + 4))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Size = Instance.ReadMemoryUInt(DisplayDevicePtr);
            if (Size < OffsetStateFlags + 4 || !Instance.IsRegionMapped(DisplayDevicePtr, Size))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (DeviceIndex != 0)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            bool EnumeratingAdapters = DevicePtr == 0;
            if (!EnumeratingAdapters)
            {
                if (!Instance.WinHelper.TryReadUnicodeString(DevicePtr, out string Adapter, out _)
                    || !string.Equals(Adapter, AdapterName, StringComparison.OrdinalIgnoreCase))
                {
                    return NTSTATUS.STATUS_UNSUCCESSFUL;
                }
            }

            if (!Instance.WinHelper.TryGetPrimaryMonitorRect(out _, out _, out _, out _))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            int Written = (int)Math.Min(Size, DisplayDeviceSize) - OffsetDeviceName;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Written);
            Buffer = Buffer.Slice(0, Written);
            Buffer.Clear();

            WriteField(Buffer, OffsetDeviceName, DeviceNameCharacters, EnumeratingAdapters ? AdapterName : MonitorName);
            WriteField(Buffer, OffsetDeviceString, DeviceStringCharacters, EnumeratingAdapters ? AdapterString : MonitorString);
            WriteField(Buffer, OffsetDeviceId, DeviceStringCharacters, EnumeratingAdapters ? AdapterId : MonitorId);
            WriteField(Buffer, OffsetDeviceKey, DeviceStringCharacters, EnumeratingAdapters ? AdapterKey : MonitorKey);

            uint StateFlags = EnumeratingAdapters
                ? DisplayDeviceActive | DisplayDevicePrimaryDevice | DisplayDeviceVgaCompatible
                : DisplayDeviceActive | DisplayDeviceAttached;

            int StateFlagsIndex = OffsetStateFlags - OffsetDeviceName;
            if (StateFlagsIndex + 4 <= Buffer.Length)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(StateFlagsIndex, 4), StateFlags);

            if (!Instance.WriteMemory(DisplayDevicePtr + OffsetDeviceName, Buffer))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteField(Span<byte> Buffer, int FieldOffset, int FieldCharacters, string Value)
        {
            int Index = FieldOffset - OffsetDeviceName;
            if (Index >= Buffer.Length)
                return;

            int Available = Math.Min(FieldCharacters - 1, (Buffer.Length - Index) / sizeof(char));
            if (Available <= 0)
                return;

            string Text = Value.Length > Available ? Value.Substring(0, Available) : Value;
            Encoding.Unicode.GetBytes(Text, Buffer.Slice(Index, Text.Length * sizeof(char)));
        }
    }
}
