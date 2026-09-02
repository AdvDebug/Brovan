using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    /// <summary>
    /// The one active display path Brovan reports through the DisplayConfig API. DXGI reads it to build its
    /// output list and to find a monitor device path, so an empty answer leaves a guest with no outputs.
    /// </summary>
    internal static class Win32kDisplayConfig
    {
        internal const uint PathCount = 1;

        internal const int ModalitySize = 216;

        private const int ModalityFlags = 0;
        private const int ModalityAdapterId = 16;
        private const int ModalitySourceId = 24;
        private const int ModalityTargetId = 28;
        private const int ModalitySignalInfo = 32;
        private const int ModalityOutputTechnology = 80;
        private const int ModalityRotation = 104;
        private const int ModalityScalingLegacy = 108;
        private const int ModalityScaling = 112;
        private const int ModalitySourcePosition = 116;
        private const int ModalitySourceWidth = 124;
        private const int ModalitySourceHeight = 128;
        private const int ModalityRemovalReason = 188;

        private const ulong ModalityTargetMode = 0x0000000000000002;
        private const ulong ModalitySourcePositionValid = 0x0000000000000800;
        private const ulong ModalityScalingValid = 0x0000000000010000;
        private const ulong ModalitySourceMode = 0x0000000000020000;
        private const ulong ModalityScalingLegacyValid = 0x0000040000000000;
        private const ulong ModalityTargetAvailable = 0x0100000000000000;
        private const ulong ModalityTargetInUse = 0x2000000000000000;
        private const ulong ModalitySourceInUse = 0x4000000000000000;
        private const ulong ModalityPathActive = 0x8000000000000000;

        internal const int SourceDeviceNameSize = 84;
        internal const int TargetDeviceNameSize = 420;

        internal const uint DeviceInfoGetSourceName = 1;
        internal const uint DeviceInfoGetTargetName = 2;

        internal const uint TopologyInternal = 1;

        internal const uint SourceId = 0;
        internal const uint TargetId = 1;

        internal const uint OutputTechnologyDisplayPort = 10;
        private const uint RotationIdentity = 1;
        private const uint ScalingIdentity = 1;
        private const uint ScanLineOrderingProgressive = 1;

        internal const int HeaderSize = 20;

        private const uint FriendlyNameForced = 0x00000002;

        private const string AdapterName = @"\\.\DISPLAY1";
        private const string MonitorFriendlyName = "Generic PnP Monitor";
        private const string MonitorDevicePath =
            @"\\?\DISPLAY#Default_Monitor#1&0&UID0#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}";

        private const uint RefreshHz = 60;

        /// <summary>
        /// user32 runs the DisplayConfig results through RtlNtStatusToDosError, so the status has to reach it
        /// in the return register rather than as the dispatcher's own result.
        /// </summary>
        internal static NTSTATUS Complete(BinaryEmulator Instance, NTSTATUS Status)
        {
            Instance.SetRawSyscallReturn((uint)Status);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static bool WriteModality(BinaryEmulator Instance, ulong Destination)
        {
            uint Width = (uint)HostDisplayMetrics.ScreenWidth;
            uint Height = (uint)HostDisplayMetrics.ScreenHeight;

            Span<byte> Record = Instance.WinHelper.Shared.GetSpan(ModalitySize).Slice(0, ModalitySize);
            Record.Clear();

            ulong Flags = ModalityPathActive | ModalitySourceMode | ModalityTargetMode
                        | ModalitySourcePositionValid | ModalityScalingValid | ModalityScalingLegacyValid
                        | ModalityTargetAvailable | ModalityTargetInUse | ModalitySourceInUse;

            BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(ModalityFlags, 8), Flags);
            Win32kDxgk.WriteLuid(Record.Slice(ModalityAdapterId, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalitySourceId, 4), SourceId);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityTargetId, 4), TargetId);

            WriteVideoSignalInfo(Record.Slice(ModalitySignalInfo, 48), Width, Height);

            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityOutputTechnology, 4), OutputTechnologyDisplayPort);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityRotation, 4), RotationIdentity);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityScalingLegacy, 4), ScalingIdentity);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityScaling, 4), ScalingIdentity);
            BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(ModalitySourcePosition, 8), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalitySourceWidth, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalitySourceHeight, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(ModalityRemovalReason, 4), 0);

            return Instance.WriteMemory(Destination, Record);
        }

        private static void WriteVideoSignalInfo(Span<byte> Signal, uint Width, uint Height)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(Signal.Slice(0, 8), (ulong)Width * Height * RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(8, 4), Height * RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(12, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(16, 4), RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(20, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(24, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(28, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(32, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(36, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(40, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Signal.Slice(44, 4), ScanLineOrderingProgressive);
        }

        internal static bool WriteSourceName(BinaryEmulator Instance, ulong Destination)
        {
            Span<byte> Tail = Instance.WinHelper.Shared.GetSpan(SourceDeviceNameSize - HeaderSize)
                                      .Slice(0, SourceDeviceNameSize - HeaderSize);
            Tail.Clear();

            WriteString(Tail.Slice(0, 64), AdapterName);

            return Instance.WriteMemory(Destination + HeaderSize, Tail);
        }

        internal static bool WriteTargetName(BinaryEmulator Instance, ulong Destination)
        {
            Span<byte> Tail = Instance.WinHelper.Shared.GetSpan(TargetDeviceNameSize - HeaderSize)
                                      .Slice(0, TargetDeviceNameSize - HeaderSize);
            Tail.Clear();

            BinaryPrimitives.WriteUInt32LittleEndian(Tail.Slice(0, 4), FriendlyNameForced);
            BinaryPrimitives.WriteUInt32LittleEndian(Tail.Slice(4, 4), OutputTechnologyDisplayPort);
            BinaryPrimitives.WriteUInt32LittleEndian(Tail.Slice(12, 4), 0);

            WriteString(Tail.Slice(16, 128), MonitorFriendlyName);
            WriteString(Tail.Slice(144, 256), MonitorDevicePath);

            return Instance.WriteMemory(Destination + HeaderSize, Tail);
        }

        private static void WriteString(Span<byte> Field, string Value)
        {
            int Characters = Math.Min(Value.Length, Field.Length / sizeof(char) - 1);
            System.Text.Encoding.Unicode.GetBytes(Value.AsSpan(0, Characters), Field);
        }

    }
}
