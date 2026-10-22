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
        internal const uint DeviceInfoGetDisplayInfo = 0xFFFFFFEB;

        // An undocumented record that dxgi builds its adapters and outputs from.
        internal const int DisplayInfoSize = 2056;
        internal const uint NoSource = 0xFFFFFFFF;
        private const int DisplayInfoAdapter = 0x14;
        private const int DisplayInfoRenderAdapter = 0x340;
        private const int AdapterBlockVendorId = 4;
        private const int AdapterBlockDeviceId = 8;
        private const int AdapterBlockDriverVersion = 24;
        private const int AdapterBlockDescription = 0x1C;
        private const int AdapterBlockInterface = 0x11C;
        private const int DescriptionCharacters = 128;
        private const int InterfaceCharacters = 260;
        private const int AdapterBlockSize = AdapterBlockInterface + InterfaceCharacters * 2;
        private const int DisplayInfoModeWidth = 0x674;
        private const int DisplayInfoDeviceName = 0x67C;
        private const int DisplayInfoMonitor = 0x77C;
        private const int DisplayInfoActiveWidth = 0x784;
        private const int DisplayInfoRefresh = 0x790;
        private const int DisplayInfoDesktopWidth = 0x7A8;
        private const int DisplayInfoBitsPerColor = 0x7B8;
        private const int DisplayInfoPrimaries = 0x7C0;
        private const uint BitsPerColor = 8;
        private static readonly int[] SrgbPrimaries = Array.ConvertAll(new[] { 0.64, 0.33, 0.30, 0.60, 0.15, 0.06, 0.3127, 0.3290 },
            Value => (int)Math.Round(Value * (1 << 20)));

        internal const uint TopologyInternal = 1;

        internal const uint SourceId = 0;
        internal const uint TargetId = 1;

        internal const uint OutputTechnologyDisplayPort = 10;
        private const uint RotationIdentity = 1;
        private const uint ScalingIdentity = 1;
        private const uint ScanLineOrderingProgressive = 1;

        internal const int HeaderSize = 20;

        private const uint FriendlyNameForced = 0x00000002;

        internal const string AdapterName = @"\\.\DISPLAY1";
        internal const string MonitorFriendlyName = "Generic PnP Monitor";
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
            Win32kDxgk.WriteLuid(Record.Slice(ModalityAdapterId, 8), Win32kDxgk.Display);
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

        internal static bool WriteDisplayInfo(BinaryEmulator Instance, ulong Destination, DxgkAdapter Adapter, bool WithSource)
        {
            // The monitor lookup can use the shared buffer, so it runs first.
            uint Monitor = WithSource ? (uint)Instance.WinHelper.GetPrimaryMonitorHandle() : 0;
            Span<byte> Info = Instance.WinHelper.Shared.GetSpan(DisplayInfoSize).Slice(0, DisplayInfoSize);
            Info.Clear();

            Span<byte> Block = Info.Slice(DisplayInfoAdapter, AdapterBlockSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Block, Adapter.BusType);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(AdapterBlockVendorId), Adapter.VendorId);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(AdapterBlockDeviceId), Adapter.DeviceId);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(AdapterBlockDriverVersion), Win32kDxgk.WddmVersion);
            WriteString(Block.Slice(AdapterBlockDescription, DescriptionCharacters * 2), Adapter.Description);
            WriteString(Block.Slice(AdapterBlockInterface, InterfaceCharacters * 2), Adapter.DeviceInterface);
            Block.CopyTo(Info.Slice(DisplayInfoRenderAdapter));

            if (WithSource)
            {
                uint Width = (uint)HostDisplayMetrics.ScreenWidth;
                uint Height = (uint)HostDisplayMetrics.ScreenHeight;

                foreach (int Offset in stackalloc int[] { DisplayInfoModeWidth, DisplayInfoActiveWidth, DisplayInfoDesktopWidth })
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(Offset), Width);
                    BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(Offset + 4), Height);
                }

                WriteString(Info.Slice(DisplayInfoDeviceName, 64), AdapterName);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(DisplayInfoMonitor), Monitor);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(DisplayInfoRefresh), RefreshHz);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(DisplayInfoRefresh + 4), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(DisplayInfoBitsPerColor), BitsPerColor);

                for (int Index = 0; Index < SrgbPrimaries.Length; Index++)
                    BinaryPrimitives.WriteInt32LittleEndian(Info.Slice(DisplayInfoPrimaries + Index * 4), SrgbPrimaries[Index]);
            }

            return Instance.WriteMemory(Destination + DisplayInfoAdapter, Info.Slice(DisplayInfoAdapter));
        }

        private static void WriteString(Span<byte> Field, string Value)
        {
            int Characters = Math.Min(Value.Length, Field.Length / sizeof(char) - 1);
            System.Text.Encoding.Unicode.GetBytes(Value.AsSpan(0, Characters), Field);
        }

    }
}
