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
        internal const uint ModeCount = 2;

        internal const int PathInfoSize = 72;
        internal const int ModeInfoSize = 64;

        internal const uint TopologyInternal = 1;

        internal const uint SourceId = 0;
        internal const uint TargetId = 1;

        private const uint PathActive = 0x00000001;
        private const uint OutputTechnologyDisplayPort = 10;
        private const uint RotationIdentity = 1;
        private const uint ScalingIdentity = 1;
        private const uint ScanLineOrderingProgressive = 1;
        private const uint PixelFormat32Bpp = 3;
        private const uint ModeInfoTypeSource = 1;
        private const uint ModeInfoTypeTarget = 2;

        private const uint RefreshHz = 60;
        private const int SourceModeIndex = 0;
        private const int TargetModeIndex = 1;

        /// <summary>
        /// The DisplayConfig syscalls answer in Win32 error codes, not NTSTATUS. Their callers retry on
        /// ERROR_INSUFFICIENT_BUFFER, and an NTSTATUS in its place reads as a hard failure.
        /// </summary>
        internal static NTSTATUS Complete(BinaryEmulator Instance, uint Win32Error)
        {
            Instance.SetRawSyscallReturn(Win32Error);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static bool WritePaths(BinaryEmulator Instance, ulong Destination)
        {
            Span<byte> Path = Instance.WinHelper.Shared.GetSpan(PathInfoSize).Slice(0, PathInfoSize);
            Path.Clear();

            // DISPLAYCONFIG_PATH_SOURCE_INFO
            Win32kDxgk.WriteLuid(Path.Slice(0, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(8, 4), SourceId);
            BinaryPrimitives.WriteInt32LittleEndian(Path.Slice(12, 4), SourceModeIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(16, 4), 0);

            // DISPLAYCONFIG_PATH_TARGET_INFO
            Win32kDxgk.WriteLuid(Path.Slice(20, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(28, 4), TargetId);
            BinaryPrimitives.WriteInt32LittleEndian(Path.Slice(32, 4), TargetModeIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(36, 4), OutputTechnologyDisplayPort);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(40, 4), RotationIdentity);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(44, 4), ScalingIdentity);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(48, 4), RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(52, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(56, 4), ScanLineOrderingProgressive);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(60, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(64, 4), 0);

            BinaryPrimitives.WriteUInt32LittleEndian(Path.Slice(68, 4), PathActive);

            return Instance.WriteMemory(Destination, Path);
        }

        internal static bool WriteModes(BinaryEmulator Instance, ulong Destination)
        {
            uint Width = (uint)HostDisplayMetrics.ScreenWidth;
            uint Height = (uint)HostDisplayMetrics.ScreenHeight;

            Span<byte> Modes = Instance.WinHelper.Shared.GetSpan(ModeInfoSize * (int)ModeCount)
                                       .Slice(0, ModeInfoSize * (int)ModeCount);
            Modes.Clear();

            Span<byte> Source = Modes.Slice(SourceModeIndex * ModeInfoSize, ModeInfoSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Source.Slice(0, 4), ModeInfoTypeSource);
            BinaryPrimitives.WriteUInt32LittleEndian(Source.Slice(4, 4), SourceId);
            Win32kDxgk.WriteLuid(Source.Slice(8, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Source.Slice(16, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Source.Slice(20, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Source.Slice(24, 4), PixelFormat32Bpp);
            BinaryPrimitives.WriteInt32LittleEndian(Source.Slice(28, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Source.Slice(32, 4), 0);

            Span<byte> Target = Modes.Slice(TargetModeIndex * ModeInfoSize, ModeInfoSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(0, 4), ModeInfoTypeTarget);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(4, 4), TargetId);
            Win32kDxgk.WriteLuid(Target.Slice(8, 8));

            // DISPLAYCONFIG_VIDEO_SIGNAL_INFO
            ulong PixelRate = (ulong)Width * Height * RefreshHz;
            BinaryPrimitives.WriteUInt64LittleEndian(Target.Slice(16, 8), PixelRate);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(24, 4), Height * RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(28, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(32, 4), RefreshHz);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(36, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(40, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(44, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(48, 4), Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(52, 4), Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(56, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(60, 4), ScanLineOrderingProgressive);

            return Instance.WriteMemory(Destination, Modes);
        }
    }
}
