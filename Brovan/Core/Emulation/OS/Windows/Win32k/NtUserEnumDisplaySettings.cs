using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnumDisplaySettings : IWinSyscall
    {
        private const uint EnumCurrentSettings = 0xFFFFFFFF;
        private const uint EnumRegistrySettings = 0xFFFFFFFE;

        private const int DevModeSize = 0xDC;
        private const int OffsetDeviceName = 0x00;
        private const int OffsetSpecVersion = 0x40;
        private const int OffsetDriverVersion = 0x42;
        private const int OffsetSize = 0x44;
        private const int OffsetFields = 0x48;
        private const int OffsetPositionX = 0x4C;
        private const int OffsetPositionY = 0x50;
        private const int OffsetDisplayOrientation = 0x54;
        private const int OffsetLogPixels = 0xA6;
        private const int OffsetBitsPerPel = 0xA8;
        private const int OffsetPelsWidth = 0xAC;
        private const int OffsetPelsHeight = 0xB0;
        private const int OffsetDisplayFlags = 0xB4;
        private const int OffsetDisplayFrequency = 0xB8;

        private const uint DmPosition = 0x00000020;
        private const uint DmDisplayOrientation = 0x00000080;
        private const uint DmLogPixels = 0x00020000;
        private const uint DmBitsPerPel = 0x00040000;
        private const uint DmPelsWidth = 0x00080000;
        private const uint DmPelsHeight = 0x00100000;
        private const uint DmDisplayFlags = 0x00200000;
        private const uint DmDisplayFrequency = 0x00400000;

        private const ushort SpecVersion = 0x0401;
        private const uint BitsPerPixel = 32;
        private const uint LogPixels = 96;
        private const string DeviceName = @"\\.\DISPLAY1";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ModeNumber = (uint)Instance.WinHelper.GetArg(1);
            ulong DevModePtr = Instance.WinHelper.GetArg(2);

            if (DevModePtr == 0 || !Instance.IsRegionMapped(DevModePtr, DevModeSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Only the current mode is advertised, so an enumerating caller stops after index 0.
            if (ModeNumber != EnumCurrentSettings && ModeNumber != EnumRegistrySettings && ModeNumber != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.TryGetPrimaryMonitorRect(out int Left, out int Top, out int Right, out int Bottom))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            Instance._emulator.WriteMemory(DevModePtr + OffsetDeviceName, DeviceName + "\0", Encoding.Unicode);
            Instance._emulator.WriteMemory(DevModePtr + OffsetSpecVersion, SpecVersion, 2);
            Instance._emulator.WriteMemory(DevModePtr + OffsetDriverVersion, SpecVersion, 2);
            Instance._emulator.WriteMemory(DevModePtr + OffsetSize, (ushort)DevModeSize, 2);
            Instance._emulator.WriteMemory(DevModePtr + OffsetFields,
                DmPosition | DmDisplayOrientation | DmLogPixels | DmBitsPerPel | DmPelsWidth | DmPelsHeight | DmDisplayFlags | DmDisplayFrequency, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetPositionX, (uint)Left, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetPositionY, (uint)Top, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetDisplayOrientation, 0u, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetLogPixels, (ushort)LogPixels, 2);
            Instance._emulator.WriteMemory(DevModePtr + OffsetBitsPerPel, BitsPerPixel, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetPelsWidth, (uint)(Right - Left), 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetPelsHeight, (uint)(Bottom - Top), 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetDisplayFlags, 0u, 4);
            Instance._emulator.WriteMemory(DevModePtr + OffsetDisplayFrequency, Instance.WinHelper.GetPrimaryDisplayFrequency(), 4);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
