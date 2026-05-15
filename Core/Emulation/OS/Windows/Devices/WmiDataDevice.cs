using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class WmiDataDevice : IWinDevice
    {
        private const uint FILE_DEVICE_UNKNOWN = 0x22;
        private const uint IOCTL_WMI_QUERY_ALL_DATA = 0x00224000;
        public string DeviceName => "\\Device\\WMIDataDevice";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.OutputBuffer != null && Data.OutputBuffer.Length != 0)
                Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);

            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;

            if (IOCTL == IOCTL_WMI_QUERY_ALL_DATA || GetDeviceType(IOCTL) == FILE_DEVICE_UNKNOWN)
                return NTSTATUS.STATUS_WMI_GUID_NOT_FOUND;

            return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
        }

        private static uint GetDeviceType(uint IOCTL)
        {
            return IOCTL >> 16;
        }
    }
}
