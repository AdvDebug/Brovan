using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NullDevice : IWinDevice
    {
        internal const string ObjectName = "\\Device\\Null";

        public string DeviceName => ObjectName;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = ObjectName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;
            return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
        }
    }
}
