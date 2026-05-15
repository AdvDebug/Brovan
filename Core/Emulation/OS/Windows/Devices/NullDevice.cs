using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NullDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\Null";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        public static bool IsNullDevicePath(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Normalized = Path.Trim().TrimEnd('\0').Replace('/', '\\');
            while (Normalized.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Normalized = Normalized.Substring(4);

            if (Normalized.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Normalized.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
            {
                Normalized = Normalized.Substring(4);
            }

            Normalized = Normalized.TrimEnd('\\');

            return Normalized.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NUL:", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NULL", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("\\Device\\Null", StringComparison.OrdinalIgnoreCase);
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;
            return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
        }
    }
}
