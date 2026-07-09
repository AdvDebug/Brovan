namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class CMNotifyDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\DeviceApi\\CMNotify";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
