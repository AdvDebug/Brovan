namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class VolumeDevice : IWinDevice
    {
        public string DeviceName => WindowsStorageDeviceSupport.VolumeDeviceName;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = WindowsStorageDeviceSupport.VolumeDeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            return WindowsStorageDeviceSupport.HandleDeviceControl(Instance, Ioctl, ref Data, IsVolume: true);
        }
    }
}
