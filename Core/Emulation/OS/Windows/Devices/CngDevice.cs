using System;
using System.Security.Cryptography;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class CngDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\CNG";
        private const uint IOCTL_CNG_GET_KERNEL_STATE = 0x00390008;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (IOCTL)
            {
                case IOCTL_CNG_GET_KERNEL_STATE:
                    if (Data.OutputBuffer == null || Data.OutputLength == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    uint Size = Math.Min(Data.OutputLength, (uint)Data.OutputBuffer.Length);
                    if (Size == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    RandomNumberGenerator.Fill(Data.OutputBuffer.AsSpan(0, (int)Size));
                    Data.Information = Size;
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
        }
    }
}
