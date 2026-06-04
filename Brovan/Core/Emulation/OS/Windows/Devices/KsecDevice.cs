using System;
using System.Security.Cryptography;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class KsecDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\KsecDD";

        private const uint IOCTL_KSEC_RNG = 0x390004;
        private const uint IOCTL_KSEC_RNG_REKEY = 0x390008;
        private const uint IOCTL_KSEC_ENCRYPT_MEMORY = 0x39000E;
        private const uint IOCTL_KSEC_DECRYPT_MEMORY = 0x390012;
        private const uint IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROCESS = 0x390016;
        private const uint IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROCESS = 0x39001A;
        private const uint IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON = 0x39001E;
        private const uint IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON = 0x390022;
        private const uint IOCTL_KSEC_CLIENT_HANDSHAKE = 0x390400;

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
                case IOCTL_KSEC_RNG:
                case IOCTL_KSEC_RNG_REKEY:
                    if (Data.OutputBuffer == null || Data.OutputLength == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    uint Size = Math.Min(Data.OutputLength, (uint)Data.OutputBuffer.Length);
                    if (Size == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    RandomNumberGenerator.Fill(Data.OutputBuffer.AsSpan(0, (int)Size));
                    Data.Information = Size;
                    return NTSTATUS.STATUS_SUCCESS;

                case IOCTL_KSEC_ENCRYPT_MEMORY:
                case IOCTL_KSEC_DECRYPT_MEMORY:
                case IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROCESS:
                case IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROCESS:
                case IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON:
                case IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON:
                    {
                        byte[] Source = (Data.InputBuffer != null && Data.InputBuffer.Length > 0) ? Data.InputBuffer : Data.OutputBuffer;
                        if (Data.OutputBuffer != null && Source != null)
                        {
                            int Count = Math.Min(Data.OutputBuffer.Length, Source.Length);
                            if (!ReferenceEquals(Source, Data.OutputBuffer))
                                Array.Copy(Source, Data.OutputBuffer, Count);
                            Data.Information = (uint)Count;
                        }
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case IOCTL_KSEC_CLIENT_HANDSHAKE:
                    if (Data.OutputBuffer != null && Data.OutputLength > 0)
                    {
                        uint OutN = Math.Min(Data.OutputLength, (uint)Data.OutputBuffer.Length);
                        Data.OutputBuffer.AsSpan(0, (int)OutN).Clear();
                        Data.Information = OutN;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
        }
    }
}
