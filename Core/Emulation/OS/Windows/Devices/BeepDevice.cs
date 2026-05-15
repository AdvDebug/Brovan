using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class BeepDevice : IWinDevice
    {
        private const uint IOCTL_BEEP_SET = 0x00010000;
        private const uint BeepFrequencyMinimum = 0x25;
        private const uint BeepFrequencyMaximum = 0x7FFF;
        private const uint BeepSetParametersSize = 0x08;

        public string DeviceName => "\\Device\\Beep";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (IOCTL)
            {
                case IOCTL_BEEP_SET:
                    return SetBeep(ref Data, Instance);

                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
        }

        private static NTSTATUS SetBeep(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || Data.InputLength < BeepSetParametersSize || Data.InputBuffer.Length < BeepSetParametersSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Frequency = BinaryPrimitives.ReadUInt32LittleEndian(Data.InputBuffer.AsSpan(0, 4));
            uint Duration = BinaryPrimitives.ReadUInt32LittleEndian(Data.InputBuffer.AsSpan(4, 4));

            if (Frequency < BeepFrequencyMinimum || Frequency > BeepFrequencyMaximum)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;

            if (Duration != 0)
            {
                Instance.TriggerEventMessage($"[+] BeepDevice: requested {Frequency} Hz for {Duration} ms.", LogFlags.Syscall);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
