using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class CMApiDevice : IWinDevice
    {
        private const int ReplyHeaderSize = 20;
        private const int ReplyStatusOffset = 4;

        public string DeviceName => "\\Device\\DeviceApi\\CMApi";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.OutputLength < ReplyHeaderSize)
            {
                Data.OutputBuffer = Array.Empty<byte>();
                Data.Information = 0;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            byte[] Reply = new byte[ReplyHeaderSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(ReplyStatusOffset, 4), (uint)NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);

            Data.OutputBuffer = Reply;
            Data.Information = ReplyHeaderSize;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
