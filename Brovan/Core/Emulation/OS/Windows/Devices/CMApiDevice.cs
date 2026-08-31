using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class CMApiDevice : IWinDevice
    {
        private const int ReplyHeaderSize = 20;
        private const int ReplyStatusOffset = 4;
        private const int ReplyLengthOffset = 8;

        private const uint IoctlGetDeviceInterfaceList = 0x470807;

        // Two WCHARs. CM_Get_Device_Interface_ListW refuses anything shorter and asks again.
        private const int EmptyInterfaceListBytes = 4;

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

            // cfgmgr32 reads "class not found" as an empty interface list, but only after its sizing call has
            // been told how much room the list needs. Sizing it below the terminator loops the caller forever.
            if (IOCTL == IoctlGetDeviceInterfaceList && Data.OutputLength < ReplyHeaderSize + EmptyInterfaceListBytes)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(ReplyStatusOffset, 4), (uint)NTSTATUS.STATUS_BUFFER_TOO_SMALL);
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(ReplyLengthOffset, 4), EmptyInterfaceListBytes);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(ReplyStatusOffset, 4), (uint)NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);
            }

            Data.OutputBuffer = Reply;
            Data.Information = ReplyHeaderSize;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
