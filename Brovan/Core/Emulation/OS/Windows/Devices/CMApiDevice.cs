using System;
using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class CMApiDevice : IWinDevice
    {
        private const int ReplyHeaderSize = 20;
        private const int ReplyStatusOffset = 4;
        private const int ReplyLengthOffset = 8;

        private const uint IoctlGetDeviceInterfaceList = 0x470807;
        private const uint IoctlLocateDevNode = 0x470843;

        // Two WCHARs. CM_Get_Device_Interface_ListW refuses anything shorter and asks again.
        private const int EmptyInterfaceListBytes = 4;

        // CM_Locate_DevNodeW replies in eight bytes, NTSTATUS in the second half. Request size gives the pointer width.
        private const int LocateReplySize = 8;
        private const int LocateReplyStatusOffset = 4;
        private const uint LocateRequestSizeX64 = 40;
        private const uint LocateRequestSizeX86 = 28;
        private const int LocateDeviceIdOffsetX64 = 16;
        private const int LocateDeviceIdOffsetX86 = 12;

        // MAX_DEVICE_ID_LEN.
        private const int MaxDeviceIdLength = 200;

        private const string DeviceNodeKeyPath = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\";

        public string DeviceName => "\\Device\\DeviceApi\\CMApi";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (IOCTL == IoctlLocateDevNode)
                return LocateDevNode(ref Data, Instance);

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

        private static NTSTATUS LocateDevNode(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.OutputLength < LocateReplySize)
            {
                Data.OutputBuffer = Array.Empty<byte>();
                Data.Information = 0;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            NTSTATUS Result = DeviceNodeExists(Data.InputBuffer, Data.InputLength, Instance)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            byte[] Reply = new byte[LocateReplySize];
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(LocateReplyStatusOffset, 4), (uint)Result);
            Data.OutputBuffer = Reply;
            Data.Information = LocateReplySize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool DeviceNodeExists(byte[] Request, uint RequestLength, BinaryEmulator Instance)
        {
            if (Request == null || RequestLength < sizeof(uint) || Request.Length < sizeof(uint))
                return false;

            uint RequestSize = BinaryPrimitives.ReadUInt32LittleEndian(Request.AsSpan(0, sizeof(uint)));

            int DeviceIdOffset;
            int PointerSize;
            if (RequestSize == LocateRequestSizeX64)
            {
                DeviceIdOffset = LocateDeviceIdOffsetX64;
                PointerSize = 8;
            }
            else if (RequestSize == LocateRequestSizeX86)
            {
                DeviceIdOffset = LocateDeviceIdOffsetX86;
                PointerSize = 4;
            }
            else
            {
                return false;
            }

            int RequestEnd = DeviceIdOffset + PointerSize;
            if (RequestLength < RequestEnd || Request.Length < RequestEnd)
                return false;

            ulong DeviceIdPtr = PointerSize == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(Request.AsSpan(DeviceIdOffset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(Request.AsSpan(DeviceIdOffset, 4));

            string DeviceId = ReadDeviceId(Instance, DeviceIdPtr);
            if (string.IsNullOrEmpty(DeviceId))
                return false;

            return Instance.WinHelper.RegistryKeyExists(DeviceNodeKeyPath + DeviceId, out _, out _, out _);
        }

        private static string ReadDeviceId(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0)
                return null;

            StringBuilder Builder = new StringBuilder();

            for (int i = 0; i < MaxDeviceIdLength; i++)
            {
                ulong Slot = Address + (ulong)(i * sizeof(char));
                if (!Instance.IsRegionMapped(Slot, sizeof(char)))
                    return null;

                ushort Character = Instance._emulator.ReadMemoryUShort(Slot);
                if (Character == 0)
                    return Builder.ToString();

                Builder.Append((char)Character);
            }

            return null;
        }
    }
}
