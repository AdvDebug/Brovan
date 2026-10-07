using System.Buffers.Binary;
using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong LinkHandle = Instance.WinHelper.GetArg(0);
            ulong LinkTargetPtr = Instance.WinHelper.GetArg(1);
            ulong ReturnedLengthPtr = Instance.WinHelper.GetArg(2);

            bool Is64 = Instance.WinHelper.PointerSize == 8;
            if (Is64 && (LinkTargetPtr & 1) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Raw = stackalloc byte[16];
            Span<byte> LinkTarget = Raw.Slice(0, Is64 ? 16 : 8);
            if (!Instance.ReadMemory(LinkTargetPtr, LinkTarget))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ushort OutMaximumLength = BinaryPrimitives.ReadUInt16LittleEndian(LinkTarget.Slice(2));
            ulong OutBuffer = Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(LinkTarget.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(LinkTarget.Slice(4));

            if (OutMaximumLength != 0 && !Instance.IsRegionMapped(OutBuffer, OutMaximumLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnedLengthPtr != 0 && !Instance.IsRegionMapped(ReturnedLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinSymbolicLink Link = Instance.WinHelper.HandleManager.GetObjectByHandle<WinSymbolicLink>(LinkHandle);
            if (Link == null)
                return Instance.WinHelper.IsObjectHandle(LinkHandle) ? NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH : NTSTATUS.STATUS_INVALID_HANDLE;

            if ((Instance.WinHelper.HandleManager.GetPermissionsByHandle(LinkHandle) & AccessMask.SymbolicLinkQuery) == 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            string Stored = Link.TargetBuffer;
            int MaximumBytes = Math.Min(Stored.Length * 2, 0xFFFE);
            int LengthBytes = Math.Min(Link.Target.Length * 2, MaximumBytes);

            // NT: ReturnedLength asks for the whole MaximumLength buffer.
            int CopyBytes = ReturnedLengthPtr != 0 ? MaximumBytes : LengthBytes;
            Span<byte> Value = stackalloc byte[4];
            if (CopyBytes > OutMaximumLength)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Value, (uint)MaximumBytes);
                if (ReturnedLengthPtr != 0 && !Instance.WriteMemory(ReturnedLengthPtr, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            if (CopyBytes != 0 && !Instance.WriteMemory(OutBuffer, MemoryMarshal.AsBytes(Stored.AsSpan(0, CopyBytes / 2))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt16LittleEndian(Value, (ushort)LengthBytes);
            if (!Instance.WriteMemory(LinkTargetPtr, Value.Slice(0, 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt32LittleEndian(Value, (uint)MaximumBytes);
            if (ReturnedLengthPtr != 0 && !Instance.WriteMemory(ReturnedLengthPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQuerySymbolicLinkObject: Handle=0x{LinkHandle:X}, Target=\"{Link.Target}\" (Len={LengthBytes}, Max={MaximumBytes}).", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
