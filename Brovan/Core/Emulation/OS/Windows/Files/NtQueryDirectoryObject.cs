using System.Buffers.Binary;
using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDirectoryObject : IWinSyscall
    {
        private const uint EntrySize64 = 32;
        private const uint EntrySize32 = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DirectoryHandle = Instance.WinHelper.GetArg(0);
            ulong BufferPtr = Instance.WinHelper.GetArg(1);
            uint Length = (uint)Instance.WinHelper.GetArg(2);
            bool ReturnSingleEntry = (byte)Instance.WinHelper.GetArg(3) != 0;
            bool RestartScan = (byte)Instance.WinHelper.GetArg(4) != 0;
            ulong ContextPtr = Instance.WinHelper.GetArg(5);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(6);

            return Instance.WinHelper.PointerSize == 8
                ? Query64(Instance, DirectoryHandle, BufferPtr, Length, ReturnSingleEntry, RestartScan, ContextPtr, ReturnLengthPtr)
                : Query32(Instance, DirectoryHandle, BufferPtr, Length, ReturnSingleEntry, RestartScan, ContextPtr, ReturnLengthPtr);
        }

        private static NTSTATUS Query64(BinaryEmulator Instance, ulong DirectoryHandle, ulong BufferPtr, uint Length, bool ReturnSingleEntry, bool RestartScan, ulong ContextPtr, ulong ReturnLengthPtr)
        {
            if (Length != 0)
            {
                if ((BufferPtr & 1) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                if (!Instance.IsRegionMapped(BufferPtr, Length))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Span<byte> Value = stackalloc byte[4];
            if (!Instance.ReadMemory(ContextPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnLengthPtr != 0 && !Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Start = RestartScan ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(Value);

            if (Length > uint.MaxValue - EntrySize64)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = GetDirectory(Instance, DirectoryHandle, out WinObjectDirectory Directory);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = SelectEntries(Directory, Start, Length, ReturnSingleEntry, out uint Count, out uint Next, out uint Required);

            Span<byte> Output = Instance.WinHelper.Shared.GetSpan(Required);
            Output.Clear();
            if ((int)Status >= 0)
            {
                ulong Strings = (Count + 1) * EntrySize64;
                for (uint Index = 0; Index < Count; Index++)
                {
                    string Name = Directory.GetEntry((int)(Start + Index), out WinSymbolicLink Link);
                    Span<byte> Entry = Output.Slice((int)(Index * EntrySize64), (int)EntrySize64);
                    Strings = WriteString64(Output, Entry, Strings, BufferPtr, Name);
                    Strings = WriteString64(Output, Entry.Slice(16), Strings, BufferPtr, NtQueryObject.GetTypeName(Link));
                }
            }

            int Copied = (int)Math.Min(Required, Length);
            if (Copied != 0 && !Instance.WriteMemory(BufferPtr, Output.Slice(0, Copied)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt32LittleEndian(Value, Required);
            if (ReturnLengthPtr != 0 && !Instance.WriteMemory(ReturnLengthPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((int)Status >= 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Value, Next);
                if (!Instance.WriteMemory(ContextPtr, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return Status;
        }

        // wow64 whNT32QueryDirectoryObject: the native buffer grows to fit every entry, and only those that fit 32-bit are copied.
        private static NTSTATUS Query32(BinaryEmulator Instance, ulong DirectoryHandle, ulong BufferPtr, uint Length, bool ReturnSingleEntry, bool RestartScan, ulong ContextPtr, ulong ReturnLengthPtr)
        {
            Span<byte> Value = stackalloc byte[4];
            if (!Instance.ReadMemory(ContextPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Start = RestartScan ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(Value);

            uint Count = 0;
            uint Next = 0;
            NTSTATUS Status = GetDirectory(Instance, DirectoryHandle, out WinObjectDirectory Directory);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = SelectEntries(Directory, Start, uint.MaxValue, ReturnSingleEntry, out Count, out Next, out _);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Value.Clear();
                if (ReturnLengthPtr != 0 && !Instance.WriteMemory(ReturnLengthPtr, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                return Status;
            }

            ulong Total = EntrySize32;
            ulong Written = EntrySize32;
            uint Fit = 0;
            for (uint Index = 0; Index < Count; Index++)
            {
                string Name = Directory.GetEntry((int)(Start + Index), out WinSymbolicLink Link);
                uint Size = (uint)(Name.Length + NtQueryObject.GetTypeName(Link).Length) * 2 + EntrySize32 + 4;
                Total += Size;
                if (Total <= Length)
                {
                    Fit++;
                    Written += Size;
                }
            }

            if (Total > Length)
            {
                if (Fit == 0)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Value, (uint)Total);
                    if (ReturnLengthPtr != 0 && !Instance.WriteMemory(ReturnLengthPtr, Value))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                }

                Status = NTSTATUS.STATUS_MORE_ENTRIES;
            }

            Span<byte> Output = Instance.WinHelper.Shared.GetSpan(Written);
            Output.Clear();
            ulong Strings = (Fit + 1) * EntrySize32;
            for (uint Index = 0; Index < Fit; Index++)
            {
                string Name = Directory.GetEntry((int)(Start + Index), out WinSymbolicLink Link);
                Span<byte> Entry = Output.Slice((int)(Index * EntrySize32), (int)EntrySize32);
                Strings = WriteString32(Output, Entry, Strings, BufferPtr, Name);
                Strings = WriteString32(Output, Entry.Slice(8), Strings, BufferPtr, NtQueryObject.GetTypeName(Link));
            }

            if (!Instance.WriteMemory(BufferPtr, Output))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt32LittleEndian(Value, Next + Fit - Count);
            if (!Instance.WriteMemory(ContextPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt32LittleEndian(Value, (uint)Written);
            if (ReturnLengthPtr != 0 && !Instance.WriteMemory(ReturnLengthPtr, Value))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }

        private static NTSTATUS GetDirectory(BinaryEmulator Instance, ulong DirectoryHandle, out WinObjectDirectory Directory)
        {
            Directory = Instance.WinHelper.HandleManager.GetObjectByHandle<WinObjectDirectory>(DirectoryHandle);
            if (Directory != null)
            {
                return (Instance.WinHelper.HandleManager.GetPermissionsByHandle(DirectoryHandle) & AccessMask.DirectoryQuery) != 0
                    ? NTSTATUS.STATUS_SUCCESS
                    : NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (Instance.WinHelper.GetKnownObjectDirectoryPath(DirectoryHandle) != null)
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[!] NtQueryDirectoryObject: the entries of {Instance.WinHelper.GetKnownObjectDirectoryPath(DirectoryHandle)} are not modelled.", LogFlags.Syscall);
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            return Instance.WinHelper.IsObjectHandle(DirectoryHandle) ? NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH : NTSTATUS.STATUS_INVALID_HANDLE;
        }

        // NT: the closing zero entry counts first. An entry that does not fit ends the scan.
        private static NTSTATUS SelectEntries(WinObjectDirectory Directory, uint Start, uint Capacity, bool ReturnSingleEntry, out uint Count, out uint Next, out uint Required)
        {
            Count = 0;
            Next = (uint)Directory.Count;
            Required = EntrySize64;

            if (Start >= (uint)Directory.Count)
                return NTSTATUS.STATUS_NO_MORE_ENTRIES;

            for (uint Index = Start; Index < (uint)Directory.Count; Index++)
            {
                string Name = Directory.GetEntry((int)Index, out WinSymbolicLink Link);
                ulong Size = Required + EntrySize64 + 4 + (ulong)(Name.Length + NtQueryObject.GetTypeName(Link).Length) * 2;
                if (Size > Capacity)
                {
                    Next = Index;
                    if (!ReturnSingleEntry)
                        return NTSTATUS.STATUS_MORE_ENTRIES;

                    Required = (uint)Size;
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                }

                Required = (uint)Size;
                Count++;
                if (ReturnSingleEntry)
                {
                    Next = Index + 1;
                    break;
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong WriteString64(Span<byte> Output, Span<byte> Field, ulong Offset, ulong BufferPtr, string Text)
        {
            ushort Bytes = (ushort)(Text.Length * 2);
            BinaryPrimitives.WriteUInt16LittleEndian(Field, Bytes);
            BinaryPrimitives.WriteUInt16LittleEndian(Field.Slice(2), (ushort)(Bytes + 2));
            BinaryPrimitives.WriteUInt64LittleEndian(Field.Slice(8), BufferPtr + Offset);
            MemoryMarshal.AsBytes(Text.AsSpan()).CopyTo(Output.Slice((int)Offset));
            return Offset + Bytes + 2u;
        }

        private static ulong WriteString32(Span<byte> Output, Span<byte> Field, ulong Offset, ulong BufferPtr, string Text)
        {
            ushort Bytes = (ushort)(Text.Length * 2);
            BinaryPrimitives.WriteUInt16LittleEndian(Field, Bytes);
            BinaryPrimitives.WriteUInt16LittleEndian(Field.Slice(2), (ushort)(Bytes + 2));
            BinaryPrimitives.WriteUInt32LittleEndian(Field.Slice(4), (uint)(BufferPtr + Offset));
            MemoryMarshal.AsBytes(Text.AsSpan()).CopyTo(Output.Slice((int)Offset));
            return Offset + Bytes + 2u;
        }
    }
}
