using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreatePrivateNamespace : IWinSyscall
    {
        private const uint BoundaryHeaderSize = 0x10;
        private const uint MaxBoundarySize = 0x7FFF;
        private const uint EntryHeaderSize = 8;
        private const uint EntryName = 1;
        private const uint EntrySid = 2;
        private const uint EntryIntegrityLabel = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamespaceHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong BoundaryDescriptorPtr = Instance.WinHelper.GetArg(3);

            if (!Instance.IsMemoryRangeMapped(NamespaceHandlePtr, (ulong)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = CaptureBoundary(Instance, BoundaryDescriptorPtr, out uint BoundarySize, out byte[][] BoundaryEntries);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = VerifyCreatorAccess(Instance);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Name != null)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (Instance.WinHelper.FindPrivateNamespace(BoundarySize, BoundaryEntries) != null)
                return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;

            WinPrivateNamespace Namespace = new WinPrivateNamespace(BoundarySize, BoundaryEntries);
            Instance.WinHelper.PrivateNamespaces.Add(Namespace);

            return InsertHandle(Instance, NamespaceHandlePtr, Namespace, DesiredAccess, Attributes);
        }

        internal static NTSTATUS InsertHandle(BinaryEmulator Instance, ulong NamespaceHandlePtr, WinPrivateNamespace Namespace, AccessMask DesiredAccess, uint Attributes)
        {
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Namespace, DesiredAccess);
            if ((Attributes & WinSysHelper.OBJ_INHERIT) != 0)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ObjectHandleFlags.Inherit);

            if (!Instance.WinHelper.WritePointer(NamespaceHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT also checks the boundary SIDs against the token. Brovan grants every access check.
        internal static NTSTATUS VerifyCreatorAccess(BinaryEmulator Instance)
        {
            WinToken? Token = WinEmulatedThread.TryGetState(Instance.CurrentThread)?.ImpersonationToken;
            if (Token != null && Token.Type == TokenType.Impersonation && Token.ImpersonationLevel < SecurityImpersonationLevel.SecurityImpersonation)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // Same checks as ObpCaptureBoundaryDescriptor.
        internal static NTSTATUS CaptureBoundary(BinaryEmulator Instance, ulong Address, out uint TotalSize, out byte[][] Entries)
        {
            TotalSize = 0;
            Entries = Array.Empty<byte[]>();

            Span<byte> Header = stackalloc byte[(int)BoundaryHeaderSize];
            if (!Instance.ReadMemory(Address, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(8));
            if (Size < BoundaryHeaderSize || Size > MaxBoundarySize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Address & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Descriptor = Instance.WinHelper.Shared.GetSpan(Size);
            if (!Instance.ReadMemory(Address, Descriptor))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Descriptor) != 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Items = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(4));
            List<byte[]> Found = new List<byte[]>();
            bool HasNameEntry = false;
            bool HasLabelEntry = false;
            uint Offset = BoundaryHeaderSize;

            while (Offset + EntryHeaderSize < Size)
            {
                uint Type = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice((int)Offset));
                uint EntrySize = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice((int)Offset + 4));
                if (EntrySize < EntryHeaderSize || EntrySize > Size - Offset)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ReadOnlySpan<byte> Entry = Descriptor.Slice((int)Offset, (int)EntrySize);
                switch (Type)
                {
                    case EntryName:
                        if (HasNameEntry)
                            return NTSTATUS.STATUS_DUPLICATE_NAME;
                        HasNameEntry = true;
                        break;

                    case EntrySid:
                        if (!IsValidSid(Entry.Slice((int)EntryHeaderSize)))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;
                        break;

                    case EntryIntegrityLabel:
                        if (HasLabelEntry)
                            return NTSTATUS.STATUS_DUPLICATE_OBJECTID;
                        HasLabelEntry = true;
                        if (!IsValidSid(Entry.Slice((int)EntryHeaderSize)))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;
                        break;

                    default:
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                Found.Add(Entry.ToArray());
                Offset = (Offset + EntrySize + 7) & ~7u;
            }

            if (Items != (uint)Found.Count)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            for (int First = 0; First < Found.Count; First++)
            {
                for (int Second = First + 1; Second < Found.Count; Second++)
                {
                    if (Found[First].AsSpan().SequenceEqual(Found[Second]))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                }
            }

            TotalSize = Size;
            Entries = Found.ToArray();
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsValidSid(ReadOnlySpan<byte> Sid)
        {
            return Sid.Length >= 8 && Sid.Length >= 8 + (4 * Sid[1]) && (Sid[0] & 0xF) == 1 && Sid[1] <= 15;
        }
    }
}
