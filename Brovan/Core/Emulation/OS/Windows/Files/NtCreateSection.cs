using System;
using System.IO;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateSection : IWinSyscall
    {
        private const uint SEC_IMAGE = 0x01000000;
        private const uint SEC_RESERVE = 0x04000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            using GeneralHelper.IO.ProbeScope Scope = GeneralHelper.IO.BeginProbeScope();
            ulong SectionHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong MaximumSizePtr = Instance.WinHelper.GetArg(3);
            uint SectionPageProtection = (uint)Instance.WinHelper.GetArg(4);
            uint AllocationAttributes = (uint)Instance.WinHelper.GetArg(5);
            ulong FileHandle = Instance.WinHelper.GetArg(6);

            if (SectionHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SectionHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS NameStatus = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string FullName, out uint ObjectAttributes);
            if (NameStatus != NTSTATUS.STATUS_SUCCESS)
                return NameStatus;

            if (!Instance.WinHelper.TryLookupNameForCreate(FullName, ObjectAttributes, out WinSection? Existing, out NameStatus))
                return NameStatus;

            bool Inherit = (ObjectAttributes & WinSysHelper.OBJ_INHERIT) != 0;

            if (Existing != null)
            {
                WinHandle ExistingHandle = Instance.WinHelper.OpenObjectHandle(Existing, (AccessMask)(uint)DesiredAccess);
                if (Inherit)
                    Instance.WinHelper.HandleManager.SetHandleFlags(ExistingHandle.Handle, ObjectHandleFlags.Inherit);

                if (!Instance.WinHelper.WritePointer(SectionHandlePtr, ExistingHandle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtCreateSection: Name=\"{FullName}\", Handle=0x{ExistingHandle.Handle:X} (reused).", LogFlags.Syscall);

                return NameStatus;
            }

            bool IsImage = (AllocationAttributes & SEC_IMAGE) != 0;

            ulong Size = 0;
            if (MaximumSizePtr != 0)
            {
                if (!Instance.IsRegionMapped(MaximumSizePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Size = Instance._emulator.ReadMemoryULong(MaximumSizePtr);
            }

            string Path = null;
            WindowsFileStream Source = null;

            if (FileHandle != 0)
            {
                WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
                if (FileObj == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Path = FileObj.Path;

                if (!string.IsNullOrEmpty(Path))
                {
                    WindowsFileStream Stream = FileObj.GetFileStream();
                    if (Stream != null && Stream.ExistsAsFile && Stream.Length != 0)
                    {
                        Size = (ulong)Stream.Length;

                        if (!IsImage)
                            Source = Stream;
                    }
                }
            }

            if (Size == 0)
            {
                if (IsImage && FileHandle != 0)
                    return NTSTATUS.STATUS_FILE_INVALID;

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            bool IsReserveOnly = (AllocationAttributes & SEC_RESERVE) != 0 && FileHandle == 0;

            if (Size > uint.MaxValue && !IsReserveOnly)
                return NTSTATUS.STATUS_NO_MEMORY;

            IntPtr Storage = IntPtr.Zero;
            string SharedMemoryPath = null;
            if (!IsImage && !IsReserveOnly)
            {
                ulong StorageSize = Instance.AlignToPageSize(Size);

                // Cheaper than moving the pages and every view at the spawn.
                if (Inherit)
                    Storage = Instance.WinHelper.AllocateSessionStorage(StorageSize, out SharedMemoryPath);

                if (Storage == IntPtr.Zero)
                    Storage = Instance._emulator.AllocateSharedStorage(StorageSize);

                if (Storage == IntPtr.Zero)
                    return NTSTATUS.STATUS_COMMITMENT_LIMIT;

                if (Source != null && !CopyToStorage(Source, Storage, Size))
                {
                    Instance._emulator.ReleaseSharedStorage(Storage);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            WinHandle Handle = Instance.WinHelper.CreateSectionHandle(FullName, Size, SectionPageProtection, AllocationAttributes, Path, 0, (AccessMask)(uint)DesiredAccess, Storage, SharedMemoryPath);
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ObjectHandleFlags.Inherit);

            if (!Instance.WinHelper.WritePointer(SectionHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtCreateSection: Name=\"{FullName}\", Handle=0x{Handle.Handle:X}, Size=0x{Size:X}, Attr=0x{AllocationAttributes:X}, Prot=0x{SectionPageProtection:X}, File=0x{FileHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static unsafe bool CopyToStorage(WindowsFileStream Source, IntPtr Storage, ulong Size)
        {
            try
            {
                ulong Offset = 0;

                while (Offset < Size)
                {
                    int Want = (int)Math.Min(Size - Offset, (ulong)NtReadFile.IoChunkBytes);
                    int Read = Source.ReadAt((long)Offset, new Span<byte>((byte*)Storage + Offset, Want));
                    if (Read <= 0)
                        break;

                    Offset += (ulong)Read;
                }

                return true;
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException)
            {
                Utils.LogError($"[NtCreateSection] Reading \"{Source.GuestPath}\" into section storage failed: {Ex.Message}");
                return false;
            }
        }
    }
}