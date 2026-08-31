using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateSection : IWinSyscall
    {
        private const uint SEC_IMAGE = 0x01000000;
        private const uint SEC_RESERVE = 0x04000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

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

            string ShortName = null;
            string FullName = null;
            if (ObjectAttributesPtr != 0)
                Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out ShortName, out FullName, out _);

            if (!string.IsNullOrEmpty(FullName))
            {
                WinSection Existing = Instance.WinHelper.FindSectionByName(FullName, ShortName);
                if (Existing != null)
                {
                    WinHandle ExistingHandle = Instance.WinHelper.HandleManager.AddHandle(Existing, (AccessMask)(uint)DesiredAccess);
                    Instance.WinHelper.AddWinHandle(ExistingHandle);

                    if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)ExistingHandle.Handle))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[+] NtCreateSection: Name=\"{FullName}\", Handle=0x{ExistingHandle.Handle:X} (reused).", LogFlags.Syscall);

                    return NTSTATUS.STATUS_OBJECT_NAME_EXISTS;
                }
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
            byte[] Data = null;

            if (FileHandle != 0)
            {
                WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
                if (FileObj == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Path = FileObj.Path;

                if (!string.IsNullOrEmpty(Path))
                {
                    WindowsFileStream Stream = FileObj.GetFileStream();
                    if (Stream != null && Stream.ExistsAsFile)
                    {
                        if (IsImage)
                        {
                            if (Stream.Length != 0)
                                Size = (ulong)Stream.Length;
                        }
                        else if (Stream.TryReadAllBytes(out Data) && Data.Length != 0)
                        {
                            Size = (ulong)Data.Length;
                        }
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

            ulong BackingAddress = 0;
            if (!IsImage && !IsReserveOnly)
            {
                BackingAddress = Instance.MapWinUniqueAddress(Size, MemoryProtection.ReadWrite,
                    SpecialProtections.None, AllocationType.Commited);
                if (BackingAddress == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (Data != null && Data.Length != 0)
                {
                    if (!Instance.WriteMemory(BackingAddress, Data))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            WinHandle Handle = Instance.WinHelper.CreateSectionHandle(FullName, Size, SectionPageProtection, AllocationAttributes, Path, BackingAddress, (AccessMask)(uint)DesiredAccess);

            if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtCreateSection: Name=\"{FullName}\", Handle=0x{Handle.Handle:X}, Size=0x{Size:X}, Attr=0x{AllocationAttributes:X}, Prot=0x{SectionPageProtection:X}, File=0x{FileHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}