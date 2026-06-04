using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateSection : IWinSyscall
    {
        private const uint SEC_IMAGE = 0x01000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong SectionHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
            ulong MaximumSizePtr = Instance.WinHelper.GetArg64(3);
            uint SectionPageProtection = (uint)Instance.WinHelper.GetArg64(4);
            uint AllocationAttributes = (uint)Instance.WinHelper.GetArg64(5);
            ulong FileHandle = Instance.WinHelper.GetArg64(6);

            if (SectionHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SectionHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

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

            if (Size > uint.MaxValue)
                return NTSTATUS.STATUS_NO_MEMORY;

            ulong BackingAddress = 0;
            if (!IsImage)
            {
                BackingAddress = Instance.MapUniqueAddress((uint)Size, MemoryProtection.ReadWrite);
                if (BackingAddress == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (Data != null && Data.Length != 0)
                {
                    if (!Instance.WriteMemory(BackingAddress, Data))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            WinHandle Handle = Instance.WinHelper.CreateSectionHandle(null, Size, SectionPageProtection, AllocationAttributes, Path, BackingAddress, (AccessMask)(uint)DesiredAccess);

            if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.TriggerEventMessage($"[+] NtCreateSection: Handle=0x{Handle.Handle:X}, Size=0x{Size:X}, Attr=0x{AllocationAttributes:X}, Prot=0x{SectionPageProtection:X}, File=0x{FileHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}