using System;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFlushVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private static NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg64(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(3);

            if (BaseAddressPtr == 0 || RegionSizePtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, (uint)Instance.WinHelper.PointerSize) || !Instance.IsRegionMapped(RegionSizePtr, (uint)Instance.WinHelper.PointerSize) || !Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
            ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr);

            NTSTATUS Status = FlushRange(Instance, BaseAddress, RegionSize, out ulong FlushedSize);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WritePointer(BaseAddressPtr, BaseAddress);
                Instance.WinHelper.WritePointer(RegionSizePtr, FlushedSize);
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, FlushedSize);
            return Status;
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint ProcessHandle = Instance.WinHelper.GetArg32(0);
            uint BaseAddressPtr = Instance.WinHelper.GetArg32(1);
            uint RegionSizePtr = Instance.WinHelper.GetArg32(2);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(3);

            if (BaseAddressPtr == 0 || RegionSizePtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, 4) || !Instance.IsRegionMapped(RegionSizePtr, 4) || !Instance.IsRegionMapped(IoStatusBlockPtr, 0x08))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            ulong BaseAddress = Instance.ReadMemoryUInt(BaseAddressPtr);
            ulong RegionSize = Instance.ReadMemoryUInt(RegionSizePtr);

            NTSTATUS Status = FlushRange(Instance, BaseAddress, RegionSize, out ulong FlushedSize);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Instance._emulator.WriteMemory(BaseAddressPtr, (uint)BaseAddress);
                Instance._emulator.WriteMemory(RegionSizePtr, (uint)FlushedSize);
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, (uint)Math.Min(FlushedSize, uint.MaxValue));
            return Status;
        }

        private static unsafe NTSTATUS FlushRange(BinaryEmulator Instance, ulong BaseAddress, ulong RegionSize, out ulong FlushedSize)
        {
            FlushedSize = 0;

            if (BaseAddress == 0 || !Instance.IsRegionMapped(BaseAddress, 1))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinSection Section = Instance.WinHelper.FindSectionAt(BaseAddress, out ulong SectionOffset, out ulong ViewRemaining);
            if (Section == null)
                return NTSTATUS.STATUS_SUCCESS;

            ulong Available = Section.Size > SectionOffset ? Math.Min(Section.Size - SectionOffset, ViewRemaining) : 0;
            if (Available == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            FlushedSize = RegionSize == 0 || RegionSize > Available ? Available : RegionSize;
            if (FlushedSize == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (string.IsNullOrEmpty(Section.Path) || Section.IsImage)
                return NTSTATUS.STATUS_SUCCESS;

            // A view's address can be unmapped and mapped again meanwhile; its storage stays until a release under KernelLock.
            if (Section.Storage == IntPtr.Zero)
            {
                Utils.LogError($"[NtFlushVirtualMemory] File section \"{Section.Path}\" has no storage to flush from.");
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            WindowsFileStream Stream = Section.GetFileStream(true);
            if (Stream == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            try
            {
                for (ulong Done = 0; Done < FlushedSize;)
                {
                    int ChunkSize = (int)Math.Min(FlushedSize - Done, (ulong)NtReadFile.IoChunkBytes);
                    ReadOnlySpan<byte> Chunk = new ReadOnlySpan<byte>((byte*)Section.Storage + SectionOffset + Done, ChunkSize);
                    Stream.WriteAt((long)(SectionOffset + Done), Chunk);
                    Done += (ulong)ChunkSize;
                }
            }
            catch
            {
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtFlushVirtualMemory: Base=0x{BaseAddress:X}, Size=0x{FlushedSize:X}, File=\"{Section.Path}\".", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
