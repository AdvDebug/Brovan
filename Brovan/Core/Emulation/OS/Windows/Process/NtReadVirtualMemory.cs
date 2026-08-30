using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReadVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Read(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), Instance.WinHelper.GetArg(3), Instance.WinHelper.GetArg(4), (uint)Instance.WinHelper.PointerSize);
        }

        internal static NTSTATUS Read(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, ulong Buffer, ulong NumberOfBytesToRead, ulong BytesReadPtr, uint BytesReadSize)
        {
            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
                return ReadLocal(Instance, BaseAddress, Buffer, NumberOfBytesToRead, BytesReadPtr, BytesReadSize);

            if (!Instance.WinHelper.HandleExists(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            // NT wants PROCESS_VM_READ for a read. PROCESS_VM_OPERATION belongs to write and protect.
            WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMRead);
            if (Process == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Process.PID == Instance.WinHelper.PID)
                return ReadLocal(Instance, BaseAddress, Buffer, NumberOfBytesToRead, BytesReadPtr, BytesReadSize);

            if (Process.Remote == null)
                return NTSTATUS.STATUS_INVALID_CID;

            return ReadRemote(Instance, Process, BaseAddress, Buffer, NumberOfBytesToRead, BytesReadPtr, BytesReadSize);
        }

        private static NTSTATUS ReadLocal(BinaryEmulator Instance, ulong BaseAddress, ulong Buffer, ulong NumberOfBytesToRead, ulong BytesReadPtr, uint BytesReadSize)
        {
            if (BaseAddress == 0 || Buffer == 0 || NumberOfBytesToRead == 0 || NumberOfBytesToRead > int.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Instance.IsRegionFreed(BaseAddress, true))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if (!Instance.IsRegionMapped(BaseAddress, NumberOfBytesToRead))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if (Instance.IsRegionFreed(Buffer, true))
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!!] Tried reading from a freed buffer at 0x{Buffer:X} while using NtReadVirtualMemory.", LogFlags.Issues);
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
            }

            if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToRead))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            int Length = (int)NumberOfBytesToRead;
            byte[] Rented = ArrayPool<byte>.Shared.Rent(Length);

            try
            {
                Span<byte> Value = Rented.AsSpan(0, Length);
                if (!Instance.ReadMemory(BaseAddress, Value, (uint)Length))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WriteMemory(Buffer, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }

            if (BytesReadPtr != 0 && Instance.IsRegionMapped(BytesReadPtr, BytesReadSize))
                Instance._emulator.WriteMemory(BytesReadPtr, NumberOfBytesToRead, BytesReadSize);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReadRemote(BinaryEmulator Instance, WinProcess Process, ulong BaseAddress, ulong Buffer, ulong NumberOfBytesToRead, ulong BytesReadPtr, uint BytesReadSize)
        {
            if (BaseAddress == 0 || Buffer == 0 || NumberOfBytesToRead == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (NumberOfBytesToRead > GuestSessionMailbox.MaxPayloadBytes)
                NumberOfBytesToRead = GuestSessionMailbox.MaxPayloadBytes;

            if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToRead))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            byte[] Remote = ArrayPool<byte>.Shared.Rent((int)NumberOfBytesToRead);
            int RemoteLength;

            try
            {
                NTSTATUS RemoteStatus = Process.Remote.ReadMemory(BaseAddress, Remote.AsSpan(0, (int)NumberOfBytesToRead), out RemoteLength);
                if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                    return RemoteStatus;

                if (!Instance._emulator.WriteMemory(Buffer, Remote, 0, RemoteLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Remote);
            }

            if (BytesReadPtr != 0 && Instance.IsRegionMapped(BytesReadPtr, BytesReadSize))
                Instance._emulator.WriteMemory(BytesReadPtr, (ulong)RemoteLength, BytesReadSize);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Read 0x{RemoteLength:X} bytes from process \"{Process.Name}\" at 0x{BaseAddress:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
