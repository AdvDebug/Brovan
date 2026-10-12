using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReadVirtualMemory : IWinSyscall
    {
        // MmCopyVirtualMemory copies nothing from a source chunk of this size it cannot lock whole.
        internal const uint CopyChunkBytes = 0xE000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Read(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), Instance.WinHelper.GetArg(3), Instance.WinHelper.GetArg(4), (uint)Instance.WinHelper.PointerSize);
        }

        internal static NTSTATUS Read(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, ulong Buffer, ulong NumberOfBytesToRead, ulong BytesReadPtr, uint BytesReadSize)
        {
            if (!IsValidRequest(Instance, BaseAddress, Buffer, NumberOfBytesToRead, BytesReadPtr, BytesReadSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT does not check the handle for an empty request.
            ulong Copied = 0;
            NTSTATUS Status = NumberOfBytesToRead == 0
                ? NTSTATUS.STATUS_SUCCESS
                : ReadProcess(Instance, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, out Copied);

            WriteCount(Instance, BytesReadPtr, Copied, BytesReadSize);
            return Status;
        }

        // NT rejects these before it looks at the handle (MiReadWriteVirtualMemory).
        internal static bool IsValidRequest(BinaryEmulator Instance, ulong BaseAddress, ulong Buffer, ulong Length, ulong CountPtr, uint CountSize)
        {
            const ulong HighestUserAddress = NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress;
            ulong LastOffset = Length == 0 ? 0 : Length - 1;
            if (BaseAddress + LastOffset < BaseAddress || BaseAddress + LastOffset > HighestUserAddress)
                return false;
            if (Buffer + LastOffset < Buffer || Buffer + LastOffset > HighestUserAddress)
                return false;
            return CountPtr == 0 || Instance.IsAccessible(CountPtr, CountSize, true);
        }

        private static NTSTATUS ReadProcess(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, ulong Buffer, ulong Length, out ulong Copied)
        {
            Copied = 0;

            // NT wants PROCESS_VM_READ for a read. PROCESS_VM_OPERATION belongs to write and protect.
            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMRead, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Process.PID == Instance.WinHelper.PID)
                return CopyLocal(Instance, BaseAddress, Buffer, Length, out Copied);
            if (Process.Remote == null)
                return NTSTATUS.STATUS_INVALID_CID;
            return ReadRemote(Instance, Process, BaseAddress, Buffer, Length, out Copied);
        }

        internal static NTSTATUS CopyLocal(BinaryEmulator Instance, ulong Source, ulong Destination, ulong Length, out ulong Copied)
        {
            Copied = 0;
            byte[] Rented = ArrayPool<byte>.Shared.Rent((int)Math.Min(Length, CopyChunkBytes));

            try
            {
                while (Copied < Length)
                {
                    uint Chunk = (uint)Math.Min(Length - Copied, CopyChunkBytes);
                    Span<byte> Data = Rented.AsSpan(0, (int)Chunk);

                    if (Instance.AccessibleLength(Source + Copied, Chunk, false) < Chunk || !Instance._emulator.ReadMemory(Source + Copied, Data))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    ulong Writable = Instance.AccessibleLength(Destination + Copied, Chunk, true);
                    if (Writable != 0 && !Instance._emulator.WriteMemory(Destination + Copied, Data.Slice(0, (int)Writable)))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    Copied += Writable;
                    if (Writable < Chunk)
                        return NTSTATUS.STATUS_PARTIAL_COPY;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReadRemote(BinaryEmulator Instance, WinProcess Process, ulong BaseAddress, ulong Buffer, ulong Length, out ulong Copied)
        {
            Copied = 0;
            byte[] Rented = ArrayPool<byte>.Shared.Rent((int)Math.Min(Length, CopyChunkBytes));

            try
            {
                while (Copied < Length)
                {
                    uint Chunk = (uint)Math.Min(Length - Copied, CopyChunkBytes);
                    NTSTATUS RemoteStatus = Process.Remote.ReadMemory(BaseAddress + Copied, Rented.AsSpan(0, (int)Chunk), out int RemoteLength);
                    if (RemoteStatus != NTSTATUS.STATUS_SUCCESS || RemoteLength < Chunk)
                        return Copied == 0 && RemoteStatus != NTSTATUS.STATUS_SUCCESS ? RemoteStatus : NTSTATUS.STATUS_PARTIAL_COPY;

                    ulong Writable = Instance.AccessibleLength(Buffer + Copied, Chunk, true);
                    if (Writable != 0 && !Instance._emulator.WriteMemory(Buffer + Copied, Rented, 0, (int)Writable))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    Copied += Writable;
                    if (Writable < Chunk)
                        return NTSTATUS.STATUS_PARTIAL_COPY;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Read 0x{Copied:X} bytes from process \"{Process.Name}\" at 0x{BaseAddress:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void WriteCount(BinaryEmulator Instance, ulong CountPtr, ulong Count, uint CountSize)
        {
            if (CountPtr != 0)
                Instance._emulator.WriteMemory(CountPtr, Count, CountSize);
        }
    }
}
