using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWriteVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Write(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), Instance.WinHelper.GetArg(3), Instance.WinHelper.GetArg(4), (uint)Instance.WinHelper.PointerSize);
        }

        internal static NTSTATUS Write(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, ulong Buffer, ulong NumberOfBytesToWrite, ulong BytesWrittenPtr, uint BytesWrittenSize)
        {
            // NT does not check the handle for an empty request.
            if (NumberOfBytesToWrite == 0)
            {
                NtReadVirtualMemory.WriteCount(Instance, BytesWrittenPtr, 0, BytesWrittenSize);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (BaseAddress + NumberOfBytesToWrite < BaseAddress || Buffer + NumberOfBytesToWrite < Buffer)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMWrite, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong Copied;
            if (Process.PID == Instance.WinHelper.PID)
                Status = NtReadVirtualMemory.CopyLocal(Instance, Buffer, BaseAddress, NumberOfBytesToWrite, out Copied);
            else if (Process.Remote == null)
                return NTSTATUS.STATUS_INVALID_CID;
            else
                Status = WriteRemote(Instance, Process, BaseAddress, Buffer, NumberOfBytesToWrite, out Copied);

            NtReadVirtualMemory.WriteCount(Instance, BytesWrittenPtr, Copied, BytesWrittenSize);
            return Status;
        }

        private static NTSTATUS WriteRemote(BinaryEmulator Instance, WinProcess Process, ulong BaseAddress, ulong Buffer, ulong Length, out ulong Copied)
        {
            Copied = 0;
            byte[] Rented = ArrayPool<byte>.Shared.Rent((int)Math.Min(Length, NtReadVirtualMemory.CopyChunkBytes));

            try
            {
                while (Copied < Length)
                {
                    uint Chunk = (uint)Math.Min(Length - Copied, NtReadVirtualMemory.CopyChunkBytes);
                    Span<byte> Data = Rented.AsSpan(0, (int)Chunk);

                    if (NtReadVirtualMemory.AccessibleLength(Instance, Buffer + Copied, Chunk, false) < Chunk || !Instance._emulator.ReadMemory(Buffer + Copied, Data))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    NTSTATUS RemoteStatus = Process.Remote.WriteMemory(BaseAddress + Copied, Data, out ulong Written);
                    Copied += Math.Min(Written, Chunk);

                    if (RemoteStatus != NTSTATUS.STATUS_SUCCESS || Written < Chunk)
                        return Copied == 0 && RemoteStatus != NTSTATUS.STATUS_SUCCESS && RemoteStatus != NTSTATUS.STATUS_PARTIAL_COPY
                            ? RemoteStatus
                            : NTSTATUS.STATUS_PARTIAL_COPY;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
