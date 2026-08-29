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
            if (BaseAddress == 0 || Buffer == 0 || NumberOfBytesToWrite == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (NumberOfBytesToWrite > GuestSessionMailbox.MaxPayloadBytes)
                NumberOfBytesToWrite = GuestSessionMailbox.MaxPayloadBytes;

            if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToWrite))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            int Length = (int)NumberOfBytesToWrite;
            byte[] Rented = ArrayPool<byte>.Shared.Rent(Length);

            try
            {
                Span<byte> Payload = Rented.AsSpan(0, Length);
                if (!Instance.ReadMemory(Buffer, Payload, (uint)Length))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
                {
                    if (!Instance.WinHelper.HandleExists(ProcessHandle))
                        return NTSTATUS.STATUS_INVALID_HANDLE;

                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation | AccessMask.ProcessVMWrite);
                    if (Process == null)
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    if (Process.PID != Instance.WinHelper.PID)
                    {
                        if (Process.Remote == null)
                            return NTSTATUS.STATUS_INVALID_CID;

                        NTSTATUS RemoteStatus = Process.Remote.WriteMemory(BaseAddress, Payload, out ulong Written);
                        if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                            return RemoteStatus;

                        WriteCount(Instance, BytesWrittenPtr, Written, BytesWrittenSize);
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                }

                if (!Instance.IsRegionMapped(BaseAddress, NumberOfBytesToWrite))
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (!Instance._emulator.WriteMemory(BaseAddress, Payload))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }

            WriteCount(Instance, BytesWrittenPtr, NumberOfBytesToWrite, BytesWrittenSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteCount(BinaryEmulator Instance, ulong BytesWrittenPtr, ulong Count, uint BytesWrittenSize)
        {
            if (BytesWrittenPtr == 0)
                return;

            if (Instance.IsRegionMapped(BytesWrittenPtr, BytesWrittenSize))
                Instance._emulator.WriteMemory(BytesWrittenPtr, Count, BytesWrittenSize);
        }
    }
}
