using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWriteVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddress = Instance.WinHelper.GetArg(1);
            ulong Buffer = Instance.WinHelper.GetArg(2);
            ulong NumberOfBytesToWrite = Instance.WinHelper.GetArg(3);
            ulong BytesWrittenPtr = Instance.WinHelper.GetArg(4);

            if (BaseAddress == 0 || Buffer == 0 || NumberOfBytesToWrite == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (NumberOfBytesToWrite > GuestSessionRegistry.MaxPayloadBytes)
                NumberOfBytesToWrite = GuestSessionRegistry.MaxPayloadBytes;

            if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToWrite))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            byte[] Payload = Instance.ReadMemory(Buffer, (uint)NumberOfBytesToWrite);
            if (Payload.Length == 0)
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
                    NTSTATUS RemoteStatus = GuestSessionRegistry.SendRequest(
                        Process.PID,
                        GuestSessionRegistry.OpcodeWriteMemory,
                        BaseAddress,
                        0,
                        Payload,
                        Span<byte>.Empty,
                        out _,
                        out ulong Written);

                    if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                        return RemoteStatus;

                    WriteCount(Instance, BytesWrittenPtr, Written);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            if (!Instance.IsRegionMapped(BaseAddress, NumberOfBytesToWrite))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if (!Instance._emulator.WriteMemory(BaseAddress, Payload))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WriteCount(Instance, BytesWrittenPtr, (ulong)Payload.Length);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteCount(BinaryEmulator Instance, ulong BytesWrittenPtr, ulong Count)
        {
            if (BytesWrittenPtr == 0)
                return;

            int PointerSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;
            if (Instance.IsRegionMapped(BytesWrittenPtr, (ulong)PointerSize))
                Instance._emulator.WriteMemory(BytesWrittenPtr, Count, (uint)PointerSize);
        }
    }
}
