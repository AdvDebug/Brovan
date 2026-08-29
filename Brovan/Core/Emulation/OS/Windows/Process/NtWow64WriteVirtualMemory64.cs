using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64WriteVirtualMemory64 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddress = Instance.WinHelper.GetWideArg(1);
            ulong Buffer = Instance.WinHelper.GetArg(3);
            ulong NumberOfBytesToWrite = Instance.WinHelper.GetWideArg(4);
            ulong BytesWrittenPtr = Instance.WinHelper.GetArg(6);

            return NtWriteVirtualMemory.Write(Instance, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, BytesWrittenPtr, 8);
        }
    }
}
