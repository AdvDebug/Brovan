using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64ReadVirtualMemory64 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddress = Instance.WinHelper.GetWideArg(1);
            ulong Buffer = Instance.WinHelper.GetArg(3);
            ulong NumberOfBytesToRead = Instance.WinHelper.GetWideArg(4);
            ulong BytesReadPtr = Instance.WinHelper.GetArg(6);

            return NtReadVirtualMemory.Read(Instance, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, BytesReadPtr, 8);
        }
    }
}
