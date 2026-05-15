using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDispatchMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong MessagePtr = Instance.WinHelper.GetArg64(0);
            if (!Win32kHelper.TryReadMessage(Instance, MessagePtr, out Win32kMessage Message))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Result = Win32kHelper.DispatchMessage(Instance, Message);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
