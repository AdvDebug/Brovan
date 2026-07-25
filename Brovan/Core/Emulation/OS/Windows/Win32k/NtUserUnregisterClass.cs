using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUnregisterClass : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ClassNamePtr = Instance.WinHelper.GetArg(0);
            ulong InstanceHandle = Instance.WinHelper.GetArg(1);

            bool Read = Instance.WinHelper.TryReadUnicodeString(ClassNamePtr, out string ClassName, out _);

            Instance.SetRawSyscallReturn(Read && Instance.WinHelper.UnregisterWindowClass(InstanceHandle, ClassName) ? 1u : 0u);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
