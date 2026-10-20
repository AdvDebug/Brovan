using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetIoCompletion : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong IoCompletionHandle = Instance.WinHelper.GetArg(0);
            ulong KeyContext = Instance.WinHelper.GetArg(1);
            ulong ApcContext = Instance.WinHelper.GetArg(2);
            NTSTATUS IoStatus = (NTSTATUS)(int)(uint)Instance.WinHelper.GetArg(3);
            ulong IoStatusInformation = Instance.WinHelper.GetArg(4);

            NTSTATUS HandleStatus = Instance.WinHelper.ReferenceObjectByHandle(IoCompletionHandle, AccessMask.None, out WinIoCompletion Completion);
            if (HandleStatus != NTSTATUS.STATUS_SUCCESS)
                return HandleStatus;

            Instance.WinHelper.PostCompletion(Instance, IoCompletionHandle, Completion, new WinIoCompletionEntry
            {
                KeyContext = KeyContext,
                ApcContext = ApcContext,
                IoStatus = IoStatus,
                IoStatusInformation = IoStatusInformation
            });

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
