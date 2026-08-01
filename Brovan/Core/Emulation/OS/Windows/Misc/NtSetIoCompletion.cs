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

            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(IoCompletionHandle);
            if (Completion == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Completion.Entries.Enqueue(new WinIoCompletionEntry
            {
                KeyContext = KeyContext,
                ApcContext = ApcContext,
                IoStatus = IoStatus,
                IoStatusInformation = IoStatusInformation
            });

            if (Instance.WakeWorkerFactoryWaitersForObject(IoCompletionHandle))
                Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
