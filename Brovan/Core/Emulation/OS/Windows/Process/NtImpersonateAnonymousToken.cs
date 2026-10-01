using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtImpersonateAnonymousToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ThreadHandle = Instance.WinHelper.GetArg(0);

            EmulatedThread Thread = WindowsThreadContext64.ResolveThread(Instance, ThreadHandle);

            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            State.ImpersonationTokenHandle = 0;
            State.ImpersonationToken = new WinToken
            {
                Type = TokenType.Impersonation,
                IsAnonymous = true,
                ImpersonationLevel = SecurityImpersonationLevel.SecurityImpersonation,
                OwningThreadId = Thread.ThreadId
            };

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
