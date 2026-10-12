using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtContinue : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ContextPtr = Instance.WinHelper.GetArg(0);
            bool TestAlert = (byte)Instance.WinHelper.GetArg(1) != 0;

            return Continue(Instance, ContextPtr, TestAlert);
        }

        internal static NTSTATUS Continue(BinaryEmulator Instance, ulong ContextPtr, bool TestAlert)
        {
            NTSTATUS Status = WindowsThreadContext64.TryReadContextFlags(Instance, ContextPtr, out uint Flags, ProbeSize64: 0x200);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            EmulatedThread CurrentThread = Instance.CurrentThread;
            if (CurrentThread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadContext64.ApplyResumeContext(Instance, CurrentThread, ContextPtr, Flags);

            WindowsThreadState State = WinEmulatedThread.GetState(CurrentThread);
            State.DispatchException = false;
            State.ExceptionInformation = null;

            if (CurrentThread.State == EmulatedThreadState.Exception)
                CurrentThread.State = EmulatedThreadState.Running;

            if (TestAlert)
                Instance.WinHelper.DispatchNextUserApc(CurrentThread, true);

            WindowsThreadContext64.ResumeAtNewContext(Instance, CurrentThread);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
