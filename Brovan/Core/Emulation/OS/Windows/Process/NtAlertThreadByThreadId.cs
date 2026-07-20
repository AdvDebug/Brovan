using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertThreadByThreadId : IWinSyscall
    {
        internal static EmulatedThread GetTargetThread(BinaryEmulator Instance, uint ThreadId)
        {
            if (Instance == null)
                return null;

            if (Instance.CurrentThread != null && Instance.CurrentThread.ThreadId == ThreadId)
                return Instance.CurrentThread;

            return Instance.Threads.Values.FirstOrDefault(thread => thread != null && thread.ThreadId == ThreadId);
        }

        internal static NTSTATUS AlertThread(BinaryEmulator Instance, uint ThreadId)
        {
            EmulatedThread TargetThread = GetTargetThread(Instance, ThreadId);
            if (TargetThread == null || TargetThread.State == EmulatedThreadState.Terminated)
                return NTSTATUS.STATUS_INVALID_CID;

            WindowsThreadState State = WinEmulatedThread.GetState(TargetThread);
            State.AlertByThreadIdPending = true;

            if (TargetThread.WaitActive && State.AlertByThreadIdWaitActive && TargetThread.State == EmulatedThreadState.Waiting)
            {
                if (TargetThread.Context == null)
                    TargetThread.Context = new CpuContext();

                ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : TargetThread.Context.RIP);
                TargetThread.Context.RIP = ResumeRip;
                TargetThread.Context.RAX = (ulong)(uint)NTSTATUS.STATUS_ALERTED;

                State.AlertByThreadIdPending = false;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_ALERTED;
                State.WaitObjects = null;
                Instance.WinHelper.ClearWaitState(TargetThread, true);
                TargetThread.State = EmulatedThreadState.Ready;

                if (Instance.CurrentThread == TargetThread)
                {
                    Instance.WriteRegister(Registers.UC_X86_REG_RIP, TargetThread.Context.RIP);
                    Instance.WriteRegister(Registers.UC_X86_REG_RAX, TargetThread.Context.RAX);
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint ThreadId = (uint)Instance.WinHelper.GetArg(0);
            return AlertThread(Instance, ThreadId);
        }
    }
}
