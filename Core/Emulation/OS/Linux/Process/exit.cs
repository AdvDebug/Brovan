using System.Linq;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Exit : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong error_code = Context.Arg0;
            EmulatedThread CurrentThread = Instance.CurrentThread;
            if (CurrentThread == null)
            {
                Instance.TriggerEventMessage($"[!] Process has been terminated with error code: {error_code}", LogFlags.Important);
                Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                Instance.StopEmulation();
                return;
            }

            CurrentThread.ExitCode = (int)(uint)error_code;
            CurrentThread.State = EmulatedThreadState.Terminated;

            LinuxGuest.CleanupExitedThread(Instance, CurrentThread);

            bool HasOtherRunningThreads = Instance.Threads.Values.Any(t => t != null && t.ThreadId != CurrentThread.ThreadId && t.State != EmulatedThreadState.Terminated);
            Instance.TriggerEventMessage($"[{(error_code == 0 ? '+' : '!')}] Thread with ID {CurrentThread.ThreadId} has been terminated with error code: {error_code}", LogFlags.Important);
            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);

            Instance._emulator.WriteRegister(Instance.IPRegister, 0UL);
            if (HasOtherRunningThreads)
                Instance._emulator.StopEmulation();
            else
                Instance.StopEmulation();
        }
    }
}