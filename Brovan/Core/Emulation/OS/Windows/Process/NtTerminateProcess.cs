using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong ExitCode = (uint)Instance.WinHelper.GetArg64(1);

                if (ExitCode == 0)
                {
                    int CurrentTID = Instance.CurrentThreadId;
                    foreach (EmulatedThread EmuThread in Instance.Threads.Values)
                    {
                        if (EmuThread.ThreadId != CurrentTID)
                        {
                            Instance.WinHelper.ClearTerminationState(EmuThread);
                            EmuThread.State = EmulatedThreadState.Terminated;
                            EmuThread.ExitCode = (int)ExitCode;
                        }
                    }
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (ProcessHandle == ulong.MaxValue)
                {
                    Instance.TriggerEventMessage($"[{(ExitCode == 0 ? '+' : '!')}] Process asked to be terminated with exit code 0x{ExitCode:X}", LogFlags.Important);
                    foreach (EmulatedThread ProcessThreads in Instance.Threads.Values)
                    {
                        if (ProcessThreads == null)
                            continue;

                        Instance.WinHelper.AbandonMutexesOwnedByThread(ProcessThreads.ThreadId);
                        Instance.WinHelper.ClearTerminationState(ProcessThreads);
                        ProcessThreads.State = EmulatedThreadState.Terminated;
                    }
                    Instance.StopEmulation();
                    return NTSTATUS.STATUS_SUCCESS;
                }
                else
                {
                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessTerminate);
                    if (Process == null)
                        return NTSTATUS.STATUS_ACCESS_DENIED;
                    if (Process.PID == Instance.WinHelper.PID)
                    {
                        Instance.TriggerEventMessage($"[{(ExitCode == 0 ? '+' : '!')}] Process asked to be terminated with exit code 0x{ExitCode:X}", LogFlags.Important);
                        Instance.StopEmulation();
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                }
            }
            return Instance.WinUnimplemented;
        }
    }
}