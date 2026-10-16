using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Exit_group : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            EndProcess(Instance, Helper, Context.Arg0);
        }

        internal static void EndProcess(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong error_code)
        {
            if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                Instance.TriggerEventMessage($"[!] Process has been terminated with error code: {error_code}", LogFlags.Important);
            Helper.SetReturnValue(Instance, LinuxErrno.ESUCCESS);
            Utils.SetGuestExitCode((byte)error_code);
            Instance.StopEmulation();
        }
    }
}
