using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Exit_group : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong error_code = Context.Arg0;
            Instance.TriggerEventMessage($"[!] Process has been terminated with error code: {error_code}", LogFlags.Important);
            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
            Instance.StopEmulation();
        }
    }
}
