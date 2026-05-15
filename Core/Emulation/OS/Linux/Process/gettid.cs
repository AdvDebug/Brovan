using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Gettid : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if(Thread == null)
            {
                Instance.TriggerEventMessage("[-] We couldn't get the current thread for some reason?", LogFlags.Issues);
                Helper.SetReturnValue(Instance, Context, 9999);
                return;
            }
            Helper.SetReturnValue(Instance, Context, Thread.ThreadId);
        }
    }
}
