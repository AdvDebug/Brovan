using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Getpid : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            Helper.SetReturnValue(Instance, Context, Helper.PID);
        }
    }
}