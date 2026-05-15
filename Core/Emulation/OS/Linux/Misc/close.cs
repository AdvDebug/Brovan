using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal class Close : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            if(!Helper.DescriptorTable.ContainsHandle(fd))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            Helper.DescriptorTable.CloseHandle(fd);
            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
            return;
        }
    }
}