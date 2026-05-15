using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal class Uname : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong buf = Context.Arg0;
            Utsname uts = Helper.CreateUtsname(Instance.IsX64Guest);
            if (!StructSerializer.WriteStruct(Instance, buf, uts).Success)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }
            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}