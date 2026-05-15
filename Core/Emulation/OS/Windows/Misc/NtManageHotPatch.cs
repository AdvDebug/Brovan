using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtManageHotPatch : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }
    }
}
