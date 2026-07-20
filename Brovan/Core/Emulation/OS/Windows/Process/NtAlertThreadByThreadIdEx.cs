using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertThreadByThreadIdEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint ThreadId = (uint)Instance.WinHelper.GetArg(0);
            return NtAlertThreadByThreadId.AlertThread(Instance, ThreadId);
        }
    }
}