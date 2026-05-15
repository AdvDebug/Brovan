using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertThreadByThreadIdEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint ThreadId = (uint)Instance.WinHelper.GetArg64(0);
            return NtAlertThreadByThreadId.AlertThread(Instance, ThreadId);
        }
    }
}