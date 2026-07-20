using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCallbackReturn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ResultAddress = Instance.WinHelper.GetArg(0);
            uint ResultLength = (uint)Instance.WinHelper.GetArg(1);
            NTSTATUS Status = (NTSTATUS)Instance.WinHelper.GetArg(2);

            bool Completed = Instance.WinHelper.CompleteUserCallback(ResultAddress, ResultLength);
            if (!Completed)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
