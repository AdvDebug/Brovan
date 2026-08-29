namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64CsrBasepCreateProcess2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Message = Instance.WinHelper.GetArg(0);
            if (Message == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
