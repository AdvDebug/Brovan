using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Windows only calls this from the server process, and a class carries its own procedure anyway.
    internal class NtUserInitializeClientPfnArrays : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Ansi = Instance.WinHelper.GetArg(0);
            ulong Unicode = Instance.WinHelper.GetArg(1);
            ulong Worker = Instance.WinHelper.GetArg(2);

            if (Unicode == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.PublishClientPfnArrays(Ansi, Unicode, Worker);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
