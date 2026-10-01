using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDeleteObjectApp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Handle = Instance.WinHelper.GetArg(0);
            bool Deleted = Win32kHelper.DeleteGdiObject(Instance, Handle);
            Instance.SetRawSyscallReturn(Deleted ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
