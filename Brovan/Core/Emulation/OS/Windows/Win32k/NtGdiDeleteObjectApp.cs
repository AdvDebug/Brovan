using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDeleteObjectApp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Handle = Instance.WinHelper.GetArg(0);
            if (Win32kHelper.IsStockObject(Instance, Handle))
            {
                Instance.SetRawSyscallReturn(1ul);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.RemovePenBrush(Instance, Handle);
            Win32kHelper.RemoveBitmap(Instance, Handle);
            Win32kHelper.RemoveFont(Instance, Handle);
            bool Deleted = Instance.WinHelper.FreeGdiHandle(Handle);
            Instance.SetRawSyscallReturn(Deleted ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
