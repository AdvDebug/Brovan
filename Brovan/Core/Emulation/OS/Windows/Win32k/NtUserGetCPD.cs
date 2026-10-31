using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetCPD : IWinSyscall
    {
        private const uint CpdWindow = 0x20;
        private const uint CpdDialog = 0x40;
        private const uint CpdClass = 0x80;
        private const uint CpdConversionBits = 0x03;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Options = (uint)Instance.WinHelper.GetArg(1);
            ulong Procedure = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            uint Kind = Options & ~CpdConversionBits;
            ulong Result = Kind == CpdWindow || Kind == CpdDialog || Kind == CpdClass
                ? Instance.WinHelper.GetCallProcHandle(Window, Procedure, (ushort)Options)
                : 0;

            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
