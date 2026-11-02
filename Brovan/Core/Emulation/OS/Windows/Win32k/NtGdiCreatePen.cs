using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreatePen : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Style = (uint)Instance.WinHelper.GetArg(0);
            int Width = unchecked((int)Instance.WinHelper.GetArg(1));
            uint ColorRef = (uint)Instance.WinHelper.GetArg(2);

            if (Style > Win32kHelper.PenStyleInsideFrame || (Width == int.MinValue && Style != Win32kHelper.PenStyleNull))
            {
                // NT leaves LastError unchanged on x86.
                if (Instance.WinHelper.PointerSize == 8)
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong PenHandle = Win32kHelper.CreatePen(Instance, Style, Width, ColorRef);
            Instance.SetRawSyscallReturn(PenHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
