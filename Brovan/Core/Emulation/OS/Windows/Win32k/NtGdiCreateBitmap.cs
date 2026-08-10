using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateBitmap : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            int Width = unchecked((int)Instance.WinHelper.GetArg(0));
            int Height = unchecked((int)Instance.WinHelper.GetArg(1));
            ushort Planes = (ushort)Instance.WinHelper.GetArg(2);
            ushort BitsPerPixel = (ushort)Instance.WinHelper.GetArg(3);
            ulong InitialBits = Instance.WinHelper.GetArg(4);

            ulong Handle = Win32kHelper.CreateBitmap(Instance, Width, Height, Planes, BitsPerPixel, false, false);
            if (Handle == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (InitialBits != 0)
            {
                Win32kHelper.TryGetBitmap(Instance, Handle, out Win32kBitmap Bitmap);
                if (!Win32kHelper.CopyBitmapBitsIn(Instance, Bitmap, InitialBits))
                {
                    Win32kHelper.RemoveBitmap(Instance, Handle);
                    Instance.WinHelper.FreeGdiHandle(Handle);
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
