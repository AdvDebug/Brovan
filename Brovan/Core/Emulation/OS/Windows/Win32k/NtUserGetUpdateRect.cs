using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetUpdateRect : IWinSyscall
    {
        private const int RectSize = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // The update area is one flag here, so a paint owed covers the whole client area.
            bool Pending = Window.PaintPending && Window.Visible;

            if (RectPtr != 0)
            {
                if (!Instance.IsRegionMapped(RectPtr, RectSize))
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Win32kHelper.GetClientRect(Instance, Window, out int Left, out int Top, out int Width, out int Height);

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RectSize).Slice(0, RectSize);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x00, 4), Pending ? Left : 0);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Pending ? Top : 0);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), Pending ? Left + Width : 0);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), Pending ? Top + Height : 0);

                if (!Instance.WriteMemory(RectPtr, Buffer))
                {
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(Pending);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
