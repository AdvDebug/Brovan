using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetAppClipBox : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            if (RectPtr == 0 || !Instance.IsRegionMapped(RectPtr, 16))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryGetDcExtent(Instance, Hdc, out int Width, out int Height))
            {
                Width = 0;
                Height = 0;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(16);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(8, 4), Width);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(12, 4), Height);

            if (!Instance.WriteMemory(RectPtr, Buffer.Slice(0, 16)))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)(Width > 0 && Height > 0 ? Win32kHelper.RegionSimple : Win32kHelper.RegionNull));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
