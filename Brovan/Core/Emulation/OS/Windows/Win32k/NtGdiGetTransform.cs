using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTransform : IWinSyscall
    {
        private const uint WorldToPage = 0x203;
        private const uint WorldToDevice = 0x204;
        private const uint PageToDevice = 0x304;
        private const uint DeviceToWorld = 0x402;
        private const int XformSize = 24;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Kind = Instance.WinHelper.GetArg32(1);
            ulong XformPtr = Instance.WinHelper.GetArg(2);

            if (!TryGetTranslation(Instance, Hdc, Kind, out float Dx, out float Dy))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Xform = stackalloc byte[XformSize];
            Xform.Clear();
            BinaryPrimitives.WriteSingleLittleEndian(Xform, 1f);
            BinaryPrimitives.WriteSingleLittleEndian(Xform.Slice(12), 1f);
            BinaryPrimitives.WriteSingleLittleEndian(Xform.Slice(16), Dx);
            BinaryPrimitives.WriteSingleLittleEndian(Xform.Slice(20), Dy);

            Instance.SetRawSyscallReturn(Instance.WriteMemory(XformPtr, Xform) ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryGetTranslation(BinaryEmulator Instance, ulong Hdc, uint Kind, out float Dx, out float Dy)
        {
            Dx = 0;
            Dy = 0;
            if ((Kind != WorldToPage && Kind != WorldToDevice && Kind != PageToDevice && Kind != DeviceToWorld)
                || !Win32kHelper.TryGetWorldTranslation(Instance, Hdc, out float WorldDx, out float WorldDy))
                return false;

            if (Kind == WorldToPage)
            {
                Dx = WorldDx;
                Dy = WorldDy;
                return true;
            }

            Instance.WinHelper.ReadDcPageOrigin(Hdc, out int PageX, out int PageY);
            if (Kind == PageToDevice)
            {
                Dx = PageX;
                Dy = PageY;
                return true;
            }

            Dx = Kind == DeviceToWorld ? 0 - (PageX + WorldDx) : PageX + WorldDx;
            Dy = Kind == DeviceToWorld ? 0 - (PageY + WorldDy) : PageY + WorldDy;
            return true;
        }
    }
}
