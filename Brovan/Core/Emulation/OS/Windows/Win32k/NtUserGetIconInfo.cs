using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetIconInfo : IWinSyscall
    {
        private const ushort ResourceTypeIcon = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);
            ulong IconInfoPtr = Instance.WinHelper.GetArg(1);
            ulong ModuleNamePtr = Instance.WinHelper.GetArg(2);
            ulong ResourceNamePtr = Instance.WinHelper.GetArg(3);
            ulong BppPtr = Instance.WinHelper.GetArg(4);
            bool Internal = (uint)Instance.WinHelper.GetArg(5) != 0;

            bool Wide = Instance.WinHelper.PointerSize == 8;
            int Size = Wide ? 0x20 : 0x14;

            if (IconInfoPtr == 0 || !Instance.IsRegionMapped(IconInfoPtr, (ulong)Size))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // The stock cursor is the host's shape, so it has no image.
            if (!Win32kHelper.TryGetCursorIcon(Instance, Handle, out Win32kHelper.Win32kCursorIcon Data))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_CURSOR_HANDLE);

            // A colour icon's mask is stored at twice its height. The top half is returned unless internal.
            int MaskRows = !Internal && Data.ColorBitmap != 0 && Win32kHelper.TryGetBitmap(Instance, Data.MaskBitmap, out Win32kBitmap Stored)
                ? Stored.Height / 2
                : 0;
            ulong Mask = Win32kHelper.CopyBitmap(Instance, Data.MaskBitmap, MaskRows);
            ulong Color = Data.ColorBitmap == 0 ? 0 : Win32kHelper.CopyBitmap(Instance, Data.ColorBitmap);
            if (Mask == 0 || (Data.ColorBitmap != 0 && Color == 0))
            {
                DeleteCopy(Instance, Mask);
                DeleteCopy(Instance, Color);
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            Span<byte> Info = stackalloc byte[0x20];
            Info.Clear();
            BinaryPrimitives.WriteInt32LittleEndian(Info.Slice(0x00, 4), Data.ResourceType == ResourceTypeIcon ? 1 : 0);
            BinaryPrimitives.WriteInt32LittleEndian(Info.Slice(0x04, 4), Data.HotspotX);
            BinaryPrimitives.WriteInt32LittleEndian(Info.Slice(0x08, 4), Data.HotspotY);
            if (Wide)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Info.Slice(0x10, 8), Mask);
                BinaryPrimitives.WriteUInt64LittleEndian(Info.Slice(0x18, 8), Color);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(0x0C, 4), (uint)Mask);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(0x10, 4), (uint)Color);
            }

            if (!Instance.WriteMemory(IconInfoPtr, Info.Slice(0, Size)))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            ClearNameLength(Instance, ModuleNamePtr);
            ClearNameLength(Instance, ResourceNamePtr);

            if (BppPtr != 0 && Instance.IsRegionMapped(BppPtr, 4))
                Instance._emulator.WriteMemory(BppPtr, Data.BitsPerPixel, 4);

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void ClearNameLength(BinaryEmulator Instance, ulong UnicodeString)
        {
            if (UnicodeString != 0 && Instance.IsRegionMapped(UnicodeString, 2))
                Instance._emulator.WriteMemory(UnicodeString, (ushort)0, 2);
        }

        private static void DeleteCopy(BinaryEmulator Instance, ulong Bitmap)
        {
            if (Bitmap != 0 && Win32kHelper.RemoveBitmap(Instance, Bitmap))
                Instance.WinHelper.FreeGdiHandle(Bitmap);
        }

        private static NTSTATUS Fail(BinaryEmulator Instance, uint Error)
        {
            Instance.SetLastWinError(Error);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
