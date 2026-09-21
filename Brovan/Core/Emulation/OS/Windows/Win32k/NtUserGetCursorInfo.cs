using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetCursorInfo : IWinSyscall
    {
        private const int CursorInfo64Size = 0x18;
        private const int CursorInfo32Size = 0x14;
        private const uint CursorShowing = 0x0001;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong InfoPtr = Instance.WinHelper.GetArg(0);
            bool Wide = Instance.WinHelper.PointerSize == 8;
            int Size = Wide ? CursorInfo64Size : CursorInfo32Size;

            if (InfoPtr == 0 || !Instance.IsRegionMapped(InfoPtr, (ulong)Size))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.GetCursorPosition(Instance, out int X, out int Y);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Size);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Win32kHelper.IsCursorShowing(Instance) ? CursorShowing : 0);

            int PointOffset = Wide ? 0x10 : 0x0C;
            if (Wide)
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), Win32kHelper.GetCursorHandle(Instance));
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), (uint)Win32kHelper.GetCursorHandle(Instance));

            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(PointOffset, 4), X);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(PointOffset + 4, 4), Y);

            if (!Instance.WriteMemory(InfoPtr, Buffer))
            {
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
