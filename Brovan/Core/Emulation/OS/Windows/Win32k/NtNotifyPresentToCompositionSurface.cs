using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtNotifyPresentToCompositionSurface : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SurfaceHandle = Instance.WinHelper.GetArg(0);
            ulong TokenPtr = Instance.WinHelper.GetArg(1);

            Span<byte> Token = stackalloc byte[DxgkComposition.OffsetTokenBindingId + 8];
            if (TokenPtr != 0)
            {
                if (!Instance.ReadMemory(TokenPtr, Token))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (BinaryPrimitives.ReadUInt32LittleEndian(Token) != DxgkComposition.TokenModelRedirectedFlip)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(SurfaceHandle, AccessMask.CompositionSurfaceBind, out DxgkCompositionSurface Surface);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // The present that follows carries the same token, so nothing is kept here.
            return TokenPtr != 0 && Surface.GetBoundBuffer(BinaryPrimitives.ReadUInt64LittleEndian(Token.Slice(DxgkComposition.OffsetTokenBindingId))) != null
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
