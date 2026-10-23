using System.Buffers.Binary;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIPresent : IWinSyscall
    {
        private const uint FlagPresentCountValid = 0x1000;
        private const uint FlagRedirectedFlip = 0x8000;

        // NT refuses this flag and present regions with a redirected flip (DXGCONTEXT::CopyPresentArgs).
        private const uint FlagRefusedWithRedirectedFlip = 0x400000;

        private const int OffsetFlipToken = 16;
        private const int OffsetFenceValue = 0;
        private const int OffsetSurface = 8;
        private const int OffsetPresentLimitId = 32;
        private const int OffsetTokenPresentCount = 104;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            bool Wide = PointerSize == 8;

            // A 32-bit caller's layout is the one whNtGdiDdDDIPresent converts.
            int OffsetFlags = Wide ? 88 : 72;
            int OffsetBroadcastCount = Wide ? 92 : 76;
            int OffsetToken = Wide ? 360 : 344;
            int OffsetSwapchainIndex = Wide ? 28 : 24;
            int OffsetRegions = Wide ? 0x5A0 : 0x590;
            int OffsetOptimizeForComposition = Wide ? 0x5D0 : 0x5AC;

            Span<byte> Arguments = stackalloc byte[0x5A8];
            Arguments = Arguments.Slice(0, OffsetRegions + PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags));
            if ((Flags & FlagRedirectedFlip) == 0 || (Flags & ~(FlagPresentCountValid | FlagRedirectedFlip | FlagRefusedWithRedirectedFlip)) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetBroadcastCount)) != 0)
                return Instance.WinUnimplemented;

            if ((Flags & FlagRefusedWithRedirectedFlip) != 0 || WinSysHelper.ReadPointerField(Arguments.Slice(OffsetRegions), 0, (uint)PointerSize) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Token = Arguments.Slice(OffsetToken);
            if (BinaryPrimitives.ReadUInt32LittleEndian(Token) != DxgkComposition.TokenModelRedirectedFlip)
                return Instance.WinUnimplemented;

            Span<byte> Flip = Token.Slice(OffsetFlipToken);
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(BinaryPrimitives.ReadUInt64LittleEndian(Flip.Slice(OffsetSurface)),
                AccessMask.CompositionSurfaceBind, out DxgkCompositionSurface Surface);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT takes the buffer from the binding, so a source allocation or window that does not match it is not refused.
            DxgkCompositionBuffer Buffer = Surface.GetBoundBuffer(BinaryPrimitives.ReadUInt64LittleEndian(Token.Slice(DxgkComposition.OffsetTokenBindingId)));
            if (Buffer == null)
                return NTSTATUS.STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND;

            if (Buffer.Window == 0)
                return Instance.WinUnimplemented;

            ulong FenceValue = BinaryPrimitives.ReadUInt64LittleEndian(Flip.Slice(OffsetFenceValue));
            int PresentLimitReleases = BinaryPrimitives.ReadUInt64LittleEndian(Flip.Slice(OffsetPresentLimitId)) != 0 ? 1 : 0;

            // NT completes the token as skipped when the bound window is gone.
            if (Instance.WinHelper.GetWindow(Buffer.Window) == null)
            {
                Buffer.Skip(Instance, FenceValue, PresentLimitReleases);
                return NTSTATUS.STATUS_GRAPHICS_PRESENT_INVALID_WINDOW;
            }

            uint Index = BinaryPrimitives.ReadUInt32LittleEndian(Flip.Slice(OffsetSwapchainIndex));
            if (Index < Buffer.Realizations.Length && Buffer.Realizations[Index].Length == 1 && !DxgkComposition.IsPresentableFormat(Buffer.Realizations[Index][0].Format))
            {
                Utils.LogError($"[-] dxgk: a present of DXGI format {Buffer.Realizations[Index][0].Format} cannot be shown.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            DxgkPresentPacket Present = new()
            {
                Buffer = Buffer,
                Index = Index,
                FenceValue = FenceValue,
                PresentCount = BinaryPrimitives.ReadUInt32LittleEndian(Flip.Slice(OffsetTokenPresentCount)),
                PresentLimitReleases = PresentLimitReleases,
            };

            if (!Process.Gpu.TryEnqueue(Instance, Context, Present))
                return NTSTATUS.STATUS_NO_MEMORY;

            Instance.WinHelper.WriteByte(ArgumentsPtr + (ulong)OffsetOptimizeForComposition, 1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
