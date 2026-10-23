using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtBindCompositionSurface : IWinSyscall
    {
        // The checks follow NtBindCompositionSurface, ValidateBufferAttributes, CFlipExBuffer::Create and
        // CBufferRealization::Initialize.
        private const int InfoSize64 = 0x520;
        private const int InfoSize32 = 0x48C;

        private const uint KindSingle = 1;
        private const uint KindSwapchain = 2;
        private const uint SwapchainKindMin = 2;
        private const uint SwapchainKindMax = 4;
        private const uint MaxRealizations = 31;
        private const int OffsetRealizations = 8;
        private const int RealizationStride = 32;

        private const int OffsetAlphaMode = 0x10;
        private const uint AlphaModeStraight = 2;
        private const uint MaxAlphaMode = 3;

        // NT accepts this one only behind a feature flag.
        private const uint FeatureSizePreference = 3;
        private const uint AttributeFlagRealizationKind = 0x10;
        private const uint MaxRealizationKind = 4;
        private const uint AttributeFlags32Mask = 0x3FFFF;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong BindingIdPtr = Instance.WinHelper.GetArg(5);
            if (BindingIdPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT writes the binding id whatever the status.
            NTSTATUS Status = TryBind(Instance, out ulong BindingId);
            Instance.WinHelper.WriteUInt64(BindingIdPtr, BindingId);
            return Status;
        }

        private static NTSTATUS TryBind(BinaryEmulator Instance, out ulong BindingId)
        {
            BindingId = 0;
            ulong SurfaceHandle = Instance.WinHelper.GetArg(0);
            bool KeepBuffers = (uint)Instance.WinHelper.GetArg(1) != 0;
            uint WindowArgument = (uint)Instance.WinHelper.GetArg(2);
            uint BufferFlag = (uint)Instance.WinHelper.GetArg(3);
            ulong InfoPtr = Instance.WinHelper.GetArg(4);
            bool Wide = Instance.WinHelper.PointerSize == 8;

            if (InfoPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Info = stackalloc byte[InfoSize64];
            Info = Info.Slice(0, Wide ? InfoSize64 : InfoSize32);
            if (!Instance.ReadMemory(InfoPtr, Info))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (WindowArgument != 0 || BufferFlag != 0)
                return Instance.WinUnimplemented;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(SurfaceHandle, AccessMask.CompositionSurfaceBind, out DxgkCompositionSurface Surface);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Surface.ActiveBuffer != null)
                return NTSTATUS.STATUS_ALREADY_INITIALIZED;

            uint Kind = BinaryPrimitives.ReadUInt32LittleEndian(Info);
            if (Kind == KindSingle)
                return Instance.WinUnimplemented;

            if (Kind != KindSwapchain)
                return Wide || Kind == 3 ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_NOT_IMPLEMENTED;

            // A 32-bit caller's layout is the one whNtBindCompositionSurface converts.
            int OffsetSizePreference = Wide ? 0x20 : 0x1C;
            int OffsetRealizationKind = Wide ? 0x54 : 0x50;
            int OffsetAttributeFlags = Wide ? 0x98 : 0x94;
            int OffsetSwapchain = Wide ? 0xA0 : 0x98;
            int OffsetWindow = Wide ? 0x488 : 0x480;
            int HandleSize = Wide ? 8 : 4;

            uint AlphaMode = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetAlphaMode));
            uint SizePreference = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetSizePreference));
            uint AttributeFlags = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetAttributeFlags)) & (Wide ? uint.MaxValue : AttributeFlags32Mask);
            if (AlphaMode > MaxAlphaMode || AlphaMode == AlphaModeStraight || SizePreference > FeatureSizePreference
                || ((AttributeFlags & AttributeFlagRealizationKind) != 0 && BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetRealizationKind)) - 1 >= MaxRealizationKind))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint SwapchainKind = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetSwapchain));
            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetSwapchain + 4));
            if (SwapchainKind - SwapchainKindMin > SwapchainKindMax - SwapchainKindMin || Count - 1 >= MaxRealizations)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (SizePreference == FeatureSizePreference || SwapchainKind != SwapchainKindMin)
                return Instance.WinUnimplemented;

            Status = Instance.WinHelper.ReferenceOptionalObjectByHandle(ReadHandle(Info, OffsetWindow + HandleSize, Wide), AccessMask.SemaphoreModifyState,
                out WinSemaphore Semaphore);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = Instance.WinHelper.ReferenceOptionalObjectByHandle(ReadHandle(Info, OffsetWindow + 2 * HandleSize, Wide), AccessMask.StandardRightsAll,
                out DxgkSharedSyncObject SharedFence);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            DxgkStorage[][] Realizations = new DxgkStorage[Count][];
            for (int Index = 0; Index < Realizations.Length; Index++)
            {
                ulong RealizationHandle = ReadHandle(Info, OffsetSwapchain + OffsetRealizations + Index * RealizationStride, Wide);
                if (RealizationHandle == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Status = Instance.WinHelper.ReferenceObjectByHandle(RealizationHandle, AccessMask.StandardRightsRequired, out DxgkSharedResource Shared);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                Realizations[Index] = Shared.Storage;
            }

            foreach (DxgkStorage[] Realization in Realizations)
                DxgkStorage.AddReferences(Realization);

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!KeepBuffers)
                Surface.ReleaseBuffers(Instance, Process);

            DxgkCompositionBuffer Buffer = new() { Realizations = Realizations, PresentLimit = Semaphore, FlipExFence = SharedFence?.Fence };
            BindingId = Surface.Bind(Buffer);

            ulong Window = ReadHandle(Info, OffsetWindow, Wide);
            if (Window == 0)
                return NTSTATUS.STATUS_SUCCESS;

            // NT: a refused window makes the surface lose every buffer.
            WinWindow Target = Instance.WinHelper.GetWindow(Window);
            if (Target == null)
            {
                Surface.ReleaseBuffers(Instance, Process);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            Buffer.Window = Target.Hwnd;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // A 32-bit handle is sign extended, as wow64win does.
        private static ulong ReadHandle(ReadOnlySpan<byte> Info, int Offset, bool Wide)
            => Wide ? BinaryPrimitives.ReadUInt64LittleEndian(Info.Slice(Offset)) : (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(Info.Slice(Offset));
    }
}
