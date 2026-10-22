using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIEscape : IWinSyscall
    {
        private const int OffsetDevice = 4;
        private const int OffsetType = 8;
        private const int OffsetPrivate = 16;

        private const uint EscapeDriverPrivate = 0;

        private const uint CodeRegisterDevicePage = 0;
        private const uint CodePreferredNode = 1;
        private const uint CodeVersion = 3;
        private const uint CodeRegisterContextPage = 7;

        private const int RegisterDevicePageSize = 56;
        private const int PreferredNodeSize = 16;
        private const int VersionSize = 8;
        private const int RegisterContextPageSize = 48;

        // NT keeps the 64-bit fields of the private data 64-bit for a 32-bit caller (WarpKMEscape).
        private const int OffsetPage = 16;
        private const int OffsetPageSize = 24;
        private const uint RequiredPageSize = 0x1000;
        private const uint WarpEscapeVersion = 2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetPrivateSize = OffsetPrivate + PointerSize;
            int OffsetContext = OffsetPrivateSize + 4;

            Span<byte> Arguments = stackalloc byte[32];
            Arguments = Arguments.Slice(0, OffsetContext + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkAdapter Adapter))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint DeviceHandle = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetDevice));
            uint ContextHandle = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetContext));
            DxgkDevice Device = null;
            DxgkContext Context = null;
            if ((DeviceHandle != 0 && (!Process.TryGet(DeviceHandle, out Device) || Device.Adapter != Adapter))
                || (ContextHandle != 0 && (!Process.TryGet(ContextHandle, out Context) || (Device != null && Context.Device != Device))))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Adapter.Kind != DxgkAdapterKind.BasicRender || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetType)) != EscapeDriverPrivate)
                return Instance.WinUnimplemented;

            ulong PrivatePtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetPrivate), 0, (uint)PointerSize);
            uint PrivateSize = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetPrivateSize));

            Span<byte> Private = stackalloc byte[RegisterDevicePageSize];
            if (PrivateSize < sizeof(uint) || !Instance.ReadMemory(PrivatePtr, Private.Slice(0, sizeof(uint))))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Code = BinaryPrimitives.ReadUInt32LittleEndian(Private);
            int Expected = Code switch
            {
                CodeRegisterDevicePage => RegisterDevicePageSize,
                CodePreferredNode => PreferredNodeSize,
                CodeVersion => VersionSize,
                CodeRegisterContextPage => RegisterContextPageSize,
                _ => 0,
            };

            if (Expected == 0)
                return IsUnmodeledCode(Code) ? Instance.WinUnimplemented : NTSTATUS.STATUS_NOT_SUPPORTED;

            Private = Private.Slice(0, Expected);
            if (PrivateSize != Expected || !Instance.ReadMemory(PrivatePtr + sizeof(uint), Private.Slice(sizeof(uint))))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Code switch
            {
                CodeRegisterDevicePage => RegisterDevicePage(Instance, Device, Private),
                CodePreferredNode => PreferredNode(Instance, Process, Private),
                CodeVersion => Version(Private),
                _ => RegisterContextPage(Instance, Context, Private),
            };

            if (Status == NTSTATUS.STATUS_SUCCESS && !Instance.WriteMemory(PrivatePtr, Private))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Status;
        }

        private static NTSTATUS RegisterDevicePage(BinaryEmulator Instance, DxgkDevice Device, Span<byte> Private)
        {
            if (Device == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            BinaryPrimitives.WriteUInt64LittleEndian(Private.Slice(28), 1);
            return ProbePage(Instance, Private);
        }

        // NT keeps node 0 for DWM and gives the other nodes to devices in turn (WARPKMADAPTER::QueryPreferredGpuNode).
        private static NTSTATUS PreferredNode(BinaryEmulator Instance, DxgkProcess Process, Span<byte> Private)
        {
            uint Nodes = Win32kDxgk.WarpNodeCount(Instance);
            BinaryPrimitives.WriteUInt32LittleEndian(Private.Slice(8), ++Process.PreferredNodeCounter % (Nodes - 1) + 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Private.Slice(12), 1);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Version(Span<byte> Private)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Private.Slice(4), WarpEscapeVersion);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The submit path never reads the page, only whether the context has its DMA buffer.
        private static NTSTATUS RegisterContextPage(BinaryEmulator Instance, DxgkContext Context, Span<byte> Private)
        {
            if (Context == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = ProbePage(Instance, Private);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Context.DmaBufferReady = true;
            BinaryPrimitives.WriteUInt32LittleEndian(Private.Slice(40), DxgkContext.DmaBufferSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ProbePage(BinaryEmulator Instance, ReadOnlySpan<byte> Private)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(Private.Slice(OffsetPageSize)) != RequiredPageSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WinHelper.ProbeForWrite(BinaryPrimitives.ReadUInt64LittleEndian(Private.Slice(OffsetPage)), RequiredPageSize);
        }

        private static bool IsUnmodeledCode(uint Code) => Code is 4 or 5 or 6 or 13 or 14 or 15 or 0xD0D0D001;
    }
}
