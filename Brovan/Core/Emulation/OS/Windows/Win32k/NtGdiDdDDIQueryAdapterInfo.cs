using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIQueryAdapterInfo : IWinSyscall
    {
        private const uint UmDriverPrivate = 0;
        private const uint UmDriverName = 1;
        private const uint UmOpenGlInfo = 2;
        private const uint GetSegmentSize = 3;
        private const uint CheckDriverUpdateStatus = 11;
        private const uint DriverVersion = 13;
        private const uint AdapterType = 15;
        private const uint Wddm12Caps = 17;
        private const uint UmdDriverVersion = 18;
        private const uint Wddm13Caps = 22;
        private const uint Wddm20Caps = 24;
        private const uint NodeMetadata = 25;
        private const uint Xbox = 27;
        private const uint PhysicalAdapterCount = 30;
        private const uint PhysicalAdapterDeviceIds = 31;
        private const uint QueryRegistry = 48;
        private const uint DriverVersionRender = 56;
        private const uint AdapterTypeRender = 57;
        private const uint AdapterUniqueGuid = 60;
        private const uint DriverDescriptionRender = 66;
        private const uint ParavirtualizationRender = 68;
        private const uint CrossAdapterResourceSupport = 76;
        private const uint Wddm30Caps = 77;

        private const int MaxPathCharacters = 260;
        private const int UmdFileNameInfoSize = 4 + MaxPathCharacters * 2;
        private const uint UmdVersionCount = 4;
        private const int OpenGlInfoSize = 0x210;
        private const int OffsetOpenGlVersion = MaxPathCharacters * 2;
        private const int OffsetOpenGlFlags = OffsetOpenGlVersion + 4;
        private const int SegmentSizeInfoSize = 24;
        private const int Wddm12CapsSize = 12;
        private const int NodeMetadataSize = 78;
        private const int QueryDeviceIdsSize = 28;
        private const int UniqueGuidSize = 80;

        private const int QueryRegistryInfoSize = 552;
        private const int OffsetRegistryFlags = 4;
        private const int OffsetRegistryValueName = 8;
        private const int OffsetRegistryValueType = 528;
        private const int OffsetRegistryPhysicalAdapter = 532;
        private const int OffsetRegistryOutputSize = 536;
        private const int OffsetRegistryOutput = 544;
        private const uint RegistryAdapterKey = 1;
        private const uint RegistryDriverStorePath = 2;
        private const uint RegistryDriverImagePath = 3;
        private const uint RegistryTranslatePath = 1;
        private const uint RegistryKnownFlags = 3;
        private const uint RegistryStatusSuccess = 0;
        private const uint RegistryStatusBufferOverflow = 1;
        private const uint RegistryTranslatePathSlack = 16;
        private const int DriverDescriptionSize = 8192;

        private const uint WarpPrivateVersion = 2;
        private const uint WarpWddmVersion = 0x3200;
        private const uint WarpPrivateFlags = 1;
        private const string WarpUmdName = "d3d10warp.dll";
        private const uint WarpEngineType3D = 1;
        private const string NodeNamePrefix = "3DNode";
        private const uint WarpWddm12Caps = 500;
        private const uint WarpWddm12Flags = 0x34;
        private const uint WarpWddm13Caps = 0x20;
        private const uint WarpWddm20Caps = 5;
        private const uint WarpCrossAdapterSupport = 2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetSize = 8 + PointerSize;
            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, OffsetSize + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Handle = BinaryPrimitives.ReadUInt32LittleEndian(Arguments);
            uint Type = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(4));
            ulong DataPtr = WinSysHelper.ReadPointerField(Arguments.Slice(8), 0, (uint)PointerSize);
            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetSize));

            if (!Instance.WinHelper.DxgkProcess.TryGet(Handle, out DxgkAdapter Adapter) || DataPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Type == QueryRegistry)
                return QueryDriverRegistry(Instance, Adapter, DataPtr, Size);

            if (Size == 0 || Size > DriverDescriptionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(DataPtr, Size);
            if (Data.IsEmpty)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Answer(Instance, Adapter, Type, Data, out int Written);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Instance.WriteMemory(DataPtr, Data.Slice(0, Written)) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static NTSTATUS Answer(BinaryEmulator Instance, DxgkAdapter Adapter, uint Type, Span<byte> Data, out int Written)
        {
            bool Render = Adapter.Kind == DxgkAdapterKind.BasicRender;
            Written = Data.Length;

            switch (Type)
            {
                case UmDriverPrivate when Render && Data.Length >= 8:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, WarpPrivateVersion);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), WarpWddmVersion);
                    if (Data.Length >= 12)
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(8), WarpPrivateFlags);
                    Written = Math.Min(Data.Length, 12);
                    return NTSTATUS.STATUS_SUCCESS;

                case UmOpenGlInfo when Data.Length == OpenGlInfoSize:
                    return WriteOpenGlInfo(Instance, Adapter, Data);

                case UmDriverName when Render && Data.Length == UmdFileNameInfoSize:
                    if (BinaryPrimitives.ReadUInt32LittleEndian(Data) >= UmdVersionCount)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    WriteString(Data.Slice(4), WarpUmdName);
                    return NTSTATUS.STATUS_SUCCESS;

                case GetSegmentSize when Data.Length == SegmentSizeInfoSize:
                    BinaryPrimitives.WriteUInt64LittleEndian(Data, Adapter.DedicatedVideoMemory);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(8), 0);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(16), Win32kDxgk.SharedSegmentSize);
                    return NTSTATUS.STATUS_SUCCESS;

                case CheckDriverUpdateStatus or Xbox or Wddm30Caps when Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, 0);
                    return NTSTATUS.STATUS_SUCCESS;

                case DriverVersion when Data.Length == 4:
                case DriverVersionRender when Render && Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Win32kDxgk.WddmVersion);
                    return NTSTATUS.STATUS_SUCCESS;

                case AdapterType when Data.Length == 4:
                case AdapterTypeRender when Render && Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Adapter.AdapterType);
                    return NTSTATUS.STATUS_SUCCESS;

                case Wddm12Caps when Data.Length == Wddm12CapsSize:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Render ? WarpWddm12Caps : 0);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), Render ? WarpWddm12Caps : 0);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(8), Render ? WarpWddm12Flags : 0);
                    return NTSTATUS.STATUS_SUCCESS;

                case UmdDriverVersion when Render && Data.Length == 8:
                    if (!TryReadDriverVersion(Instance.WinHelper, Adapter, out ulong Version))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    BinaryPrimitives.WriteUInt64LittleEndian(Data, Version);
                    return NTSTATUS.STATUS_SUCCESS;

                case Wddm13Caps when Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Render ? WarpWddm13Caps : 0);
                    return NTSTATUS.STATUS_SUCCESS;

                case Wddm20Caps when Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Render ? WarpWddm20Caps : 0);
                    return NTSTATUS.STATUS_SUCCESS;

                case NodeMetadata when Render && Data.Length == NodeMetadataSize:
                    return WriteNodeMetadata(Instance, Data);

                case PhysicalAdapterCount when Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, 1);
                    return NTSTATUS.STATUS_SUCCESS;

                case PhysicalAdapterDeviceIds when Data.Length == QueryDeviceIdsSize:
                    if (BinaryPrimitives.ReadUInt32LittleEndian(Data) != 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    Data.Slice(4).Clear();
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), Adapter.VendorId);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(8), Adapter.DeviceId);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(24), Adapter.BusType);
                    return NTSTATUS.STATUS_SUCCESS;

                case AdapterUniqueGuid when Data.Length == UniqueGuidSize:
                    WriteString(Data, Adapter.UniqueId);
                    return NTSTATUS.STATUS_SUCCESS;

                case DriverDescriptionRender when Render && Data.Length == DriverDescriptionSize:
                    WriteString(Data, Adapter.Description);
                    return NTSTATUS.STATUS_SUCCESS;

                case ParavirtualizationRender when Render && Data.Length == 1:
                    Data[0] = 0;
                    return NTSTATUS.STATUS_SUCCESS;

                case CrossAdapterResourceSupport when Render && Data.Length == 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, WarpCrossAdapterSupport);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // D3DKMT_NODEMETADATA is packed, so IoMmuSupported is byte 77.
        private static NTSTATUS WriteNodeMetadata(BinaryEmulator Instance, Span<byte> Data)
        {
            uint Node = BinaryPrimitives.ReadUInt32LittleEndian(Data);
            if (Node >= Win32kDxgk.WarpNodeCount(Instance))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<char> Name = stackalloc char[NodeNamePrefix.Length + 2];
            NodeNamePrefix.CopyTo(Name);
            Node.TryFormat(Name.Slice(NodeNamePrefix.Length), out int Digits, "X2");

            Data.Slice(4).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), WarpEngineType3D);
            Encoding.Unicode.GetBytes(Name.Slice(0, NodeNamePrefix.Length + Digits), Data.Slice(8, 64));
            Data[77] = 1;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS WriteOpenGlInfo(BinaryEmulator Instance, DxgkAdapter Adapter, Span<byte> Data)
        {
            WinSysHelper WinHelper = Instance.WinHelper;
            string Suffix = WinHelper.PointerSize == 4 ? Win32kDxgk.WowSuffix : string.Empty;
            string Name = string.Empty;
            uint Version = 0;
            uint Flags = 0;
            WinRegKey Key = Win32kDxgk.TryGetDriverKey(WinHelper, Adapter, out string DriverKey) ? WinHelper.ResolveRegistryKey(DriverKey) : null;
            if (Key != null)
            {
                if (WinHelper.TryGetRegistryValue(Key, Win32kDxgk.OpenGlDriverNameValue + Suffix, out ValueNode Value)
                    && (Value.Type == WinSysHelper.RegSz || Value.Type == WinSysHelper.RegMultiSz))
                    Name = WinSysHelper.DecodeRegistryString(Value.Data);
                Version = ReadDword(WinHelper, Key, Win32kDxgk.OpenGlVersionValue + Suffix);
                Flags = ReadDword(WinHelper, Key, Win32kDxgk.OpenGlFlagsValue + Suffix);
            }

            if (Name.Length >= MaxPathCharacters)
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;

            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetOpenGlVersion), Version);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetOpenGlFlags), Flags);
            Data.Slice(0, OffsetOpenGlVersion).Clear();
            Encoding.Unicode.GetBytes(Name, Data);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint ReadDword(WinSysHelper WinHelper, WinRegKey Key, string Name)
        {
            return WinHelper.TryGetRegistryValue(Key, Name, out ValueNode Value) && Value.Type == WinSysHelper.RegDword
                && Value.Data != null && Value.Data.Length >= 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(Value.Data)
                : 0;
        }

        // NT reports buffer overflow in the record (DxgkpQueryRegistry).
        private static NTSTATUS QueryDriverRegistry(BinaryEmulator Instance, DxgkAdapter Adapter, ulong DataPtr, uint Size)
        {
            if (Size < QueryRegistryInfoSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Info = stackalloc byte[QueryRegistryInfoSize];
            if (!Instance.ReadMemory(DataPtr, Info))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint QueryType = BinaryPrimitives.ReadUInt32LittleEndian(Info);
            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetRegistryFlags));
            uint ValueType = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetRegistryValueType));
            uint PhysicalAdapter = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetRegistryPhysicalAdapter));
            if (Flags > RegistryKnownFlags || PhysicalAdapter != 0 || QueryType > RegistryDriverImagePath)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (QueryType >= RegistryDriverStorePath && (ValueType != 0 || (Flags & RegistryTranslatePath) != 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (QueryType != RegistryAdapterKey || !Win32kDxgk.TryGetDriverKey(Instance.WinHelper, Adapter, out string Key))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            // NT limits the value name to 259 characters.
            ReadOnlySpan<char> Name = MemoryMarshal.Cast<byte, char>(Info.Slice(OffsetRegistryValueName, (MaxPathCharacters - 1) * 2));
            int End = Name.IndexOf('\0');
            if (End >= 0)
                Name = Name.Slice(0, End);
            int Split = Name.LastIndexOf('\\');
            if (Split > 0)
            {
                Key = string.Concat(Key, "\\", Name.Slice(0, Split));
                Name = Name.Slice(Split + 1);
            }

            if (!Instance.WinHelper.TryReadRegistryValue(Key, Name.ToString(), out ValueNode Value))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            if ((uint)Value.Type != ValueType)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Data = Value.Data ?? Array.Empty<byte>();
            if ((uint)Data.Length > Size - OffsetRegistryOutput)
            {
                uint Needed = (uint)Data.Length + ((Flags & RegistryTranslatePath) != 0 ? RegistryTranslatePathSlack : 0);
                return WriteRegistryResult(Instance, DataPtr, Needed, RegistryStatusBufferOverflow, ReadOnlySpan<byte>.Empty);
            }

            return WriteRegistryResult(Instance, DataPtr, (uint)Data.Length, RegistryStatusSuccess, Data);
        }

        private static NTSTATUS WriteRegistryResult(BinaryEmulator Instance, ulong DataPtr, uint OutputSize, uint Status, ReadOnlySpan<byte> Output)
        {
            // NT leaves both outputs unchanged if either is unwritable.
            if (!Instance.IsAccessible(DataPtr + OffsetRegistryOutputSize, (ulong)(OffsetRegistryOutput - OffsetRegistryOutputSize + Output.Length), true))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Result = stackalloc byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(Result, OutputSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Result.Slice(4), Status);
            if (!Instance.WriteMemory(DataPtr + OffsetRegistryOutputSize, Result))
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (!Output.IsEmpty && !Instance.WriteMemory(DataPtr + OffsetRegistryOutput, Output))
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryReadDriverVersion(WinSysHelper WinHelper, DxgkAdapter Adapter, out ulong Version)
        {
            Version = 0;
            return Win32kDxgk.TryGetDriverKey(WinHelper, Adapter, out string DriverKey)
                && WinHelper.TryReadRegistryString(DriverKey, "DriverVersion", out string Text)
                && AppxPackageModel.TryParseVersion(Text, out Version);
        }

        private static void WriteString(Span<byte> Field, string Value)
        {
            int Written = Encoding.Unicode.GetBytes(Value, Field);
            Field.Slice(Written).Clear();
        }
    }
}
