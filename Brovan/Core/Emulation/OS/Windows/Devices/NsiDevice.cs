using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed partial class NsiDevice : IWinDevice
    {
        private const uint FileDeviceNetwork = 0x12;
        private const uint MethodNeither = 3;
        private const uint IoctlNsiGetParameter = (FileDeviceNetwork << 16) | (1 << 2) | MethodNeither;
        private const uint IoctlNsiGetAllParameters = (FileDeviceNetwork << 16) | (3 << 2) | MethodNeither;
        private const uint IoctlNsiEnumerateObjectsAllParameters = (FileDeviceNetwork << 16) | (6 << 2) | MethodNeither;

        // nsiproxy reports the same Information on both guest widths.
        private const ulong GetParameterInformation = 0x50;
        private const ulong GetAllParametersInformation = 0x68;
        private const ulong EnumerateInformation = 0x70;

        private const uint StoreActive = 1;
        private const uint StoreInvalid = 2;
        private const uint StoreMax = 3;
        private const uint ActionGetExact = 0;
        private const uint ActionGetFirst = 1;
        private const uint ActionGetNext = 2;
        private const uint StructRw = 0;
        private const uint StructRoDynamic = 1;
        private const uint StructRoStatic = 2;

        private const int ModuleIdSize = 24;
        private const uint ModuleIdTypeGuid = 1;
        internal static readonly Guid NdisModuleGuid = new Guid("eb004a11-9b1a-11d4-9123-0050047759bc");
        private const uint NdisObjectCount = 18;
        internal static readonly Guid Ipv4ModuleGuid = new Guid("eb004a00-9b1a-11d4-9123-0050047759bc");
        internal static readonly Guid Ipv6ModuleGuid = new Guid("eb004a01-9b1a-11d4-9123-0050047759bc");
        private const uint IpObjectCount = 37;

        private static readonly (Guid Module, uint ObjectCount, NTSTATUS MissStatus)[] Modules =
        {
            (NdisModuleGuid, NdisObjectCount, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND),
            (Ipv4ModuleGuid, IpObjectCount, NTSTATUS.STATUS_NOT_FOUND),
            (Ipv6ModuleGuid, IpObjectCount, NTSTATUS.STATUS_NOT_FOUND),
        };

        private const uint ObjectCompartment = 7;
        private const uint ObjectThreadCompartment = 8;
        private const uint ObjectCompartmentIdForGuid = 11;
        private const uint ObjectInterfaceInformation = 0;
        private const uint ObjectIndexToLuid = 2;

        // These sizes match every Windows 11 ndis.sys from 22621.900 to 26100.9818.
        internal const int InterfaceRwSize = 1092;
        internal const int InterfaceDynamicSize = 216;
        internal const int InterfaceStaticSize = 600;
        private const int CountedStringSize = 516;
        private const int PhysicalAddressSize = 34;
        private const uint OperUp = 1;
        private const uint OperDown = 2;
        private const uint MediaConnected = 1;
        private const uint MediaDisconnected = 2;
        private const uint NotMediaConnected = 2;
        private const uint FullDuplex = 2;
        private const uint DedicatedConnection = 1;

        internal const uint DefaultCompartmentId = 1;
        private const int ThreadRwSize = 8;
        private const int CompartmentRwSize = 1640;
        private const int CompartmentGuidOffset = 1620;
        private const int GuidSize = 16;

        // ndisNsiGetCompartmentInfo copies whole fields only.
        private static readonly (int Offset, int Size)[] CompartmentFields =
        {
            (0, 4), (8, 8), (16, 16), (32, 16), (48, 516), (564, 516), (1080, 16), (1096, 516), (1616, 4), (1620, 16)
        };
        private const int CompartmentFieldsEnd = 1636;

        private const string CompartmentStoreKey = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a11-9b1a-11d4-9123-0050047759bc}\\7";
        private const string DefaultCompartmentValue = "01000000";

        public string DeviceName => "\\Device\\Nsi";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            Data.Information = 0;

            // METHOD_NEITHER
            Data.OutputBuffer = null;

            if (IOCTL == IoctlNsiGetParameter)
                return GetParameter(ref Data, Instance);
            if (IOCTL == IoctlNsiGetAllParameters)
                return GetAllParameters(ref Data, Instance, Enumerate: false);
            if (IOCTL == IoctlNsiEnumerateObjectsAllParameters)
                return GetAllParameters(ref Data, Instance, Enumerate: true);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                ReportUnmodeled(Instance, $"IOCTL 0x{IOCTL:X}");
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        private readonly struct GetParameterRequest
        {
            public readonly ulong ModulePtr;
            public readonly uint Object;
            public readonly uint Store;
            public readonly uint Action;
            public readonly ulong KeyPtr;
            public readonly uint KeyLength;
            public readonly uint ParamType;
            public readonly ulong ParamPtr;
            public readonly uint ParamLength;
            public readonly uint ParamOffset;

            public GetParameterRequest(ReadOnlySpan<byte> Raw, bool Is64)
            {
                if (Is64)
                {
                    ModulePtr = BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(0x10));
                    Object = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x18));
                    Store = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x20));
                    Action = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x24));
                    KeyPtr = BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(0x28));
                    KeyLength = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x30));
                    ParamType = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x38));
                    ParamPtr = BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(0x40));
                    ParamLength = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x48));
                    ParamOffset = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x4C));
                }
                else
                {
                    ModulePtr = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x08));
                    Object = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x0C));
                    Store = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x10));
                    Action = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x14));
                    KeyPtr = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x18));
                    KeyLength = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x1C));
                    ParamType = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x20));
                    ParamPtr = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x24));
                    ParamLength = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x28));
                    ParamOffset = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(0x2C));
                }
            }

            public static int SizeOf(bool Is64) => Is64 ? 0x50 : 0x30;
        }

        private static NTSTATUS GetParameter(ref DeviceData Data, BinaryEmulator Instance)
        {
            bool Is64 = Instance.WinHelper.PointerSize == 8;
            int RequestSize = GetParameterRequest.SizeOf(Is64);
            if (Data.InputBuffer == null || Data.InputLength < RequestSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            GetParameterRequest Request = new GetParameterRequest(Data.InputBuffer.AsSpan(0, RequestSize), Is64);

            // nsiproxy probes all three buffers first.
            Span<byte> ModuleId = stackalloc byte[ModuleIdSize];
            if (Request.ModulePtr == 0 || !Instance.ReadMemory(Request.ModulePtr, ModuleId))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            NTSTATUS Probed = ProbeBlock(Instance, Request.KeyPtr, Request.KeyLength, 1);
            if (Probed == NTSTATUS.STATUS_SUCCESS)
                Probed = ProbeBlock(Instance, Request.ParamPtr, Request.ParamLength, 1);
            if (Probed != NTSTATUS.STATUS_SUCCESS)
                return Probed;

            if (Request.Store > StoreMax || Request.Action > ActionGetNext || Request.Store == StoreInvalid || Request.ParamType > StructRoStatic)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if ((ulong)Request.ParamLength + Request.ParamOffset > uint.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Resolved = ResolveModule(Instance, ModuleId, Request.Store, Request.Object, out Guid Module);
            if (Resolved != NTSTATUS.STATUS_SUCCESS)
                return Resolved;

            if (Module == NdisModuleGuid)
            {
                switch (Request.Object)
                {
                    case ObjectCompartment:
                        return GetCompartment(ref Data, Instance, in Request);
                    case ObjectThreadCompartment:
                        return GetThreadCompartment(ref Data, Instance, in Request);
                    case ObjectCompartmentIdForGuid:
                        return GetCompartmentIdForGuid(ref Data, Instance, in Request);
                }
            }

            if (TryFindObject(Module, Request.Object, out NsiObject Modeled))
                return GetModeledParameter(ref Data, Instance, Modeled, in Request);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                ReportUnmodeled(Instance, $"object {Request.Object} of module {Module}");
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        // ndisNsiGetCompartmentInfo.
        private static NTSTATUS GetCompartment(ref DeviceData Data, BinaryEmulator Instance, in GetParameterRequest Request)
        {
            if (Request.KeyLength != sizeof(uint))
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Request.ParamLength == 0 || Request.ParamPtr == 0)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            Span<byte> Key = stackalloc byte[sizeof(uint)];
            if (!Instance.ReadMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            uint CompartmentId = BinaryPrimitives.ReadUInt32LittleEndian(Key);

            bool Found = Request.Action switch
            {
                ActionGetExact => CompartmentId == DefaultCompartmentId,
                ActionGetFirst => true,
                _ => CompartmentId < DefaultCompartmentId
            };
            if (!Found)
                return Request.Action == ActionGetExact ? NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND : NTSTATUS.STATUS_NO_MORE_ENTRIES;

            if (Request.ParamType != StructRw)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            Span<byte> Rw = stackalloc byte[CompartmentRwSize];
            ReadDefaultCompartmentRw(Instance, Rw);

            Span<byte> Output = stackalloc byte[CompartmentFieldsEnd];
            int Consumed = CopyFields(Rw, CompartmentFields, CompartmentFieldsEnd, Request.ParamOffset, Request.ParamLength, Output);
            if (Consumed == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            BinaryPrimitives.WriteUInt32LittleEndian(Key, DefaultCompartmentId);
            int Produced = (int)Math.Min((uint)Consumed, Request.ParamLength);

            // nsiproxy returns the full buffer with a zero-filled tail.
            if (!Instance.WinHelper.WritePadded(Request.ParamPtr, Request.ParamLength, Output.Slice(0, Produced)) || !Instance.WriteMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetParameterInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // netio serves this from the 8-byte read-write block.
        private static NTSTATUS GetThreadCompartment(ref DeviceData Data, BinaryEmulator Instance, in GetParameterRequest Request)
        {
            if (Request.KeyLength != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Request.ParamType != StructRw)
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            if ((ulong)Request.ParamOffset + Request.ParamLength > ThreadRwSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Request.Action != ActionGetExact)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            Span<byte> Rw = stackalloc byte[ThreadRwSize];
            Rw.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Rw, DefaultCompartmentId);

            if (Request.ParamPtr != 0 && Request.ParamLength != 0
                && !Instance.WriteMemory(Request.ParamPtr, Rw.Slice((int)Request.ParamOffset, (int)Request.ParamLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetParameterInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // ndisNsiGetCompartmentIdForGuid.
        private static NTSTATUS GetCompartmentIdForGuid(ref DeviceData Data, BinaryEmulator Instance, in GetParameterRequest Request)
        {
            if (Request.KeyPtr == 0 || Request.KeyLength != GuidSize || Request.ParamType != StructRoStatic || Request.ParamPtr == 0
                || Request.ParamLength != sizeof(uint) || Request.ParamOffset != 0 || Request.Action != ActionGetExact)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Key = stackalloc byte[GuidSize];
            if (!Instance.ReadMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Rw = stackalloc byte[CompartmentRwSize];
            ReadDefaultCompartmentRw(Instance, Rw);
            if (!Key.SequenceEqual(Rw.Slice(CompartmentGuidOffset, GuidSize)))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            Span<byte> Id = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(Id, DefaultCompartmentId);
            if (!Instance.WriteMemory(Request.ParamPtr, Id))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetParameterInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS GetModeledParameter(ref DeviceData Data, BinaryEmulator Instance, NsiObject Object, in GetParameterRequest Request)
        {
            if (Object.Parameter == ParameterSupport.Unmodeled)
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    ReportUnmodeled(Instance, $"get parameter on object {Object.Object} of module {Object.Module}");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }
            if (Request.KeyLength != Object.KeySize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Object.Parameter == ParameterSupport.ThroughGetAll)
                return GetParameterThroughGetAll(ref Data, Instance, Object, in Request);

            ReadOnlySpan<(int Offset, int Size)> Fields = Object.Fields(Request.ParamType);
            if (Fields.IsEmpty || Request.ParamPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Key = stackalloc byte[Object.KeySize];
            if (!Instance.ReadMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            NTSTATUS Status = Object.Find(Instance, Network, Request.Action, Key, out NsiRow Row);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            byte[] Block = Row.Block(Request.ParamType);
            byte[] Output = new byte[Block.Length];
            int Consumed = CopyFields(Block, Fields, Block.Length, Request.ParamOffset, Request.ParamLength, Output);
            if (Consumed == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int Produced = (int)Math.Min((uint)Consumed, Request.ParamLength);
            if (!Instance.WinHelper.WritePadded(Request.ParamPtr, Request.ParamLength, Output.AsSpan(0, Produced)) || !Instance.WriteMemory(Request.KeyPtr, Row.Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetParameterInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS GetParameterThroughGetAll(ref DeviceData Data, BinaryEmulator Instance, NsiObject Object, in GetParameterRequest Request)
        {
            int Size = Object.BlockSize(Request.ParamType);
            if (Size == 0)
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            if ((ulong)Request.ParamOffset + Request.ParamLength > (ulong)Size)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Key = stackalloc byte[Object.KeySize];
            if (Object.KeySize != 0 && !Instance.ReadMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            NTSTATUS Status = Object.Find(Instance, Network, Request.Action, Key, out NsiRow Row);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            byte[] Block = new byte[Size];
            ReadOnlySpan<byte> Filled = Row.Block(Request.ParamType);
            Filled.Slice(0, Math.Min(Size, Filled.Length)).CopyTo(Block);
            if ((Request.ParamLength != 0 && !Instance.WriteMemory(Request.ParamPtr, Block.AsSpan((int)Request.ParamOffset, (int)Request.ParamLength)))
                || (Request.Action != ActionGetExact && Object.KeySize != 0 && !Instance.WriteMemory(Request.KeyPtr, Row.Key)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetParameterInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private readonly struct AllParametersRequest
        {
            public readonly ulong ModulePtr;
            public readonly uint Object;
            public readonly uint Store;
            public readonly uint Action;
            public readonly ulong KeyPtr;
            public readonly uint KeySize;
            public readonly ulong RwPtr;
            public readonly uint RwSize;
            public readonly ulong DynamicPtr;
            public readonly uint DynamicSize;
            public readonly ulong StaticPtr;
            public readonly uint StaticSize;
            public readonly uint Count;

            public AllParametersRequest(ReadOnlySpan<byte> Raw, bool Is64, bool Enumerate)
            {
                int Pointer = Is64 ? 8 : 4;
                int Offset = 2 * Pointer;
                ModulePtr = ReadPointer(Raw, ref Offset, Pointer);
                Object = (uint)ReadPointer(Raw, ref Offset, Pointer);
                Store = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(Offset));
                Action = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(Offset + 4));
                Offset += 8;
                KeyPtr = ReadPointer(Raw, ref Offset, Pointer);
                KeySize = (uint)ReadPointer(Raw, ref Offset, Pointer);
                RwPtr = ReadPointer(Raw, ref Offset, Pointer);
                RwSize = (uint)ReadPointer(Raw, ref Offset, Pointer);
                DynamicPtr = ReadPointer(Raw, ref Offset, Pointer);
                DynamicSize = (uint)ReadPointer(Raw, ref Offset, Pointer);
                StaticPtr = ReadPointer(Raw, ref Offset, Pointer);
                StaticSize = (uint)ReadPointer(Raw, ref Offset, Pointer);
                Count = Enumerate ? BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(Offset)) : 0;
            }

            private static ulong ReadPointer(ReadOnlySpan<byte> Raw, ref int Offset, int Pointer)
            {
                ulong Value = Pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(Offset)) : BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(Offset));
                Offset += Pointer;
                return Value;
            }

            // nsi_get_all_param_ex, and nsi_enumerate_all_ex, which ends with the count.
            public static int SizeOf(bool Is64, bool Enumerate) => Is64 ? (Enumerate ? 0x70 : 0x68) : (Enumerate ? 0x3C : 0x38);

            public static int RwSizeOffset(bool Is64) => Is64 ? 0x40 : 0x24;

            public static int DynamicSizeOffset(bool Is64) => Is64 ? 0x50 : 0x2C;

            public static int StaticSizeOffset(bool Is64) => Is64 ? 0x60 : 0x34;

            public static int CountOffset(bool Is64) => Is64 ? 0x68 : 0x38;
        }

        private static NTSTATUS GetAllParameters(ref DeviceData Data, BinaryEmulator Instance, bool Enumerate)
        {
            bool Is64 = Instance.WinHelper.PointerSize == 8;
            int RequestSize = AllParametersRequest.SizeOf(Is64, Enumerate);
            if (Data.InputBuffer == null || Data.InputLength < RequestSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            AllParametersRequest Request = new AllParametersRequest(Data.InputBuffer.AsSpan(0, RequestSize), Is64, Enumerate);
            uint Entries = Enumerate ? Request.Count : 1;

            Span<byte> ModuleId = stackalloc byte[ModuleIdSize];
            if (Request.ModulePtr == 0 || !Instance.ReadMemory(Request.ModulePtr, ModuleId))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            NTSTATUS Probed = Enumerate ? Instance.WinHelper.ProbeForWrite(Data.InputPointer, (uint)RequestSize) : NTSTATUS.STATUS_SUCCESS;
            if (Probed == NTSTATUS.STATUS_SUCCESS)
                Probed = ProbeBlock(Instance, Request.KeyPtr, Request.KeySize, Entries);
            if (Probed == NTSTATUS.STATUS_SUCCESS)
                Probed = ProbeBlock(Instance, Request.RwPtr, Request.RwSize, Entries);
            if (Probed == NTSTATUS.STATUS_SUCCESS)
                Probed = ProbeBlock(Instance, Request.DynamicPtr, Request.DynamicSize, Entries);
            if (Probed == NTSTATUS.STATUS_SUCCESS)
                Probed = ProbeBlock(Instance, Request.StaticPtr, Request.StaticSize, Entries);
            if (Probed != NTSTATUS.STATUS_SUCCESS)
                return Probed;

            bool StoreValid = Enumerate ? (Request.Store & ~3u) == 0 && Request.Store != StoreInvalid : Request.Store <= 4 && Request.Store != StoreInvalid;
            bool ActionValid = Enumerate ? Request.Action is ActionGetFirst or ActionGetNext : Request.Action <= ActionGetNext;
            if (!StoreValid || !ActionValid)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Resolved = ResolveModule(Instance, ModuleId, Request.Store, Request.Object, out Guid Module);
            if (Resolved != NTSTATUS.STATUS_SUCCESS)
                return Resolved;

            if (!TryFindObject(Module, Request.Object, out NsiObject Object))
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    ReportUnmodeled(Instance, $"object {Request.Object} of module {Module} for {(Enumerate ? "enumerate" : "get all")}");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            if (!Object.ServesAll)
                return Enumerate ? NTSTATUS.STATUS_NOT_IMPLEMENTED : NTSTATUS.STATUS_NOT_SUPPORTED;
            if (Enumerate && Object.Rows == null)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            NTSTATUS Status = Enumerate ? CheckEnumerateRequest(Object, in Request) : CheckGetAllRequest(Object, in Request);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            return Enumerate
                ? EnumerateRows(ref Data, Instance, Object, Object.RowsOf(Instance, Network), in Request, Is64)
                : GetAllRow(ref Data, Instance, Object, Network, in Request, Is64);
        }

        // The checks follow NsipValidateGetAllParametersRequest in netio.
        private static NTSTATUS CheckGetAllRequest(NsiObject Object, in AllParametersRequest Request)
        {
            if (Request.KeySize != Object.KeySize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return CheckBlockSizes(Object, in Request);
        }

        // The checks follow NsipValidateEnumerateObjectsAllParametersRequest in netio.
        private static NTSTATUS CheckEnumerateRequest(NsiObject Object, in AllParametersRequest Request)
        {
            if (Request.KeySize != 0 && Request.KeySize != Object.KeySize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Request.KeyPtr == 0 && Request.Count != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = CheckBlockSizes(Object, in Request);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong Stride = 4UL + Request.KeySize + Request.RwSize + Request.DynamicSize + Request.StaticSize;
            return Stride > uint.MaxValue || Stride * Request.Count > uint.MaxValue ? NTSTATUS.STATUS_INTEGER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CheckBlockSizes(NsiObject Object, in AllParametersRequest Request)
        {
            if ((Request.RwPtr != 0 && Request.RwSize != 0 && Request.RwSize < Object.RwSize)
                || (Request.DynamicPtr != 0 && Request.DynamicSize != 0 && Request.DynamicSize < Object.DynamicSize)
                || (Request.StaticPtr != 0 && Request.StaticSize != 0 && Request.StaticSize < Object.StaticSize))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS GetAllRow(ref DeviceData Data, BinaryEmulator Instance, NsiObject Object, GuestNetworkSnapshot Network, in AllParametersRequest Request,
            bool Is64)
        {
            Span<byte> Key = stackalloc byte[Object.KeySize];
            if (Object.KeySize != 0 && !Instance.ReadMemory(Request.KeyPtr, Key))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Object.Find(Instance, Network, Request.Action, Key, out NsiRow Row);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // netio shortens a block longer than the object's, and nsiproxy writes the shortened size back.
            if (!WriteBlock(Instance, Request.RwPtr, Request.RwSize, Row.Rw) || !WriteBlock(Instance, Request.DynamicPtr, Request.DynamicSize, Row.Dynamic)
                || !WriteBlock(Instance, Request.StaticPtr, Request.StaticSize, Row.Static)
                || (Request.Action != ActionGetExact && Object.KeySize != 0 && !Instance.WriteMemory(Request.KeyPtr, Row.Key))
                || !WriteShortenedSize(Instance, Data.InputPointer + (ulong)AllParametersRequest.RwSizeOffset(Is64), Request.RwPtr, Request.RwSize, Object.RwSize)
                || !WriteShortenedSize(Instance, Data.InputPointer + (ulong)AllParametersRequest.DynamicSizeOffset(Is64), Request.DynamicPtr, Request.DynamicSize, Object.DynamicSize)
                || !WriteShortenedSize(Instance, Data.InputPointer + (ulong)AllParametersRequest.StaticSizeOffset(Is64), Request.StaticPtr, Request.StaticSize, Object.StaticSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = GetAllParametersInformation;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Without a key buffer, or with a count of 0, the call counts the objects.
        private static NTSTATUS EnumerateRows(ref DeviceData Data, BinaryEmulator Instance, NsiObject Object, NsiRow[] Rows, in AllParametersRequest Request, bool Is64)
        {
            bool Keyed = Request.KeyPtr != 0 && Request.KeySize != 0;

            // The request's action is the first step of netio's walk, so get-next starts after the key in the first slot.
            int Start = 0;
            if (Request.Action == ActionGetNext && Keyed)
            {
                Span<byte> Key = stackalloc byte[Object.KeySize];
                if (!Instance.ReadMemory(Request.KeyPtr, Key))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                while (Start < Rows.Length && Object.KeyOrder(Rows[Start].Key, Key) <= 0)
                    Start++;
            }

            uint Available = (uint)(Rows.Length - Start);
            uint Written = Available;
            NTSTATUS Status = Object.CountOnlyStatus;
            if (Keyed && Request.Count != 0)
            {
                Status = NTSTATUS.STATUS_SUCCESS;
                Written = Math.Min(Request.Count, Available);
                for (uint i = 0; i < Written; i++)
                {
                    if (!WriteRow(Instance, Rows[Start + (int)i], in Request, i, WriteKey: true))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (Available > Request.Count)
                    Status = NTSTATUS.STATUS_MORE_ENTRIES;
            }
            else if (Available != 0)
            {
                // Without a key buffer netio does not move the block pointers, so the last row ends up in the first slot.
                if (!WriteRow(Instance, Rows[Rows.Length - 1], in Request, 0, WriteKey: false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (!Instance.WinHelper.WriteUInt32(Data.InputPointer + (ulong)AllParametersRequest.CountOffset(Is64), Written))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = EnumerateInformation;
            return Status;
        }

        private static bool WriteRow(BinaryEmulator Instance, NsiRow Row, in AllParametersRequest Request, uint Slot, bool WriteKey)
        {
            return (!WriteKey || Instance.WriteMemory(Request.KeyPtr + Slot * Request.KeySize, Row.Key))
                && WriteBlock(Instance, Request.RwPtr == 0 ? 0 : Request.RwPtr + Slot * Request.RwSize, Request.RwSize, Row.Rw)
                && WriteBlock(Instance, Request.DynamicPtr == 0 ? 0 : Request.DynamicPtr + Slot * Request.DynamicSize, Request.DynamicSize, Row.Dynamic)
                && WriteBlock(Instance, Request.StaticPtr == 0 ? 0 : Request.StaticPtr + Slot * Request.StaticSize, Request.StaticSize, Row.Static);
        }

        private static bool WriteBlock(BinaryEmulator Instance, ulong Address, uint Size, byte[] Block)
        {
            if (Address == 0 || Size == 0 || Block.Length == 0)
                return true;

            return Instance.WriteMemory(Address, Block);
        }

        private static bool WriteShortenedSize(BinaryEmulator Instance, ulong SizeAddress, ulong BlockPtr, uint Size, int ObjectSize)
        {
            if (BlockPtr == 0 || Size <= ObjectSize)
                return true;

            return Instance.WinHelper.ProbeForWrite(SizeAddress, sizeof(uint)) == NTSTATUS.STATUS_SUCCESS
                && Instance.WinHelper.WriteUInt32(SizeAddress, (uint)ObjectSize);
        }

        // Get-next takes the first row after the key in the provider's order.
        private static NTSTATUS FindRow(NsiObject Object, NsiRow[] Rows, uint Action, ReadOnlySpan<byte> Key, out NsiRow Found)
        {
            Found = null;
            foreach (NsiRow Row in Rows)
            {
                bool Match = Action switch
                {
                    ActionGetExact => Key.SequenceEqual(Row.Key),
                    ActionGetFirst => true,
                    _ => Object.KeyOrder(Row.Key, Key) > 0,
                };

                if (Match)
                {
                    Found = Row;
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            return Action == ActionGetExact ? Object.MissStatus : NTSTATUS.STATUS_NO_MORE_ENTRIES;
        }

        private static int CompareScalarKeys(ReadOnlySpan<byte> Left, ReadOnlySpan<byte> Right) => ScalarKey(Left).CompareTo(ScalarKey(Right));

        // netio sorts what a bulk provider returns by the key bytes.
        private static int CompareKeyBytes(ReadOnlySpan<byte> Left, ReadOnlySpan<byte> Right) => Left.SequenceCompareTo(Right);

        private static ulong ScalarKey(ReadOnlySpan<byte> Key) => Key.Length switch
        {
            sizeof(ulong) => BinaryPrimitives.ReadUInt64LittleEndian(Key),
            sizeof(uint) => BinaryPrimitives.ReadUInt32LittleEndian(Key),
            _ => 0,
        };

        internal sealed class NsiRow
        {
            public byte[] Key;
            public byte[] Rw = Array.Empty<byte>();
            public byte[] Dynamic = Array.Empty<byte>();
            public byte[] Static = Array.Empty<byte>();

            public byte[] Block(uint ParamType) => ParamType switch
            {
                StructRw => Rw,
                StructRoDynamic => Dynamic,
                _ => Static,
            };
        }

        private enum ParameterSupport
        {
            Unmodeled,
            Fields,
            ThroughGetAll,
        }

        private delegate int KeyComparison(ReadOnlySpan<byte> Left, ReadOnlySpan<byte> Right);

        private delegate NTSTATUS RowLookup(NsiObject Object, BinaryEmulator Instance, GuestNetworkSnapshot Network, uint Action, ReadOnlySpan<byte> Key,
            out NsiRow Row);

        private sealed class NsiObject
        {
            public Guid Module;
            public uint Object;
            public int KeySize;
            public int RwSize;
            public int DynamicSize;
            public int StaticSize;
            public bool ServesAll;
            public ParameterSupport Parameter;
            public NTSTATUS CountOnlyStatus = NTSTATUS.STATUS_SUCCESS;
            public NTSTATUS MissStatus;
            public (int Offset, int Size)[] RwFields = Array.Empty<(int, int)>();
            public (int Offset, int Size)[] DynamicFields = Array.Empty<(int, int)>();
            public (int Offset, int Size)[] StaticFields = Array.Empty<(int, int)>();
            // Null when the provider registers no enumerate routine.
            public Func<BinaryEmulator, GuestNetworkSnapshot, NsiRow[]> Rows;
            public KeyComparison KeyOrder = CompareScalarKeys;
            public RowLookup Lookup;
            private Comparison<NsiRow> RowOrder;

            public NsiRow[] RowsOf(BinaryEmulator Instance, GuestNetworkSnapshot Network)
            {
                if (Rows == null)
                    return Array.Empty<NsiRow>();

                NsiRow[] Built = Rows(Instance, Network);
                Array.Sort(Built, RowOrder ??= (Left, Right) => KeyOrder(Left.Key, Right.Key));
                return Built;
            }

            public NTSTATUS Find(BinaryEmulator Instance, GuestNetworkSnapshot Network, uint Action, ReadOnlySpan<byte> Key, out NsiRow Row) =>
                Lookup != null ? Lookup(this, Instance, Network, Action, Key, out Row) : FindRow(this, RowsOf(Instance, Network), Action, Key, out Row);

            public int BlockSize(uint ParamType) => ParamType switch
            {
                StructRw => RwSize,
                StructRoDynamic => DynamicSize,
                _ => StaticSize,
            };

            public ReadOnlySpan<(int Offset, int Size)> Fields(uint ParamType) => ParamType switch
            {
                StructRw => RwFields,
                StructRoDynamic => DynamicFields,
                _ => StaticFields,
            };
        }

        private static readonly NsiObject[] ModeledObjects;

        // The parts of this partial class initialize their static fields in no fixed order, so the table is built here.
        static NsiDevice()
        {
            ModeledObjects = new[]
            {
                new NsiObject
                {
                    Module = NdisModuleGuid,
                    Object = ObjectInterfaceInformation,
                    KeySize = sizeof(ulong),
                    RwSize = InterfaceRwSize,
                    DynamicSize = InterfaceDynamicSize,
                    StaticSize = InterfaceStaticSize,
                    ServesAll = true,
                    Parameter = ParameterSupport.Fields,
                    RwFields = new (int, int)[] { (0, 16), (16, 4), (20, CountedStringSize), (536, PhysicalAddressSize), (570, 2), (572, CountedStringSize), (1088, 4) },
                    DynamicFields = BuildDynamicFields(),
                    StaticFields = new (int, int)[]
                    {
                        (0, 4), (4, CountedStringSize), (520, 4), (524, 4), (528, 4), (532, 4), (536, 16), (552, 2), (554, PhysicalAddressSize), (588, 4), (592, 4), (596, 4)
                    },
                    Rows = BuildInterfaceRows,
                },
                new NsiObject
                {
                    Module = NdisModuleGuid,
                    Object = ObjectIndexToLuid,
                    KeySize = sizeof(uint),
                    Parameter = ParameterSupport.Fields,
                    StaticSize = sizeof(ulong),
                    StaticFields = new (int, int)[] { (0, sizeof(ulong)) },
                    Rows = BuildIndexRows,
                },
                InterfaceStateObject(), ThreadCompartmentObject(),
                IpInterfaceObject(Ipv4ModuleGuid), IpInterfaceObject(Ipv6ModuleGuid),
                UnicastObject(Ipv4ModuleGuid), UnicastObject(Ipv6ModuleGuid),
                RouteObject(Ipv4ModuleGuid), RouteObject(Ipv6ModuleGuid),
                AnycastObject(Ipv4ModuleGuid), AnycastObject(Ipv6ModuleGuid),
                MulticastObject(Ipv4ModuleGuid), MulticastObject(Ipv6ModuleGuid),
                BestRouteObject(Ipv4ModuleGuid), BestRouteObject(Ipv6ModuleGuid),
                IpCompartmentObject(Ipv4ModuleGuid), IpCompartmentObject(Ipv6ModuleGuid),
                IpGlobalObject(Ipv4ModuleGuid), IpGlobalObject(Ipv6ModuleGuid),
            };

            foreach (NsiObject Modeled in ModeledObjects)
            {
                foreach ((Guid Module, uint _, NTSTATUS MissStatus) in Modules)
                {
                    if (Module == Modeled.Module)
                        Modeled.MissStatus = MissStatus;
                }
            }
        }

        private static NTSTATUS ResolveModule(BinaryEmulator Instance, ReadOnlySpan<byte> ModuleId, uint Store, uint Object, out Guid Module)
        {
            Module = Guid.Empty;
            if (Store != StoreActive && Store != StoreMax)
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    ReportUnmodeled(Instance, $"persistent store {Store}");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            if (!TryFindModule(ModuleId, out Module, out uint ObjectCount))
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    ReportUnmodeled(Instance, $"module {new Guid(ModuleId.Slice(8, GuidSize))} object {Object}");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            return Object >= ObjectCount ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryFindModule(ReadOnlySpan<byte> ModuleId, out Guid Module, out uint ObjectCount)
        {
            Module = Guid.Empty;
            ObjectCount = 0;
            if (BinaryPrimitives.ReadUInt32LittleEndian(ModuleId.Slice(4)) != ModuleIdTypeGuid)
                return false;

            Guid Requested = new Guid(ModuleId.Slice(8, GuidSize));
            foreach ((Guid Known, uint Count, NTSTATUS _) in Modules)
            {
                if (Known == Requested)
                {
                    Module = Known;
                    ObjectCount = Count;
                    return true;
                }
            }

            return false;
        }

        internal static NsiRow[] RowsOf(BinaryEmulator Instance, GuestNetworkSnapshot Network, Guid Module, uint Object) =>
            TryFindObject(Module, Object, out NsiObject Found) ? Found.RowsOf(Instance, Network) : Array.Empty<NsiRow>();

        internal static NTSTATUS GetAllOf(BinaryEmulator Instance, GuestNetworkSnapshot Network, Guid Module, uint Object, ReadOnlySpan<byte> Key, out NsiRow Row)
        {
            Row = null;
            if (!TryFindObject(Module, Object, out NsiObject Found))
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            if (Key.Length != Found.KeySize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Found.Find(Instance, Network, ActionGetExact, Key, out Row);
        }

        private static bool TryFindObject(Guid Module, uint Object, out NsiObject Found)
        {
            foreach (NsiObject Candidate in ModeledObjects)
            {
                if (Candidate.Module == Module && Candidate.Object == Object)
                {
                    Found = Candidate;
                    return true;
                }
            }

            Found = null;
            return false;
        }

        private static (int Offset, int Size)[] BuildDynamicFields()
        {
            (int, int)[] Fields = new (int, int)[5 + (InterfaceDynamicSize - 24) / 8];
            for (int i = 0; i < 5; i++)
                Fields[i] = (i * 4, 4);
            for (int i = 5; i < Fields.Length; i++)
                Fields[i] = (24 + (i - 5) * 8, 8);
            return Fields;
        }

        private static NsiRow[] BuildInterfaceRows(BinaryEmulator Instance, GuestNetworkSnapshot Network)
        {
            NsiRow[] Rows = new NsiRow[Network.Interfaces.Length];
            for (int i = 0; i < Rows.Length; i++)
            {
                GuestNetworkInterface Interface = Network.Interfaces[i];
                NsiRow Row = new NsiRow
                {
                    Key = BitConverter.GetBytes(Interface.Luid),
                    Rw = new byte[InterfaceRwSize],
                    Dynamic = new byte[InterfaceDynamicSize],
                    Static = new byte[InterfaceStaticSize],
                };
                FillInterfaceInformation(Interface, Row.Rw, Row.Dynamic, Row.Static);
                Rows[i] = Row;
            }

            return Rows;
        }

        private static NsiRow[] BuildIndexRows(BinaryEmulator Instance, GuestNetworkSnapshot Network)
        {
            NsiRow[] Rows = new NsiRow[Network.Interfaces.Length];
            for (int i = 0; i < Rows.Length; i++)
            {
                GuestNetworkInterface Interface = Network.Interfaces[i];
                Rows[i] = new NsiRow { Key = BitConverter.GetBytes(Interface.Index), Static = BitConverter.GetBytes(Interface.Luid) };
            }

            return Rows;
        }

        // The blocks are nsi_ndis_ifinfo_rw, nsi_ndis_ifinfo_dynamic and nsi_ndis_ifinfo_static.
        internal static void FillInterfaceInformation(GuestNetworkInterface Interface, Span<byte> Rw, Span<byte> Dynamic, Span<byte> Static)
        {
            const uint AdminUp = 1;

            Rw.Clear();
            Dynamic.Clear();
            Static.Clear();

            Interface.NetworkGuid.TryWriteBytes(Rw);
            BinaryPrimitives.WriteUInt32LittleEndian(Rw.Slice(16), AdminUp);
            WriteCountedString(Rw.Slice(20, CountedStringSize), Interface.Alias);
            WritePhysicalAddress(Rw.Slice(536, PhysicalAddressSize), Interface.PhysicalAddress);

            BinaryPrimitives.WriteUInt32LittleEndian(Dynamic, Interface.Connected ? OperUp : OperDown);
            BinaryPrimitives.WriteUInt32LittleEndian(Dynamic.Slice(4), Interface.Connected ? 0 : NotMediaConnected);
            BinaryPrimitives.WriteUInt32LittleEndian(Dynamic.Slice(8), Interface.Connected ? MediaConnected : MediaDisconnected);
            BinaryPrimitives.WriteUInt32LittleEndian(Dynamic.Slice(12), FullDuplex);
            BinaryPrimitives.WriteUInt32LittleEndian(Dynamic.Slice(16), Interface.Mtu);
            BinaryPrimitives.WriteUInt64LittleEndian(Dynamic.Slice(24), Interface.LinkSpeed);
            BinaryPrimitives.WriteUInt64LittleEndian(Dynamic.Slice(32), Interface.LinkSpeed);
            BinaryPrimitives.WriteUInt64LittleEndian(Dynamic.Slice(208), 1);

            BinaryPrimitives.WriteUInt32LittleEndian(Static, Interface.Index);
            WriteCountedString(Static.Slice(4, CountedStringSize), Interface.Description);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(520), Interface.Type);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(524), Interface.AccessType);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(532), DedicatedConnection);
            Interface.InterfaceGuid.TryWriteBytes(Static.Slice(536));
            BinaryPrimitives.WriteUInt16LittleEndian(Static.Slice(552), Interface.Hardware ? (ushort)1 : (ushort)0);
            WritePhysicalAddress(Static.Slice(554, PhysicalAddressSize), Interface.PhysicalAddress);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(588), Interface.Hardware ? 1u : 0u);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(592), Interface.MediaType);
            BinaryPrimitives.WriteUInt32LittleEndian(Static.Slice(596), Interface.PhysicalMediumType);
        }

        private static void WriteCountedString(Span<byte> Field, string Text)
        {
            int Characters = Math.Min(Text.Length, (CountedStringSize - 4) / 2);
            BinaryPrimitives.WriteUInt16LittleEndian(Field, (ushort)(Characters * 2));
            for (int i = 0; i < Characters; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(Field.Slice(2 + i * 2), Text[i]);
        }

        private static void WritePhysicalAddress(Span<byte> Field, byte[] Address)
        {
            int Length = Math.Min(Address.Length, PhysicalAddressSize - 2);
            BinaryPrimitives.WriteUInt16LittleEndian(Field, (ushort)Length);
            Address.AsSpan(0, Length).CopyTo(Field.Slice(2));
        }

        // NT providers copy whole fields, from the one at the offset, while they fit.
        private static int CopyFields(ReadOnlySpan<byte> Block, ReadOnlySpan<(int Offset, int Size)> Fields, int FieldsEnd, uint ParamOffset, uint ParamLength,
            Span<byte> Output)
        {
            int Start = 0;
            while (Start < Fields.Length && Fields[Start].Offset != ParamOffset)
                Start++;
            if (Start == Fields.Length)
                return 0;

            Output.Clear();
            long Remaining = ParamLength;
            int Consumed = 0;
            for (int i = Start; i < Fields.Length && Remaining > 0; i++)
            {
                (int Offset, int Size) = Fields[i];
                if (Remaining < Size)
                    break;

                int Next = i + 1 < Fields.Length ? Fields[i + 1].Offset : FieldsEnd;
                Block.Slice(Offset, Size).CopyTo(Output.Slice(Offset - (int)ParamOffset));
                Remaining -= Next - Offset;
                Consumed = Next - (int)ParamOffset;
            }

            return Consumed;
        }

        private static void ReadDefaultCompartmentRw(BinaryEmulator Instance, Span<byte> Rw)
        {
            Rw.Clear();

            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(CompartmentStoreKey);
            if (Key == null || !Instance.WinHelper.TryGetRegistryValue(Key, DefaultCompartmentValue, out ValueNode Value) || Value?.Data == null)
                return;

            Value.Data.AsSpan(0, Math.Min(Value.Data.Length, Rw.Length)).CopyTo(Rw);
        }

        private static NTSTATUS ProbeBlock(BinaryEmulator Instance, ulong Address, uint Size, uint Count)
        {
            ulong Length = (ulong)Size * Count;
            if (Length == 0)
                return NTSTATUS.STATUS_SUCCESS;
            if (Address == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            if (Length > uint.MaxValue)
                return NTSTATUS.STATUS_INTEGER_OVERFLOW;

            return Instance.WinHelper.ProbeForWrite(Address, (uint)Length);
        }

        private static void ReportUnmodeled(BinaryEmulator Instance, string What) =>
            Instance.TriggerEventMessage($"[!] NSI request not implemented: {What}.", LogFlags.General);
    }
}
