using System;
using System.Buffers.Binary;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NsiDevice : IWinDevice
    {
        private const uint FileDeviceNetwork = 0x12;
        private const uint MethodNeither = 3;
        private const uint IoctlNsiGetParameter = (FileDeviceNetwork << 16) | (1 << 2) | MethodNeither;

        // nsiproxy reports this for both guest widths.
        private const ulong GetParameterInformation = 0x50;

        private const uint StoreActive = 1;
        private const uint StoreInvalid = 2;
        private const uint StoreMax = 3;
        private const uint ActionGetExact = 0;
        private const uint ActionGetFirst = 1;
        private const uint ActionGetNext = 2;
        private const uint StructRw = 0;
        private const uint StructRoStatic = 2;

        private const int ModuleIdSize = 24;
        private const uint ModuleIdTypeGuid = 1;
        private static readonly Guid NdisModuleGuid = new Guid("eb004a11-9b1a-11d4-9123-0050047759bc");
        private const uint NdisObjectCount = 18;

        private const uint ObjectCompartment = 7;
        private const uint ObjectThreadCompartment = 8;
        private const uint ObjectCompartmentIdForGuid = 11;

        private const uint DefaultCompartmentId = 1;
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
            if (!IsProbeable(Instance, Request.KeyPtr, Request.KeyLength) || !IsProbeable(Instance, Request.ParamPtr, Request.ParamLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Request.Store > StoreMax || Request.Action > ActionGetNext || Request.Store == StoreInvalid || Request.ParamType > StructRoStatic)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if ((ulong)Request.ParamLength + Request.ParamOffset > uint.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Request.Store != StoreActive && Request.Store != StoreMax)
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    ReportUnmodeled(Instance, $"persistent store {Request.Store}");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            if (BinaryPrimitives.ReadUInt32LittleEndian(ModuleId.Slice(4)) != ModuleIdTypeGuid || new Guid(ModuleId.Slice(8, GuidSize)) != NdisModuleGuid)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (Request.Object >= NdisObjectCount)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            switch (Request.Object)
            {
                case ObjectCompartment:
                    return GetCompartment(ref Data, Instance, in Request);
                case ObjectThreadCompartment:
                    return GetThreadCompartment(ref Data, Instance, in Request);
                case ObjectCompartmentIdForGuid:
                    return GetCompartmentIdForGuid(ref Data, Instance, in Request);
            }

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                ReportUnmodeled(Instance, $"NDIS object {Request.Object}");
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

            int Start = 0;
            while (Start < CompartmentFields.Length && CompartmentFields[Start].Offset != Request.ParamOffset)
                Start++;
            if (Start == CompartmentFields.Length)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Rw = stackalloc byte[CompartmentRwSize];
            ReadDefaultCompartmentRw(Instance, Rw);

            Span<byte> Output = stackalloc byte[CompartmentFieldsEnd];
            Output.Clear();
            long Remaining = Request.ParamLength;
            int Consumed = 0;
            for (int i = Start; i < CompartmentFields.Length && Remaining > 0; i++)
            {
                (int Offset, int Size) = CompartmentFields[i];
                if (Remaining < Size)
                    break;

                int Next = i + 1 < CompartmentFields.Length ? CompartmentFields[i + 1].Offset : CompartmentFieldsEnd;
                Rw.Slice(Offset, Size).CopyTo(Output.Slice(Offset - (int)Request.ParamOffset));
                Remaining -= Next - Offset;
                Consumed = Next - (int)Request.ParamOffset;
            }

            if (Consumed == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            BinaryPrimitives.WriteUInt32LittleEndian(Key, DefaultCompartmentId);
            int Produced = (int)Math.Min((uint)Consumed, Request.ParamLength);
            if (!WriteParameter(Instance, Request.ParamPtr, Request.ParamLength, Output.Slice(0, Produced)) || !Instance.WriteMemory(Request.KeyPtr, Key))
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

        private static void ReadDefaultCompartmentRw(BinaryEmulator Instance, Span<byte> Rw)
        {
            Rw.Clear();

            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(CompartmentStoreKey);
            if (Key == null || !Instance.WinHelper.TryGetRegistryValue(Key, DefaultCompartmentValue, out ValueNode Value) || Value?.Data == null)
                return;

            Value.Data.AsSpan(0, Math.Min(Value.Data.Length, Rw.Length)).CopyTo(Rw);
        }

        private static bool IsProbeable(BinaryEmulator Instance, ulong Address, uint Length)
        {
            if (Length == 0)
                return true;

            return Address != 0 && Instance.IsRegionCommitted(Address, Length);
        }

        // nsiproxy copies back the whole buffer, so the tail reads as zero.
        private static bool WriteParameter(BinaryEmulator Instance, ulong Address, uint Length, ReadOnlySpan<byte> Produced)
        {
            if (!Instance.WriteMemory(Address, Produced))
                return false;

            ulong Done = (ulong)Produced.Length;
            while (Done < Length)
            {
                uint Chunk = (uint)Math.Min(Length - Done, (ulong)NtReadFile.IoChunkBytes);
                if (!Instance.WinHelper.WriteZeroMemory(Address + Done, Chunk))
                    return false;
                Done += Chunk;
            }

            return true;
        }

        private static void ReportUnmodeled(BinaryEmulator Instance, string What) =>
            Instance.TriggerEventMessage($"[!] NSI request not implemented: {What}.", LogFlags.General);
    }
}
