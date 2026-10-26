using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    internal readonly record struct StdObjRef(uint Flags, uint PublicRefs, ulong Oxid, ulong Oid, Guid Ipid)
    {
        public const int Size = 0x28;

        public static StdObjRef Read(ReadOnlySpan<byte> Data)
        {
            return new StdObjRef(
                BinaryPrimitives.ReadUInt32LittleEndian(Data),
                BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(4)),
                BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(8)),
                BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(0x10)),
                new Guid(Data.Slice(0x18, 16)));
        }

        public void Write(Span<byte> Data)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Data, Flags);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), PublicRefs);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(8), Oxid);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10), Oid);
            Ipid.TryWriteBytes(Data.Slice(0x18, 16));
        }
    }

    // DCOM calls between processes of one machine, framed the way combase frames them (callheaders\localcallheaders.cpp).
    internal static class Orpc
    {
        private const uint ObjRefSignature = 0x574F454D;
        private const uint ObjRefStandard = 1;
        private const uint ObjRefHandler = 2;
        private const uint ObjRefCustom = 4;
        private const int OffObjRefIid = 8;
        private const int ObjRefHeaderSize = 0x18;
        private const int OffCustomClsid = ObjRefHeaderSize;
        private const int OffCustomExtension = 0x28;
        private const int OffCustomSize = 0x2C;
        public const int CustomObjRefHeaderSize = 0x30;
        public const uint OrpcfLocal = 1;
        public const int InterfaceIdSize = 16;

        public const ushort ComVersionMajor = 5;
        public const ushort ComVersionMinor = 7;
        public const uint UserMarshalMarker = 0x72657355;
        private const uint WdtRemoteCall = 0x50746457;
        public const uint SOk = 0;
        public const uint SFalse = 1;
        public const uint ENoInterface = 0x80004002;
        public const uint ENotImpl = 0x80004001;
        public const uint EOutOfMemory = 0x8007000E;
        public const uint EInvalidArg = 0x80070057;
        public const uint EElementNotFound = 0x80070490;

        public static readonly Guid RemUnknownInterface = new Guid("00000131-0000-0000-c000-000000000046");
        public static readonly Guid RemUnknown2Interface = new Guid("00000143-0000-0000-c000-000000000046");
        public static readonly Guid RundownInterface = new Guid("00000134-0000-0000-c000-000000000046");
        public const uint ProcRemQueryInterface = 3;
        public const uint ProcRemAddRef = 4;
        public const uint ProcRemRelease = 5;
        public const uint ProcRemQueryInterface2 = 6;

        public const uint MaxRequestedInterfaces = 0x8000;
        private const uint ReservedOrpcFlags = 0xFFFFFF90;
        private const int OrpcThisSize = 0x20;
        private const int OffOrpcThisExtensions = 0x1C;
        private const int ExtentArrayHeaderSize = 0x10;
        private const int ExtentHeaderSize = 0x18;
        private const uint MaxExtents = 0x10;
        private const int LocalThisSize = 0x60;
        private const int OffLocalThisCallId = 0x18;
        private const int OffLocalThisTouchedAstas = 0x58;
        private const int OffLocalThisContainerData = 0x5C;
        private const int TouchedAstaHeaderSize = 0x10;
        private const uint MaxTouchedAstas = 0x1000;
        private const int LocalThatSize = 0x18;
        private const int EmptyDualStringArraySize = 4;

        public static readonly Guid IUnknownId = new Guid("00000000-0000-0000-c000-000000000046");
        public static readonly Guid IInspectableId = new Guid("af86e2e0-b12d-4c6a-9c5a-d7aa65101e90");

        public static readonly Guid StandardMarshal = new Guid("00000017-0000-0000-c000-000000000046");
        public static readonly Guid AggregatedStandardMarshal = new Guid("00000027-0000-0008-c000-000000000046");
        public const int StandardObjRefSize = ObjRefHeaderSize + StdObjRef.Size + EmptyDualStringArraySize;
        public const int HandlerObjRefSize = ObjRefHeaderSize + StdObjRef.Size + InterfaceIdSize + EmptyDualStringArraySize;

        public static ulong NewId() => (ulong)Random.Shared.NextInt64(1, long.MaxValue);

        public static Guid InterfaceAt(ReadOnlySpan<byte> Interfaces, int Index) => new Guid(Interfaces.Slice(Index * InterfaceIdSize, InterfaceIdSize));

        // The headers are checked as combase checks them (ValidateAndCalculateSizeOfIncomingLocalThis).
        public static bool TryGetRequestParameters(ReadOnlySpan<byte> Stub, out int Offset)
        {
            Offset = 0;
            if (Stub.Length < OrpcThisSize)
                return false;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(4));
            if (BinaryPrimitives.ReadUInt16LittleEndian(Stub) != ComVersionMajor || BinaryPrimitives.ReadUInt16LittleEndian(Stub.Slice(2)) != ComVersionMinor
                || (Flags & OrpcfLocal) == 0 || (Flags & ReservedOrpcFlags) != 0)
                return false;

            int Position = OrpcThisSize;
            if (BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(OffOrpcThisExtensions)) != 0 && !TrySkipExtentArray(Stub, ref Position))
                return false;

            if (Stub.Length - Position < LocalThisSize)
                return false;

            ReadOnlySpan<byte> LocalThis = Stub.Slice(Position);
            if (LocalThis.Slice(OffLocalThisCallId, 16).IndexOfAnyExcept((byte)0) < 0)
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(LocalThis.Slice(OffLocalThisContainerData)) != 0)
            {
                Utils.LogError("[-] ORPC: a call carries container passthrough data, which is not supported.");
                return false;
            }

            int Size = LocalThisSize;
            if (BinaryPrimitives.ReadUInt32LittleEndian(LocalThis.Slice(OffLocalThisTouchedAstas)) != 0)
            {
                if (LocalThis.Length < LocalThisSize + TouchedAstaHeaderSize)
                    return false;

                ReadOnlySpan<byte> Astas = LocalThis.Slice(LocalThisSize);
                uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Astas);
                if (Count == 0 || Count > MaxTouchedAstas || Count != BinaryPrimitives.ReadUInt32LittleEndian(Astas.Slice(0x0C))
                    || BinaryPrimitives.ReadUInt32LittleEndian(Astas.Slice(8)) == 0)
                    return false;

                Size = LocalThisSize + TouchedAstaHeaderSize + (int)Count * sizeof(ulong);
                if (LocalThis.Length < Size)
                    return false;
            }

            Offset = Position + Size;
            return true;
        }

        private static bool TrySkipExtentArray(ReadOnlySpan<byte> Stub, ref int Position)
        {
            if (Stub.Length - Position < ExtentArrayHeaderSize)
                return false;

            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Position));
            uint Rounded = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Position + 0x0C));
            if (Count > MaxExtents || BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Position + 8)) == 0 || Rounded != ((Count + 1) & ~1u))
                return false;

            Position += ExtentArrayHeaderSize;
            if (Stub.Length - Position < Rounded * 4)
                return false;

            ReadOnlySpan<byte> Pointers = Stub.Slice(Position, (int)Rounded * 4);
            Position += (int)Rounded * 4;
            for (int i = 0; i < Rounded; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(Pointers.Slice(i * 4)) == 0)
                    continue;

                if (Stub.Length - Position < ExtentHeaderSize)
                    return false;

                uint RoundedSize = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Position));
                uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Position + 0x14));
                if (Size > (uint)(Stub.Length - Position - ExtentHeaderSize) || RoundedSize != ((Size + 7) & ~7u)
                    || RoundedSize > (uint)(Stub.Length - Position - ExtentHeaderSize))
                    return false;

                Position += ExtentHeaderSize + (int)RoundedSize;
            }

            return true;
        }

        // The LocalThis is the one combase's FillLocalThis writes for a plain multithreaded-apartment call.
        public static void WriteRequestHeader(ref Ndr20Writer Writer)
        {
            Writer.WriteUInt16(ComVersionMajor);
            Writer.WriteUInt16(ComVersionMinor);
            Writer.WriteUInt32(OrpcfLocal);
            Writer.WriteUInt32(0);
            Writer.WriteGuid(Guid.NewGuid());
            Writer.WriteUInt32(0);

            Writer.WriteZeros(OffLocalThisCallId);
            Writer.WriteGuid(Guid.NewGuid());
            Writer.WriteZeros(LocalThisSize - OffLocalThisCallId - 16);
        }

        public static bool TryGetResponseParameters(ReadOnlySpan<byte> Stub, out int Offset)
        {
            Offset = 0;
            if (Stub.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(Stub) != OrpcfLocal)
                return false;

            int Position = 8;
            if (BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(4)) != 0 && !TrySkipExtentArray(Stub, ref Position))
                return false;

            if (Stub.Length - Position < LocalThatSize)
                return false;

            ReadOnlySpan<byte> LocalThat = Stub.Slice(Position, LocalThatSize);
            if (LocalThat.Slice(8).IndexOfAnyExcept((byte)0) >= 0)
            {
                Utils.LogError("[-] ORPC: a response carries a LocalThat with optional parts, which is not supported.");
                return false;
            }

            Offset = Position + LocalThatSize;
            return true;
        }

        public static void WriteHstring(ref Ndr20Writer Writer, string Value)
        {
            Writer.AlignTo(4);
            Writer.WriteUInt32(UserMarshalMarker);
            WriteHstringBody(ref Writer, Value);
        }

        // The body as HSTRING_UserMarshal writes it.
        public static void WriteHstringBody(ref Ndr20Writer Writer, ReadOnlySpan<char> Value)
        {
            Writer.AlignTo(8);
            Writer.WriteUInt32(WdtRemoteCall);
            Writer.WriteUInt32((uint)(Value.Length * sizeof(char)));
            Writer.WriteUtf16(Value);
        }

        public static bool TrySkipHstringBody(ref Ndr20Reader Reader)
        {
            Reader.Align(8);
            return Reader.TryReadUInt32(out _) && Reader.TryReadUInt32(out uint Length) && Reader.TrySkip((int)Math.Min(Length, int.MaxValue));
        }

        public static bool TryReadHstringBody(scoped ref Ndr20Reader Reader, out ReadOnlySpan<char> Value)
        {
            Value = default;
            Reader.Align(8);
            if (!Reader.TryReadUInt32(out uint Marker) || Marker != WdtRemoteCall || !Reader.TryReadUInt32(out uint Length) || (Length & 1) != 0
                || !Reader.TryReadBytes((int)Math.Min(Length, int.MaxValue), out ReadOnlySpan<byte> Chars))
                return false;

            Value = MemoryMarshal.Cast<byte, char>(Chars);
            return true;
        }

        public static void WriteResponseHeader(ref Ndr20Writer Writer)
        {
            Writer.WriteUInt32(OrpcfLocal);
            Writer.WriteUInt32(0);
            WriteEmptyLocalThat(ref Writer);
        }

        public static void WriteEmptyLocalThat(ref Ndr20Writer Writer) => Writer.WriteZeros(LocalThatSize);

        // An OBJREF_STANDARD that names no resolver bindings, as every OBJREF between processes of one machine does.
        // ObjRef must be zero on entry.
        public static void WriteStandardObjRef(Span<byte> ObjRef, Guid Iid, in StdObjRef Std)
        {
            WriteObjRefHeader(ObjRef, ObjRefStandard, Iid);
            Std.Write(ObjRef.Slice(ObjRefHeaderSize));
        }

        // ObjRef must be zero on entry.
        public static void WriteHandlerObjRef(Span<byte> ObjRef, Guid Iid, in StdObjRef Std, Guid Handler)
        {
            WriteObjRefHeader(ObjRef, ObjRefHandler, Iid);
            Std.Write(ObjRef.Slice(ObjRefHeaderSize));
            Handler.TryWriteBytes(ObjRef.Slice(ObjRefHeaderSize + StdObjRef.Size, InterfaceIdSize));
        }

        public static void WriteInterfacePointerData(ref Ndr20Writer Writer, ReadOnlySpan<byte> Data)
        {
            Writer.WriteUInt32((uint)Data.Length);
            Writer.WriteUInt32((uint)Data.Length);
            Writer.WriteBytes(Data);
            Writer.AlignTo(4);
        }

        // Size is the value the header declares, which can differ from the length of Data.
        public static void WriteCustomObjRef(ref Ndr20Writer Writer, Guid Iid, Guid Clsid, uint Size, ReadOnlySpan<byte> Data)
        {
            Span<byte> Header = Writer.Take(CustomObjRefHeaderSize);
            WriteObjRefHeader(Header, ObjRefCustom, Iid);
            Clsid.TryWriteBytes(Header.Slice(OffCustomClsid, 16));
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(OffCustomSize), Size);
            Writer.WriteBytes(Data);
        }

        public static void WriteCustomInterfacePointer(ref Ndr20Writer Writer, Guid Iid, Guid Clsid, uint Size, ReadOnlySpan<byte> Data)
        {
            uint Length = (uint)(CustomObjRefHeaderSize + Data.Length);
            Writer.WriteUInt32(Length);
            Writer.WriteUInt32(Length);
            WriteCustomObjRef(ref Writer, Iid, Clsid, Size, Data);
            Writer.AlignTo(4);
        }

        public static bool TryGetCustomObjRefData(ReadOnlySpan<byte> ObjRef, out ReadOnlySpan<byte> Data)
        {
            Data = default;
            if (!IsObjRef(ObjRef, ObjRefCustom, CustomObjRefHeaderSize) || BinaryPrimitives.ReadUInt32LittleEndian(ObjRef.Slice(OffCustomExtension)) != 0)
                return false;

            Data = ObjRef.Slice(CustomObjRefHeaderSize);
            return true;
        }

        public static bool TryReadStandardObjRef(ReadOnlySpan<byte> ObjRef, out StdObjRef Std)
        {
            Std = default;
            if (!IsObjRef(ObjRef, ObjRefStandard, ObjRefHeaderSize + StdObjRef.Size + EmptyDualStringArraySize))
                return false;

            Std = StdObjRef.Read(ObjRef.Slice(ObjRefHeaderSize));
            return true;
        }

        private static void WriteObjRefHeader(Span<byte> ObjRef, uint Kind, Guid Iid)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(ObjRef, ObjRefSignature);
            BinaryPrimitives.WriteUInt32LittleEndian(ObjRef.Slice(4), Kind);
            Iid.TryWriteBytes(ObjRef.Slice(OffObjRefIid, 16));
        }

        private static bool IsObjRef(ReadOnlySpan<byte> ObjRef, uint Kind, int MinLength)
        {
            return ObjRef.Length >= MinLength && BinaryPrimitives.ReadUInt32LittleEndian(ObjRef) == ObjRefSignature
                && BinaryPrimitives.ReadUInt32LittleEndian(ObjRef.Slice(4)) == Kind;
        }

        public static bool TryReadUniqueInterfacePointer(scoped ref Ndr20Reader Reader, out ReadOnlySpan<byte> ObjRef)
        {
            ObjRef = default;
            if (!Reader.TryReadUInt32(out uint Referent))
                return false;

            if (Referent == 0)
                return true;

            if (!Reader.TryReadUInt32(out uint Length) || !Reader.TryReadUInt32(out uint Conformance) || Length != Conformance)
                return false;

            return Reader.TryReadBytes((int)Math.Min(Length, int.MaxValue), out ObjRef);
        }
    }
}
