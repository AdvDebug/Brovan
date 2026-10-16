using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The RPCSS object resolver on the endpoint mapper port.
    internal static class RpcssPortHandler
    {
        public const string PortName = "\\RPC Control\\epmapper";

        private static readonly Guid LocalObjectExporter = new Guid("e60c73e6-88f9-11cf-9af1-0020af6e72f4");
        private static readonly Guid Scm = new Guid("412f241e-c12a-11ce-abff-0020af6e7a17");
        private static readonly Guid ScmLocalActivator = new Guid("00000136-0000-0000-c000-000000000046");
        private static readonly Guid ErrorExtension = new Guid("0000031c-0000-0000-c000-000000000046");
        private static readonly Guid RestrictedErrorObject = new Guid("00000352-0000-0000-c000-000000000046");
        private static readonly Guid ActivationPropertiesOut = new Guid("00000339-0000-0000-c000-000000000046");
        private static readonly Guid ActivationPropertiesOutInterface = new Guid("000001a3-0000-0000-c000-000000000046");
        private static readonly Guid InstantiationInfo = new Guid("000001ab-0000-0000-c000-000000000046");
        private static readonly Guid ScmReplyInfo = new Guid("000001b6-0000-0000-c000-000000000046");
        private static readonly Guid[] ServedInterfaces = { LocalObjectExporter, Scm, ScmLocalActivator };

        // Opnums from this build's combase lclor and scm format strings.
        private const uint ProcConnect = 0;
        private const uint ProcAllocateReservedIds = 3;
        private const uint ProcBulkUpdateOIDs = 4;
        private const uint ProcServerAllocateOXIDAndOIDs = 6;
        private const uint ProcServerFreeOXIDAndOIDs = 8;
        private const uint ProcDisconnect = 10;
        private const uint ProcRegisterWindowPropInterface = 6;
        private const uint ProcGetWindowPropInterface = 7;
        private const uint ProcNotifyDragDropStartOrStop = 13;
        private const uint ProcGetClassObject = 3;
        private const uint ProcCreateInstance = 4;

        private const int ProxyDecodeInfoSize = 96;
        private const int PingPeriodSeconds = 120;
        private const uint ScmProcessId = 0x3F8;
        private const uint AuthnLevelConnect = 2;
        private const uint ImpLevelIdentify = 2;
        private const int SecurityDescriptorCount = 5;
        private const uint MaximumIds = 0x100000;

        // NDR carries __int3264 in four bytes.
        private const int HwndOffset = Ndr20Writer.ContextHandleSize;
        private const int StdObjRefOffset = HwndOffset + 4;
        private const int RevokeOffset = HwndOffset + 8;

        private const uint OrOk = 0;
        private const uint OrBadOxid = 1910;
        private const int FreeOxidOffset = 24;

        private const uint RegdbEClassNotReg = 0x80040154;

        private const int SerializationHeaderSize = 0x10;
        private const int ActivationBlobPrefixSize = 8;
        private const ulong SerializationCommonHeader = 0xCCCCCCCC00081001;
        private const uint MaxActivationProperties = 10;

        // The package name, the user SID and the AppContainer SID of an OXID_INFO.
        private const int OxidInfoHstringCount = 3;
        private const string LocalBindingPrefix = "ncalrpc:[";

        private const uint MultithreadedApartmentTid = 0xFFFFFFFF;
        private const uint ContainerVersion = 3;
        private const uint OxidInfoFlags = 0x02000000;
        private const ushort AuthnWinNt = 10;
        private const ushort AuthzNone = 0xFFFF;

        // rpcss sends the system message text as the error description.
        private const string ClassNotRegisteredText = "Class not registered\r\n";
        private static readonly byte[] ClassNotRegisteredReply = BuildActivationFailure(RegdbEClassNotReg, ClassNotRegisteredText);
        private static readonly byte[] EveryoneDescriptor = BuildEveryoneDescriptor();

        private static readonly Dictionary<uint, byte[]> WindowProps = new Dictionary<uint, byte[]>();
        private static readonly Guid ResolverHandle = Guid.NewGuid();
        private static readonly Guid ProcessIdentifier = Guid.NewGuid();
        private static readonly ulong ProcessSignature = Orpc.NewId();
        private static readonly ulong LocalMachineId = Orpc.NewId();

        internal readonly record struct ServerOxid(string Endpoint, Guid RemUnknownIpid);

        private static readonly Dictionary<ulong, ServerOxid> ServerOxids = new Dictionary<ulong, ServerOxid>();
        private static ulong NextId = 0x1000;
        private static uint NextCookie = 1;

        public static bool TryHandle(WinPort Port, PortReply Served, in LrpcMessage Message, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;

            if (Port == null || !string.Equals(Port.Name, PortName, StringComparison.OrdinalIgnoreCase))
                return false;

            if (Message.Type == LrpcMessageType.Bind)
                return LrpcBindings.TryAccept(Served.Client, Message, ServedInterfaces, out _, out Reply);

            if (Message.Type != LrpcMessageType.Request || !LrpcBindings.TryResolve(Served.Client, Message, out Guid Target, out _))
                return false;

            if (Target == ScmLocalActivator)
            {
                Reply = HandleScmLocalActivator(Message, Instance);
                return Reply != null;
            }

            byte[] Stub = null;
            if (Target == LocalObjectExporter)
                Stub = HandleLocalObjectExporter(Message.ProcNumber, Message.StubData, Instance.WinHelper.PID);
            else if (Target == Scm)
                Stub = HandleScm(Message.ProcNumber, Message.StubData);

            if (Stub == null)
                return false;

            Reply = LrpcPacket.BuildResponse(Message, Stub);
            return true;
        }

        private static byte[] HandleLocalObjectExporter(uint ProcNumber, ReadOnlySpan<byte> Stub, uint ProcessId)
        {
            switch (ProcNumber)
            {
                case ProcConnect:
                    return Connect(Stub, ProcessId);

                case ProcAllocateReservedIds:
                    return AllocateReservedIds(Stub);

                case ProcBulkUpdateOIDs:
                    return BulkUpdateOIDs(Stub);

                case ProcServerAllocateOXIDAndOIDs:
                    return ServerAllocateOXIDAndOIDs(Stub);

                case ProcServerFreeOXIDAndOIDs:
                    return ServerFreeOXIDAndOIDs(Stub);

                case ProcDisconnect:
                    return Disconnect();
            }

            return null;
        }

        private static byte[] HandleScm(uint ProcNumber, ReadOnlySpan<byte> Stub)
        {
            switch (ProcNumber)
            {
                case ProcRegisterWindowPropInterface:
                    return RegisterWindowPropInterface(Stub);

                case ProcGetWindowPropInterface:
                    return GetWindowPropInterface(Stub);

                case ProcNotifyDragDropStartOrStop:
                    return BuildStatusAndResult(OrOk, 0);
            }

            return null;
        }

        private static byte[] HandleScmLocalActivator(in LrpcMessage Message, BinaryEmulator Instance)
        {
            uint ProcNumber = Message.ProcNumber;
            if (ProcNumber != ProcGetClassObject && ProcNumber != ProcCreateInstance)
                return null;

            if (!TryReadActivationRequest(Message.StubData, ProcNumber == ProcCreateInstance, out Guid Class, out ReadOnlySpan<byte> Interfaces))
                return null;

            if (Class == ActivationManagerPortHandler.RegistrarClass)
            {
                if (ProcNumber == ProcCreateInstance)
                    return BuildActivationReply(Message, Instance, Interfaces);

                Utils.LogError("[-] RPCSS: the class object of the ActivatableApplicationRegistrar is not served.");
            }

            return LrpcPacket.BuildResponse(Message, ClassNotRegisteredReply);
        }

        private static bool TryReadActivationRequest(ReadOnlySpan<byte> Stub, bool HasOuter, out Guid Class, out ReadOnlySpan<byte> Interfaces)
        {
            Class = Guid.Empty;
            Interfaces = default;
            if (!Orpc.TryGetRequestParameters(Stub, out int Offset))
                return false;

            Ndr20Reader Reader = new Ndr20Reader(Stub.Slice(Offset));
            if (HasOuter && (!Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> Outer) || !Outer.IsEmpty))
                return false;

            // dwSize and a reserved DWORD, then the serialized CustomHeader and the properties it lists.
            if (!Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> ObjRef) || !Orpc.TryGetCustomObjRefData(ObjRef, out ReadOnlySpan<byte> Blob))
                return false;

            if (Blob.Length < ActivationBlobPrefixSize + SerializationHeaderSize)
                return false;

            Ndr20Reader Header = new Ndr20Reader(Blob.Slice(ActivationBlobPrefixSize + SerializationHeaderSize));
            if (!Header.TryReadUInt32(out _) || !Header.TryReadUInt32(out uint HeaderSize) || !Header.TrySkip(8) || !Header.TryReadUInt32(out uint Count)
                || !Header.TrySkip(16) || !Header.TryReadUInt32(out uint ClassesReferent) || !Header.TryReadUInt32(out uint SizesReferent) || !Header.TryReadUInt32(out _))
                return false;

            if (Count == 0 || Count > MaxActivationProperties || ClassesReferent == 0 || SizesReferent == 0 || HeaderSize > Blob.Length - ActivationBlobPrefixSize)
                return false;

            if (!Header.TryReadUInt32(out uint ClassCount) || ClassCount != Count)
                return false;

            int InfoIndex = -1;
            for (int i = 0; i < Count; i++)
            {
                if (!Header.TryReadGuid(out Guid PropertyClass))
                    return false;
                if (InfoIndex < 0 && PropertyClass == InstantiationInfo)
                    InfoIndex = i;
            }

            if (InfoIndex < 0 || !Header.TryReadUInt32(out uint SizeCount) || SizeCount != Count)
                return false;

            int Position = ActivationBlobPrefixSize + (int)HeaderSize;
            ReadOnlySpan<byte> Property = default;
            for (int i = 0; i < Count; i++)
            {
                if (!Header.TryReadUInt32(out uint Size))
                    return false;
                if (i > InfoIndex)
                    continue;
                if (Size > (uint)(Blob.Length - Position))
                    return false;

                if (i == InfoIndex)
                    Property = Blob.Slice(Position, (int)Size);
                Position += (int)Size;
            }

            if (Property.Length < SerializationHeaderSize)
                return false;

            Ndr20Reader Info = new Ndr20Reader(Property.Slice(SerializationHeaderSize));
            if (!Info.TryReadGuid(out Class) || !Info.TrySkip(12) || !Info.TryReadUInt32(out uint InterfaceCount) || !Info.TrySkip(4)
                || !Info.TryReadUInt32(out uint InterfacesReferent) || !Info.TrySkip(8) || !Info.TryReadUInt32(out uint InterfaceConformance))
                return false;

            if (InterfaceCount == 0 || InterfaceCount > Orpc.MaxRequestedInterfaces || InterfaceCount > (uint)Property.Length / Orpc.InterfaceIdSize
                || InterfacesReferent == 0 || InterfaceConformance != InterfaceCount)
                return false;

            return Info.TryReadBytes((int)InterfaceCount * Orpc.InterfaceIdSize, out Interfaces);
        }

        private static byte[] BuildActivationReply(in LrpcMessage Message, BinaryEmulator Instance, ReadOnlySpan<byte> Interfaces)
        {
            // Each interface takes at least 24 bytes of PropsOutInfo, so a long list needs a view and can only fault.
            int Count = Interfaces.Length / Orpc.InterfaceIdSize;
            if (Count > LrpcPacket.MaxResponseStubLength / (Orpc.InterfaceIdSize + 2 * sizeof(uint)))
            {
                Utils.LogError($"[-] RPCSS: an activation reply for {Count} interfaces needs a view, which is not supported.");
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSCannotSupport);
            }

            byte[] Properties = BuildActivationPropertiesOut(Instance, Interfaces);
            Ndr20Writer Writer = new Ndr20Writer(0xB0 + Properties.Length);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUniqueReferent();
            Orpc.WriteCustomInterfacePointer(ref Writer, ActivationPropertiesOutInterface, ActivationPropertiesOut, (uint)Properties.Length, Properties);
            Writer.WriteUInt32(Orpc.SOk);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private static byte[] BuildActivationPropertiesOut(BinaryEmulator Instance, ReadOnlySpan<byte> Interfaces)
        {
            const uint PropertyCount = 2;
            byte[] PropsOut = Serialize(BuildPropsOutInfo(Instance, Interfaces).Written);
            byte[] ScmReply = Serialize(BuildScmReplyInfo(Instance).Written);

            Ndr20Writer Writer = new Ndr20Writer(0x60);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteGuid(Guid.Empty);
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteGuid(ActivationPropertiesOut);
            Writer.WriteGuid(ScmReplyInfo);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteUInt32((uint)PropsOut.Length);
            Writer.WriteUInt32((uint)ScmReply.Length);
            byte[] Header = Serialize(Writer.Written);

            uint TotalSize = (uint)(Header.Length + PropsOut.Length + ScmReply.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.AsSpan(SerializationHeaderSize), TotalSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.AsSpan(SerializationHeaderSize + 4), (uint)Header.Length);

            byte[] Blob = new byte[ActivationBlobPrefixSize + TotalSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Blob, TotalSize);
            Header.CopyTo(Blob, ActivationBlobPrefixSize);
            PropsOut.CopyTo(Blob, ActivationBlobPrefixSize + Header.Length);
            ScmReply.CopyTo(Blob, ActivationBlobPrefixSize + Header.Length + PropsOut.Length);
            return Blob;
        }

        // BuildActivationReply bounds the interface count, so the stackalloc stays small.
        private static Ndr20Writer BuildPropsOutInfo(BinaryEmulator Instance, ReadOnlySpan<byte> Interfaces)
        {
            int Count = Interfaces.Length / Orpc.InterfaceIdSize;
            Span<bool> Supported = stackalloc bool[Count];
            for (int i = 0; i < Count; i++)
                Supported[i] = ActivationManagerPortHandler.IsRegistrarInterface(InterfaceAt(Interfaces, i));

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * 0x70);
            Writer.WriteUInt32((uint)Count);
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32((uint)Count);
            Writer.WriteBytes(Interfaces);

            Writer.WriteUInt32((uint)Count);
            foreach (bool Found in Supported)
                Writer.WriteUInt32(Found ? Orpc.SOk : Orpc.ENoInterface);

            Writer.WriteUInt32((uint)Count);
            foreach (bool Found in Supported)
            {
                if (Found)
                    Writer.WriteUniqueReferent();
                else
                    Writer.WriteUInt32(0);
            }

            for (int i = 0; i < Count; i++)
            {
                if (!Supported[i])
                    continue;

                Guid Interface = InterfaceAt(Interfaces, i);
                Orpc.WriteStandardInterfacePointer(ref Writer, Interface, ActivationManagerPortHandler.GetRegistrar(Instance, Interface));
            }

            return Writer;
        }

        private static Guid InterfaceAt(ReadOnlySpan<byte> Interfaces, int Index) => new Guid(Interfaces.Slice(Index * Orpc.InterfaceIdSize, Orpc.InterfaceIdSize));

        // _PRIV_RESOLVER_INFO carries the server's OXID_INFO, so the client never asks the resolver.
        private static Ndr20Writer BuildScmReplyInfo(BinaryEmulator Instance)
        {
            Guid RemUnknownIpid = ActivationManagerPortHandler.GetRemUnknownIpid(Instance);
            ulong Oxid = ActivationManagerPortHandler.Oxid;

            Ndr20Writer Writer = new Ndr20Writer(0x180);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);
            Writer.WriteUInt64(Oxid);
            Writer.WriteUInt32(0);

            Writer.AlignTo(8);
            Writer.WriteUInt32(MultithreadedApartmentTid);
            Writer.WriteUInt32(Instance.WinHelper.ShellProcess.PID);
            Writer.WriteUInt32(AuthnLevelConnect);
            Writer.WriteUInt16(Orpc.ComVersionMajor);
            Writer.WriteUInt16(Orpc.ComVersionMinor);
            Writer.WriteUInt32(ContainerVersion);
            Writer.WriteUInt64(0);
            Writer.WriteUInt32(0);
            Writer.WriteGuid(RemUnknownIpid);
            Writer.WriteUInt32(OxidInfoFlags);
            Writer.WriteUniqueReferent();
            Writer.WriteGuid(ActivationManagerPortHandler.ProcessIdentifier);
            Writer.WriteUInt64(0);
            Writer.WriteUInt32(0);
            for (int i = 0; i < OxidInfoHstringCount; i++)
                Writer.WriteUInt32(Orpc.UserMarshalMarker);
            Writer.WriteUInt64(Oxid);
            Writer.WriteGuid(RemUnknownIpid);
            Writer.WriteUInt64(LocalMachineId);
            Writer.WriteUInt32(0);

            WriteResolverBindings(ref Writer, ActivationManagerPortHandler.Endpoint, ActivationManagerPortHandler.GetPrincipal(Instance));

            for (int i = 0; i < OxidInfoHstringCount; i++)
                Orpc.WriteHstringBody(ref Writer, default);

            return Writer;
        }

        // Local OXIDs use protseq:[endpoint] bindings without tower ids.
        private static void WriteResolverBindings(ref Ndr20Writer Writer, string Endpoint, string Principal)
        {
            const int ListTerminators = 2;
            const int SecurityServices = 2;
            int SecurityOffset = LocalBindingPrefix.Length + Endpoint.Length + "]".Length + ListTerminators;
            int Entries = SecurityOffset + SecurityServices + Principal.Length + ListTerminators;
            Writer.WriteUInt32((uint)Entries);
            Writer.WriteUInt16((ushort)Entries);
            Writer.WriteUInt16((ushort)SecurityOffset);
            Writer.WriteUtf16(LocalBindingPrefix);
            Writer.WriteUtf16(Endpoint);
            Writer.WriteUInt16(']');
            Writer.WriteUInt16(0);
            Writer.WriteUInt16(0);

            Writer.WriteUInt16(AuthnWinNt);
            Writer.WriteUInt16(AuthzNone);
            Writer.WriteUtf16(Principal);
            Writer.WriteUInt16(0);
            Writer.WriteUInt16(0);
        }

        // The NDR type serialization header is version 1, little endian, 8 bytes, then the padded data length.
        private static byte[] Serialize(ReadOnlySpan<byte> Data)
        {
            int Padded = (Data.Length + 7) & ~7;
            byte[] Result = new byte[SerializationHeaderSize + Padded];
            BinaryPrimitives.WriteUInt64LittleEndian(Result, SerializationCommonHeader);
            BinaryPrimitives.WriteUInt32LittleEndian(Result.AsSpan(8), (uint)Padded);
            Data.CopyTo(Result.AsSpan(SerializationHeaderSize));
            return Result;
        }

        // combase turns the error extent of the ORPCTHAT into the thread's error info.
        private static byte[] BuildActivationFailure(uint Result, string Description)
        {
            const uint ExtentCount = 1;
            byte[] ErrorData = BuildRestrictedErrorData(Result, Description);
            int ExtentSize = Orpc.CustomObjRefHeaderSize + ErrorData.Length;

            Ndr20Writer Writer = new Ndr20Writer(0x80 + ExtentSize);
            Writer.WriteUInt32(Orpc.OrpcfLocal);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(ExtentCount);
            Writer.WriteUInt32(0);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32((ExtentCount + 1) & ~1u);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);

            Writer.WriteUInt32(((uint)ExtentSize + 7) & ~7u);
            Writer.WriteGuid(ErrorExtension);
            Writer.WriteUInt32((uint)ExtentSize);
            Orpc.WriteCustomObjRef(ref Writer, Orpc.IUnknownId, RestrictedErrorObject, (uint)ErrorData.Length, ErrorData);
            Writer.AlignTo(8);

            Orpc.WriteEmptyLocalThat(ref Writer);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        // The marshal data combase's CRestrictedError::UnmarshalInterface reads.
        private static byte[] BuildRestrictedErrorData(uint Result, string Description)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x40 + Description.Length * sizeof(char) * 2);
            Writer.WriteUInt32(Result);
            for (int i = 0; i < 2; i++)
            {
                Writer.WriteUtf16(Description);
                Writer.WriteUInt16(0);
            }

            // The capability SID, signature, process name and stack text are empty, and each is a 4-byte length and a NUL.
            Writer.WriteZeros(4 * 6);

            // There is no section name and no section, and the originating process id follows.
            Writer.WriteZeros(4);
            Writer.WriteUInt32(ScmProcessId);

            // The optional error parts that follow are all absent.
            Writer.WriteZeros(20);
            return Writer.ToArray();
        }

        private static byte[] Connect(ReadOnlySpan<byte> Stub, uint ProcessId)
        {
            if (!TryReadConnectIdCount(Stub, out uint IdCount))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(512);

            Writer.WriteContextHandle(ResolverHandle);
            Writer.WriteUInt32(PingPeriodSeconds);

            Writer.WriteUniqueReferent();
            WriteEmptyDualStringArray(ref Writer);

            Writer.WriteUInt64(LocalMachineId);

            Writer.AlignTo(4);
            Writer.WriteUInt32(IdCount);
            Writer.AlignTo(8);
            for (uint i = 0; i < IdCount; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(IdCount);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(AuthnLevelConnect);
            Writer.WriteUInt32(ImpLevelIdentify);

            // No security packages and no channel hooks: a zero count and a null list each.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);

            Writer.WriteUInt32(ProcessId);
            Writer.WriteUInt32(ScmProcessId);
            Writer.WriteUInt64(ProcessSignature);

            Span<byte> Identifier = stackalloc byte[16];
            ProcessIdentifier.TryWriteBytes(Identifier);
            Writer.AlignTo(4);
            Writer.WriteBytes(Identifier);

            uint DescriptorsSize = (uint)(EveryoneDescriptor.Length * SecurityDescriptorCount);
            for (int i = 0; i < SecurityDescriptorCount; i++)
                Writer.WriteUInt32((uint)EveryoneDescriptor.Length);

            Writer.WriteUInt32(DescriptorsSize);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(DescriptorsSize);
            for (int i = 0; i < SecurityDescriptorCount; i++)
                Writer.WriteBytes(EveryoneDescriptor);

            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        // The id array is sized by the in parameter that follows two strings and the proxy decode block.
        private static bool TryReadConnectIdCount(ReadOnlySpan<byte> Stub, out uint IdCount)
        {
            IdCount = 0;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadUniqueWideString(out _) || !Reader.TryReadUniqueWideString(out _))
                return false;

            if (!Reader.TryReadUInt32(out uint DecodeInfoReferent))
                return false;

            if (DecodeInfoReferent != 0)
            {
                Reader.Align(8);
                if (!Reader.TrySkip(ProxyDecodeInfoSize))
                    return false;
            }

            if (!Reader.TryReadUInt32(out _) || !Reader.TryReadUInt16(out _))
                return false;

            Reader.Align(4);
            if (!Reader.TryReadUInt32(out IdCount))
                return false;

            return IdCount <= MaximumIds;
        }

        private static bool TryReadIdCount(ReadOnlySpan<byte> Stub, out uint Count)
        {
            Count = 0;

            if (Stub.Length < Ndr20Writer.ContextHandleSize + 4)
                return false;

            Count = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Ndr20Writer.ContextHandleSize, 4));
            return Count <= MaximumIds;
        }

        private static byte[] AllocateReservedIds(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(32 + (int)Count * 8);
            Writer.WriteUInt32(Count);
            Writer.AlignTo(8);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] BulkUpdateOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(16 + (int)Count * 4);
            Writer.WriteUInt32(Count);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt32(OrOk);

            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] ServerAllocateOXIDAndOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            if (!TryReadServerOxid(Stub, out ServerOxid Server))
                Utils.LogError("[-] RPCSS: the OXID_INFO of a server apartment could not be read; its endpoint is unknown.");

            Ndr20Writer Writer = new Ndr20Writer(64 + (int)Count * 8);
            ulong Oxid = NextId++;
            ServerOxids[Oxid] = Server;
            Writer.WriteUInt64(Oxid);
            Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Count);
            Writer.AlignTo(8);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt64(0);

            // No new resolver bindings.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static bool TryReadServerOxid(ReadOnlySpan<byte> Stub, out ServerOxid Server)
        {
            const int OxidInfoFixedSize = 0x80;
            Server = default;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt32(out _))
                return false;

            Reader.Align(8);
            if (!Reader.TryReadBytes(OxidInfoFixedSize, out ReadOnlySpan<byte> Info))
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(0x20)) != 0)
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(0x38)) != 0 && !TryReadDualStringArray(ref Reader, out _, out _))
                return false;

            for (int i = 0; i < OxidInfoHstringCount; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(0x5C + i * 4)) != 0 && !Orpc.TrySkipHstringBody(ref Reader))
                    return false;
            }

            if (!TryReadDualStringArray(ref Reader, out ReadOnlySpan<byte> Strings, out ushort SecurityOffset) || SecurityOffset * 2 > Strings.Length)
                return false;

            string Endpoint = FindLocalEndpoint(MemoryMarshal.Cast<byte, char>(Strings.Slice(0, SecurityOffset * 2)));
            if (Endpoint == null)
                return false;

            Server = new ServerOxid(Endpoint, new Guid(Info.Slice(0x24, 16)));
            return true;
        }

        private static bool TryReadDualStringArray(ref Ndr20Reader Reader, out ReadOnlySpan<byte> Strings, out ushort SecurityOffset)
        {
            Strings = default;
            SecurityOffset = 0;
            return Reader.TryReadUInt32(out uint Conformance) && Reader.TryReadUInt16(out ushort Entries) && Reader.TryReadUInt16(out SecurityOffset)
                && Conformance == Entries && Reader.TryReadBytes(Entries * 2, out Strings);
        }

        private static string FindLocalEndpoint(ReadOnlySpan<char> Strings)
        {
            while (!Strings.IsEmpty)
            {
                int Terminator = Strings.IndexOf('\0');
                ReadOnlySpan<char> Binding = Terminator < 0 ? Strings : Strings.Slice(0, Terminator);
                Strings = Terminator < 0 ? default : Strings.Slice(Terminator + 1);
                if (!Binding.StartsWith(LocalBindingPrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                int End = Binding.Slice(LocalBindingPrefix.Length).IndexOfAny(']', ',');
                if (End > 0)
                    return new string(Binding.Slice(LocalBindingPrefix.Length, End));
            }

            return null;
        }

        public static bool TryGetServerOxid(ulong Oxid, out ServerOxid Server)
        {
            return ServerOxids.TryGetValue(Oxid, out Server) && Server.Endpoint != null;
        }

        // The STDOBJREF and OXID_INFO go back as marshalled. They are eight byte aligned both ways.
        private static byte[] RegisterWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < StdObjRefOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            WindowProps[Hwnd] = Stub.Slice(StdObjRefOffset, Stub.Length - 4 - StdObjRefOffset).ToArray();

            Ndr20Writer Writer = new Ndr20Writer(24);
            Writer.WriteUInt32(NextCookie++);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        private static byte[] GetWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < RevokeOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            bool Revoke = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(RevokeOffset, 4)) != 0;

            if (!WindowProps.TryGetValue(Hwnd, out byte[] Registration))
                return null;

            if (Revoke)
                WindowProps.Remove(Hwnd);

            Ndr20Writer Writer = new Ndr20Writer(Registration.Length + 16);
            Writer.WriteBytes(Registration);
            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        // The resolver keeps no state for OIDs, so the array after the OXID is not read.
        private static byte[] ServerFreeOXIDAndOIDs(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < FreeOxidOffset + sizeof(ulong))
                return null;

            ulong Oxid = BinaryPrimitives.ReadUInt64LittleEndian(Stub.Slice(FreeOxidOffset, sizeof(ulong)));
            return BuildStatus(ServerOxids.Remove(Oxid) ? OrOk : OrBadOxid);
        }

        // rpcss runs down the process context, which frees every OXID it registered, and returns a NULL handle.
        private static byte[] Disconnect()
        {
            ServerOxids.Clear();

            Ndr20Writer Writer = new Ndr20Writer(Ndr20Writer.ContextHandleSize + 4);
            Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] BuildStatus(uint Status)
        {
            Ndr20Writer Writer = new Ndr20Writer(4);
            Writer.WriteUInt32(Status);
            return Writer.ToArray();
        }

        private static byte[] BuildStatusAndResult(uint Status, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(8);
            Writer.WriteUInt32(Status);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        // Empty DUALSTRINGARRAY: each list is only its terminator.
        private static void WriteEmptyDualStringArray(ref Ndr20Writer Writer)
        {
            const ushort Entries = 4;
            const ushort SecurityOffset = 2;

            Writer.WriteUInt32(Entries);
            Writer.WriteUInt16(Entries);
            Writer.WriteUInt16(SecurityOffset);
            for (int i = 0; i < Entries; i++)
                Writer.WriteUInt16(0);

            Writer.AlignTo(4);
        }

        // combase refuses a descriptor without an owner and a group.
        private static byte[] BuildEveryoneDescriptor()
        {
            const uint ComRightsExecuteAll = 0x1F;
            byte[] Administrators = NtQueryInformationToken.AdministratorsSid;
            byte[] Everyone = NtQueryInformationToken.EveryoneSid;
            int AceSize = NtAccessCheck.AceSidOffset + Everyone.Length;
            int DaclSize = NtAccessCheck.AclHeaderSize + AceSize;
            int OwnerOffset = NtAccessCheck.SelfRelativeHeaderSize;
            int GroupOffset = OwnerOffset + Administrators.Length;
            int DaclOffset = GroupOffset + Administrators.Length;

            byte[] Buffer = new byte[DaclOffset + DaclSize];
            Span<byte> Span = Buffer;

            NtAccessCheck.WriteSelfRelativeHeader(Span, NtAccessCheck.SeDaclPresent, OwnerOffset, GroupOffset, DaclOffset);
            Administrators.CopyTo(Span.Slice(OwnerOffset));
            Administrators.CopyTo(Span.Slice(GroupOffset));

            Span<byte> Acl = Span.Slice(DaclOffset);
            Acl[0] = NtAccessCheck.AclRevision;
            BinaryPrimitives.WriteUInt16LittleEndian(Acl.Slice(2, 2), (ushort)DaclSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Acl.Slice(4, 2), 1);

            Span<byte> Ace = Acl.Slice(NtAccessCheck.AclHeaderSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Ace.Slice(2, 2), (ushort)AceSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Ace.Slice(4, 4), ComRightsExecuteAll);

            Everyone.CopyTo(Ace.Slice(NtAccessCheck.AceSidOffset));
            return Buffer;
        }
    }
}
