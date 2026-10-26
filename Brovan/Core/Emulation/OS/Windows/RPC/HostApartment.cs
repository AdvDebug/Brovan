using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    internal abstract class HostObject
    {
        // The flags combase gives an object of a free-threaded apartment with agile proxies.
        internal const uint ObjectFlags = 0xE80;
        internal const uint PublicRefs = 5;

        internal ulong Oid { get; } = Orpc.NewId();

        internal virtual bool Permanent => false;

        // Implementations also answer true for IUnknown.
        internal abstract bool Supports(Guid Interface);

        // False for a method the object does not serve, and a null Stub when the parameters do not match the method.
        internal abstract bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub);

        internal virtual Guid? HandlerClass => null;

        internal virtual Guid UnmarshalClass => Orpc.StandardMarshal;

        internal int StandardObjRefSize => HandlerClass == null ? Orpc.StandardObjRefSize : Orpc.HandlerObjRefSize;

        internal void WriteStandardObjRef(Span<byte> ObjRef, Guid Interface, in StdObjRef Std)
        {
            if (HandlerClass is Guid Handler)
                Orpc.WriteHandlerObjRef(ObjRef, Interface, Std, Handler);
            else
                Orpc.WriteStandardObjRef(ObjRef, Interface, Std);
        }

        internal byte[] GetStandardObjRef(Guid Interface, in StdObjRef Std)
        {
            byte[] ObjRef = new byte[StandardObjRefSize];
            WriteStandardObjRef(ObjRef, Interface, Std);
            return ObjRef;
        }

        internal virtual byte[] GetMarshalData(Guid Interface, in StdObjRef Std) => GetStandardObjRef(Interface, Std);

        // NT asks the object for IMarshal only when it aggregates the standard marshaler (CStdIdentity::QueryInterface).
        internal byte[] GetIdentityMarshalData(Guid Interface, in StdObjRef Std) =>
            UnmarshalClass == Orpc.AggregatedStandardMarshal ? GetMarshalData(Interface, Std) : GetStandardObjRef(Interface, Std);

        internal void WriteInterfacePointer(ref Ndr20Writer Writer, Guid Interface, in StdObjRef Std)
        {
            if (UnmarshalClass == Orpc.StandardMarshal)
            {
                Orpc.WriteInterfacePointerData(ref Writer, GetStandardObjRef(Interface, Std));
                return;
            }

            byte[] Data = GetMarshalData(Interface, Std);
            Orpc.WriteCustomInterfacePointer(ref Writer, Interface, UnmarshalClass, (uint)Data.Length, Data);
        }

        protected static byte[] BuildResult(uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        internal static readonly byte[] SuccessResult = BuildResult(Orpc.SOk);

        protected static uint WriteOutInterface(ref Ndr20Writer Writer, HostCall Call, HostObject Object, Guid Interface)
        {
            Writer.AlignTo(4);
            StdObjRef Std = default;
            uint Result = Object == null ? Orpc.SOk : Call.Query(Object, Interface, PublicRefs, out Std);
            if (Object == null || Result != Orpc.SOk)
            {
                Writer.WriteUInt32(0);
                return Result;
            }

            Writer.WriteUniqueReferent();
            Object.WriteInterfacePointer(ref Writer, Interface, Std);
            return Orpc.SOk;
        }
    }

    // What a call exports joins the apartment only with a reply that is sent.
    internal sealed class HostCall
    {
        internal readonly record struct Export(HostObject Object, Guid Interface, Guid Ipid, uint Refs);

        internal HostApartment Apartment { get; }
        internal BinaryEmulator Instance { get; }
        internal List<Export> Exports { get; } = new List<Export>();

        internal HostCall(HostApartment Apartment, BinaryEmulator Instance)
        {
            this.Apartment = Apartment;
            this.Instance = Instance;
        }

        internal uint Query(HostObject Object, Guid Interface, uint Refs, out StdObjRef Std)
        {
            Std = default;
            if (!Object.Supports(Interface))
                return Orpc.ENoInterface;

            return Apartment.TryExport(this, Object, Interface, Refs, out Std) ? Orpc.SOk : Orpc.EOutOfMemory;
        }
    }

    // Its handlers run in the client's syscall, under KernelLock.
    internal sealed class HostApartment : AlpcHostServer
    {
        private const ushort MultithreadedApartment = 0xFFFF;
        private const int RemUnknownIpidSequence = 0x1401;
        private const int FirstObjectIpidSequence = 0x24007;
        private const int InterfaceRefSize = 0x18;
        private const int QueryResultSize = 0x30;

        private const uint RpcEInvalidIpid = 0x8001012B;
        private const uint RpcEInvalidObject = 0x80010114;
        private const uint CoEObjNotReg = 0x800401FB;
        private const uint EArithmeticOverflow = 0x80070216;

        private sealed class InterfaceEntry
        {
            public HostObject Object;
            public Guid Interface;
            public uint Refs;
        }

        private sealed class ObjectEntry
        {
            public readonly Dictionary<Guid, Guid> Ipids = new Dictionary<Guid, Guid>();
            public ulong Refs;
        }

        internal string Endpoint { get; } = "OLE" + Convert.ToHexString(RandomNumberGenerator.GetBytes(14));
        internal string PortName { get; }
        internal ulong Oxid { get; } = Orpc.NewId();
        internal Guid ProcessIdentifier { get; } = Guid.NewGuid();
        internal Guid RemUnknownIpid { get; }

        private readonly Dictionary<Guid, InterfaceEntry> Interfaces = new Dictionary<Guid, InterfaceEntry>();
        private readonly Dictionary<HostObject, ObjectEntry> Objects = new Dictionary<HostObject, ObjectEntry>();

        // NT: combase registers an interface with RPC when it first marshals it, and keeps it registered.
        private readonly List<Guid> Registered = new List<Guid> { Orpc.RemUnknownInterface, Orpc.RemUnknown2Interface, Orpc.RundownInterface };
        private int NextIpidSequence = FirstObjectIpidSequence;

        internal HostApartment(uint ProcessId, uint ThreadId)
        {
            this.ProcessId = ProcessId;
            this.ThreadId = ThreadId;
            PortName = LrpcClient.GetPortName(Endpoint);
            RemUnknownIpid = NewIpid(RemUnknownIpidSequence);
        }

        internal static string GetPrincipal(BinaryEmulator Instance) => LsaLookupPortHandler.ReadComputerName(Instance) + "\\" + WinSysHelper.CurrentUserName;

        // combase puts the server's process id and its apartment in the IPID.
        private Guid NewIpid(int Sequence)
        {
            Span<byte> Ipid = stackalloc byte[16];
            BinaryPrimitives.WriteInt32LittleEndian(Ipid, Sequence);
            BinaryPrimitives.WriteUInt16LittleEndian(Ipid.Slice(4), unchecked((ushort)ProcessId));
            BinaryPrimitives.WriteUInt16LittleEndian(Ipid.Slice(6), MultithreadedApartment);
            RandomNumberGenerator.Fill(Ipid.Slice(8));
            return new Guid(Ipid);
        }

        // NT: the IPID of an interface stays the same while the object is connected, and every marshal adds references.
        internal bool TryExport(HostCall Call, HostObject Object, Guid Interface, uint Refs, out StdObjRef Std)
        {
            Std = default;
            Guid Ipid = Guid.Empty;
            if (Objects.TryGetValue(Object, out ObjectEntry Entry))
                Entry.Ipids.TryGetValue(Interface, out Ipid);

            if (Ipid == Guid.Empty)
            {
                foreach (HostCall.Export Pending in Call.Exports)
                {
                    if (Pending.Object == Object && Pending.Interface == Interface)
                    {
                        Ipid = Pending.Ipid;
                        break;
                    }
                }
            }

            if (Ipid == Guid.Empty)
            {
                if (Interfaces.Count + Call.Exports.Count >= MemoryBudget.HostObjects)
                {
                    Utils.LogError($"[-] Host COM: an apartment of process {ProcessId} refused an export past the limit of {MemoryBudget.HostObjects} interfaces.");
                    return false;
                }

                Ipid = NewIpid(NextIpidSequence++);
            }

            Call.Exports.Add(new HostCall.Export(Object, Interface, Ipid, Refs));
            Std = new StdObjRef(HostObject.ObjectFlags, Refs, Oxid, Object.Oid, Ipid);
            return true;
        }

        private void Commit(HostCall Call)
        {
            foreach (HostCall.Export Export in Call.Exports)
            {
                if (!Objects.TryGetValue(Export.Object, out ObjectEntry Entry))
                {
                    Entry = new ObjectEntry();
                    Objects.Add(Export.Object, Entry);
                }

                if (!Interfaces.TryGetValue(Export.Ipid, out InterfaceEntry Found))
                {
                    Found = new InterfaceEntry { Object = Export.Object, Interface = Export.Interface };
                    Interfaces.Add(Export.Ipid, Found);
                    Entry.Ipids[Export.Interface] = Export.Ipid;
                    if (!Registered.Contains(Export.Interface))
                        Registered.Add(Export.Interface);
                }

                if (!Export.Object.Permanent)
                {
                    uint Added = Math.Min(Export.Refs, uint.MaxValue - Found.Refs);
                    Found.Refs += Added;
                    Entry.Refs += Added;
                }
            }

            Call.Exports.Clear();
        }

        internal byte[] Respond(in LrpcMessage Message, HostCall Call, ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length <= LrpcPacket.MaxResponseStubLength)
                Commit(Call);

            return LrpcPacket.BuildResponse(Message, Stub);
        }

        public NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            Reply.Data = Serve(SendData, Reply.Client.Bindings, Instance);
            return Reply.Data == null ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_SUCCESS;
        }

        internal byte[] Serve(byte[] SendData, LrpcBindingTable Bindings, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return null;

            byte[] Reply = null;
            if (Message.Type == LrpcMessageType.Bind)
            {
                if (!LrpcBindings.TryAccept(Bindings, Message, CollectionsMarshal.AsSpan(Registered), out Guid Interface, out Reply))
                {
                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                        Instance.TriggerEventMessage($"[!] Host COM: process {ProcessId} serves no interface {Interface}; refusing the bind.", LogFlags.General);
                    Reply = LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);
                }
            }
            else if (Message.Type == LrpcMessageType.Request)
            {
                Reply = HandleRequest(Message, Bindings, Instance);
            }

            return Reply ?? LrpcPacket.EchoHeader(SendData);
        }

        internal override bool Connect(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, out byte[] Reply, out object State)
        {
            Reply = Array.Empty<byte>();
            State = new LrpcBindingTable();
            return true;
        }

        internal override NTSTATUS Receive(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, bool WaitsForReply, out byte[] Reply)
        {
            Reply = null;
            byte[] Message = new byte[LrpcPacket.HeaderSize + Data.Length];
            Data.CopyTo(Message.AsSpan(LrpcPacket.HeaderSize));
            if (!WaitsForReply && !LrpcPacket.ExpectsAnswer(Message))
                return NTSTATUS.STATUS_SUCCESS;

            byte[] Whole = Serve(Message, (LrpcBindingTable)Connection.HostServerState, Instance);
            if (Whole == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Reply = Whole.AsSpan(LrpcPacket.HeaderSize).ToArray();
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal override void Disconnected(BinaryEmulator Instance, AlpcConnection Connection)
        {
        }

        private byte[] HandleRequest(in LrpcMessage Message, LrpcBindingTable Bindings, BinaryEmulator Instance)
        {
            if (!LrpcBindings.TryResolve(Bindings, Message, out Guid Interface, out Guid Ipid))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);

            ReadOnlySpan<byte> Stub = Message.StubData;
            if (!Orpc.TryGetRequestParameters(Stub, out int Offset))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

            ReadOnlySpan<byte> Parameters = Stub.Slice(Offset);
            if (Ipid == RemUnknownIpid)
            {
                if (Interface != Orpc.RemUnknownInterface && Interface != Orpc.RemUnknown2Interface && Interface != Orpc.RundownInterface)
                    return LrpcPacket.BuildFault(Message, RpcEInvalidIpid);

                return HandleRemUnknown(Message, Interface, Instance, Parameters) ?? LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);
            }

            if (!Interfaces.TryGetValue(Ipid, out InterfaceEntry Entry) || Entry.Interface != Interface)
            {
                Utils.LogError($"[-] Host COM: process {ProcessId} has no interface {Interface} at IPID {Ipid}.");
                return LrpcPacket.BuildFault(Message, RpcEInvalidIpid);
            }

            HostCall Call = new HostCall(this, Instance);
            if (!Entry.Object.TryCall(Call, Interface, Message.ProcNumber, Parameters, out byte[] Result))
            {
                Utils.LogError($"[-] Host COM: method {Message.ProcNumber} of {Interface} on {Entry.Object.GetType().Name} is not served.");
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSProcnumOutOfRange);
            }

            return Result == null ? LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData) : Respond(Message, Call, Result);
        }

        // The handlers below return the whole reply, or null for a request they cannot read.
        private byte[] HandleRemUnknown(in LrpcMessage Message, Guid Interface, BinaryEmulator Instance, ReadOnlySpan<byte> Parameters)
        {
            switch (Message.ProcNumber)
            {
                case Orpc.ProcRemQueryInterface:
                    return RemQueryInterface(Message, new HostCall(this, Instance), Parameters);

                case Orpc.ProcRemAddRef:
                    return RemAddRef(Message, Parameters);

                case Orpc.ProcRemRelease:
                    return RemRelease(Message, Parameters);

                case Orpc.ProcRemQueryInterface2 when Interface != Orpc.RemUnknownInterface:
                    return RemQueryInterface2(Message, new HostCall(this, Instance), Parameters);
            }

            Utils.LogError($"[-] Host COM: IRemUnknown method {Message.ProcNumber} is not served.");
            return null;
        }

        private static byte[] RefuseViewReply(in LrpcMessage Message, int Count)
        {
            Utils.LogError($"[-] Host COM: a reply for {Count} interfaces needs a view, which is not supported.");
            return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSCannotSupport);
        }

        private static byte[] BuildQueryFailure(in LrpcMessage Message, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // The answers follow CRemoteUnknown::RemQueryInterface in combase.
        private byte[] RemQueryInterface(in LrpcMessage Message, HostCall Call, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadGuid(out Guid Ipid) || !Reader.TryReadUInt32(out uint Refs) || !Reader.TryReadUInt16(out ushort Count))
                return null;

            if (Count == 0)
                return BuildQueryFailure(Message, Orpc.EInvalidArg);

            if (!Reader.TryReadUInt32(out uint Conformance) || Conformance != Count || Count > Orpc.MaxRequestedInterfaces
                || !Reader.TryReadBytes(Count * Orpc.InterfaceIdSize, out ReadOnlySpan<byte> Iids))
                return null;

            if (!Interfaces.TryGetValue(Ipid, out InterfaceEntry Entry))
                return BuildQueryFailure(Message, RpcEInvalidObject);

            if (Count > LrpcPacket.MaxResponseStubLength / QueryResultSize)
                return RefuseViewReply(Message, Count);

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * QueryResultSize);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(Count);
            int Failed = 0;
            for (int i = 0; i < Count; i++)
            {
                uint Result = Call.Query(Entry.Object, Orpc.InterfaceAt(Iids, i), Refs, out StdObjRef Std);
                if (Result != Orpc.SOk)
                    Failed++;

                Writer.AlignTo(8);
                Writer.WriteUInt32(Result);
                Writer.AlignTo(8);
                Std.Write(Writer.Take(StdObjRef.Size));
            }

            Writer.WriteUInt32(QueryResult(Failed, Count));
            return Respond(Message, Call, Writer.Written);
        }

        private static uint QueryResult(int Failed, int Count) => Failed == 0 ? Orpc.SOk : Failed == Count ? Orpc.ENoInterface : Orpc.SFalse;

        // As in CRemoteUnknown::RemQueryInterface2, the result arrays have one entry per IID even on failure.
        private byte[] RemQueryInterface2(in LrpcMessage Message, HostCall Call, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadGuid(out Guid Ipid) || !Reader.TryReadUInt16(out ushort Count) || !Reader.TryReadUInt32(out uint Conformance)
                || Conformance != Count || Count > Orpc.MaxRequestedInterfaces || !Reader.TryReadBytes(Count * Orpc.InterfaceIdSize, out ReadOnlySpan<byte> Iids))
                return null;

            const int MinEntrySize = 2 * sizeof(uint) + 2 * sizeof(uint) + Orpc.StandardObjRefSize;
            if (Count > LrpcPacket.MaxResponseStubLength / MinEntrySize)
                return RefuseViewReply(Message, Count);

            bool Known = Interfaces.TryGetValue(Ipid, out InterfaceEntry Entry);
            Span<uint> Results = stackalloc uint[Count];
            Span<StdObjRef> Objects = stackalloc StdObjRef[Count];
            int Failed = 0;
            for (int i = 0; i < Count && Known; i++)
            {
                Results[i] = Call.Query(Entry.Object, Orpc.InterfaceAt(Iids, i), HostObject.PublicRefs, out Objects[i]);
                if (Results[i] != Orpc.SOk)
                    Failed++;
            }

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * MinEntrySize);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(Count);
            foreach (uint Result in Results)
                Writer.WriteUInt32(Result);

            Writer.WriteUInt32(Count);
            for (int i = 0; i < Count; i++)
            {
                if (Known && Results[i] == Orpc.SOk)
                    Writer.WriteUniqueReferent();
                else
                    Writer.WriteUInt32(0);
            }

            for (int i = 0; i < Count && Known; i++)
            {
                if (Results[i] == Orpc.SOk)
                    Orpc.WriteInterfacePointerData(ref Writer, Entry.Object.GetIdentityMarshalData(Orpc.InterfaceAt(Iids, i), Objects[i]));
            }

            Writer.WriteUInt32(Count == 0 ? Orpc.EInvalidArg : !Known ? RpcEInvalidObject : QueryResult(Failed, Count));
            return Respond(Message, Call, Writer.Written);
        }

        private static bool TryReadInterfaceRefs(ReadOnlySpan<byte> Parameters, out ushort Count, out ReadOnlySpan<byte> Refs)
        {
            Refs = default;
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            return Reader.TryReadUInt16(out Count) && Reader.TryReadUInt32(out uint Conformance) && Conformance == Count
                && Reader.TryReadBytes(Count * InterfaceRefSize, out Refs);
        }

        private static Guid ReadInterfaceRef(ReadOnlySpan<byte> Refs, int Index, out ulong Count)
        {
            ReadOnlySpan<byte> Ref = Refs.Slice(Index * InterfaceRefSize, InterfaceRefSize);
            Count = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(Ref.Slice(16)) + BinaryPrimitives.ReadUInt32LittleEndian(Ref.Slice(20));
            return new Guid(Ref.Slice(0, 16));
        }

        // The answers follow CRemoteUnknown::RemAddRefWorker in combase.
        private byte[] RemAddRef(in LrpcMessage Message, ReadOnlySpan<byte> Parameters)
        {
            if (!TryReadInterfaceRefs(Parameters, out ushort Count, out ReadOnlySpan<byte> Refs))
                return null;

            if (Count > LrpcPacket.MaxResponseStubLength / sizeof(uint))
                return RefuseViewReply(Message, Count);

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * sizeof(uint));
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(Count);
            uint Last = Orpc.SOk;
            for (int i = 0; i < Count; i++)
            {
                uint Result = AddRefs(ReadInterfaceRef(Refs, i, out ulong Added), Added);
                if (Result != Orpc.SOk)
                    Last = Result;
                Writer.WriteUInt32(Result);
            }

            Writer.WriteUInt32(Last);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private uint AddRefs(Guid Ipid, ulong Refs)
        {
            if (!Interfaces.TryGetValue(Ipid, out InterfaceEntry Entry))
                return CoEObjNotReg;

            if (Entry.Object.Permanent)
                return Orpc.SOk;

            if (Refs > uint.MaxValue - Entry.Refs)
                return EArithmeticOverflow;

            Entry.Refs += (uint)Refs;
            Objects[Entry.Object].Refs += Refs;
            return Orpc.SOk;
        }

        private byte[] RemRelease(in LrpcMessage Message, ReadOnlySpan<byte> Parameters)
        {
            if (!TryReadInterfaceRefs(Parameters, out ushort Count, out ReadOnlySpan<byte> Refs))
                return null;

            for (int i = 0; i < Count; i++)
                ReleaseRefs(ReadInterfaceRef(Refs, i, out ulong Released), Released);

            return LrpcPacket.BuildResponse(Message, HostObject.SuccessResult);
        }

        private void ReleaseRefs(Guid Ipid, ulong Refs)
        {
            if (!Interfaces.TryGetValue(Ipid, out InterfaceEntry Entry) || Entry.Object.Permanent)
                return;

            uint Taken = (uint)Math.Min(Refs, Entry.Refs);
            Entry.Refs -= Taken;
            ObjectEntry Owner = Objects[Entry.Object];
            Owner.Refs -= Taken;
            if (Owner.Refs != 0)
                return;

            foreach (Guid Each in Owner.Ipids.Values)
                Interfaces.Remove(Each);

            Objects.Remove(Entry.Object);
        }
    }
}
