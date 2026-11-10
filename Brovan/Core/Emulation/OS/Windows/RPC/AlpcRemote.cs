using System.Buffers.Binary;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed unsafe class AlpcSessionPort : IDisposable
    {
        internal const string Extension = ".port";

        private const uint Magic = 0x52504C41;
        private const uint FormatVersion = 1;
        private const int ClaimAttempts = 2;

        // Marks a deleted file, so a process that still maps it never takes it over.
        private const ulong GoneHolder = ulong.MaxValue;

        private const int MagicOffset = 0x00;
        private const int VersionOffset = 0x04;
        private const int OwnerSlotOffset = 0x0C;
        private const int OwnerHolderOffset = 0x10;
        private const int NameLengthOffset = 0x18;
        private const int NameOffset = 0x20;
        private const int MaxNameBytes = 0x200;
        private const int MarkerHolderOffset = 0x220;
        private const int LanesOffset = 0x240;
        private const int LaneBlockBytes = 0xC0;
        private const int LaneCapacity = 0x400;
        private const int LaneStride = LaneBlockBytes + LaneCapacity;
        private const int FileBytes = LanesOffset + GuestSession.SlotCount * LaneStride;

        // A connect entry holds the channel id, the sender's holder and its slot.
        internal const int EntryBytes = 20;

        internal readonly string Name;
        private readonly string Location;
        private SessionMapping Mapping;

        private AlpcSessionPort(string Name, string Location, SessionMapping Mapping)
        {
            this.Name = Name;
            this.Location = Location;
            this.Mapping = Mapping;
        }

        internal int OwnerSlot => (int)Mapping.ReadUInt32(OwnerSlotOffset);

        internal ulong OwnerHolder => Mapping.ReadUInt64(OwnerHolderOffset);

        private ulong MarkerHolder => Mapping.ReadUInt64(MarkerHolderOffset);

        internal bool IsMarked => MarkerHolder != 0;

        internal SessionRing Lane(int SenderSlot)
        {
            int Block = LanesOffset + SenderSlot * LaneStride;
            return new SessionRing(Mapping.Base, Block, Block + LaneBlockBytes, LaneCapacity);
        }

        private static string PathOf(string Name) => SessionNames.InstancePath(SessionNames.AlpcPorts, Name, 0, Extension);

        internal static AlpcSessionPort TryOpenLive(string Name)
        {
            if (Name.Length * 2 > MaxNameBytes)
                return null;

            string Location = PathOf(Name);
            if (!File.Exists(Location))
                return null;

            SessionMapping Mapping = SessionMapping.OpenFile(Location, FileMode.Open, FileBytes);
            if (Mapping == null)
                return null;

            AlpcSessionPort Record = new AlpcSessionPort(Name, Location, Mapping);
            ulong Owner = Record.OwnerHolder;
            if (Record.IsFormatted() && Record.NameMatches() && Record.MarkerHolder == 0 && Owner != GuestSession.OwnHolder
                && GuestSession.IsHolderAliveCached(Owner) && (uint)Record.OwnerSlot < GuestSession.SlotCount)
                return Record;

            Record.Dispose();
            return null;
        }

        // Null with Collision false means the session could not take the record, and the port stays local.
        internal static AlpcSessionPort TryClaim(string Name, int OwnSlot, out bool Collision)
        {
            Collision = false;
            if (Name.Length * 2 > MaxNameBytes)
                return null;

            SessionNames.EnsureDirectory(SessionNames.AlpcPorts);
            string Location = PathOf(Name);
            for (int Attempt = 0; Attempt < ClaimAttempts; Attempt++)
            {
                SessionMapping Mapping = SessionMapping.OpenFile(Location, FileMode.OpenOrCreate, FileBytes);
                if (Mapping == null)
                    return null;

                AlpcSessionPort Record = new AlpcSessionPort(Name, Location, Mapping);
                Claim Result = Record.TryTakeOwner();
                if (Result == Claim.Taken)
                {
                    Record.Format(OwnSlot);
                    return Record;
                }

                if (Result == Claim.Marked)
                {
                    Record.Remove();
                    continue;
                }

                Record.Dispose();
                if (Result == Claim.Collision)
                {
                    Collision = true;
                    return null;
                }
            }

            return null;
        }

        private enum Claim
        {
            Taken,
            Collision,
            Marked,
            Deleting,
        }

        private Claim TryTakeOwner()
        {
            ref ulong Owner = ref Mapping.UInt64At(OwnerHolderOffset);
            while (true)
            {
                if (MarkerHolder != 0)
                    return TryTakeMark(Mapping) ? Claim.Marked : Claim.Deleting;

                ulong Seen = Volatile.Read(ref Owner);
                bool Stale = Seen == 0 ? IsFormatted() : !GuestSession.IsHolderAliveCached(Seen);
                if (Seen != 0 && !Stale)
                    return Claim.Collision;

                if (Stale)
                {
                    if (TryMark(Mapping))
                        return Claim.Marked;
                }
                else if (Interlocked.CompareExchange(ref Owner, GuestSession.OwnHolder, 0) == 0)
                {
                    return Claim.Taken;
                }
            }
        }

        private void Format(int OwnSlot)
        {
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(Name.AsSpan()).CopyTo(new Span<byte>(Mapping.Base + NameOffset, MaxNameBytes));
            Mapping.WriteUInt32(NameLengthOffset, (uint)(Name.Length * 2));
            Mapping.WriteUInt32(OwnerSlotOffset, (uint)OwnSlot);
            Mapping.WriteUInt32(VersionOffset, FormatVersion);

            // The magic goes last, so no reader takes the record before it is complete.
            Mapping.WriteUInt32(MagicOffset, Magic);
        }

        internal bool TryWithdraw() => OwnerHolder == GuestSession.OwnHolder && TryMark(Mapping);

        private static bool TryMark(SessionMapping Mapping)
            => Interlocked.CompareExchange(ref Mapping.UInt64At(MarkerHolderOffset), GuestSession.OwnHolder, 0) == 0;

        private static bool TryTakeMark(SessionMapping Mapping)
        {
            ref ulong Marker = ref Mapping.UInt64At(MarkerHolderOffset);
            ulong Seen = Volatile.Read(ref Marker);
            return Seen != 0 && Seen != GoneHolder && !GuestSession.IsHolderAliveCached(Seen)
                && Interlocked.CompareExchange(ref Marker, GuestSession.OwnHolder, Seen) == Seen;
        }

        // Only the process that holds the marker may call this, so a delete by name never removes a newer record.
        internal void Remove()
        {
            DeleteMarked(Mapping, Location);
            Mapping = null;
        }

        private static void DeleteMarked(SessionMapping Mapping, string Location)
        {
            SessionNames.Delete(Location);
            Mapping.WriteUInt64(MarkerHolderOffset, GoneHolder);
            Mapping.Dispose();
        }

        internal static void RemoveIfAbandoned(string Location)
        {
            SessionMapping Mapping = SessionMapping.OpenFile(Location, FileMode.Open, FileBytes);
            if (Mapping == null)
                return;

            bool Taken;
            if (Mapping.ReadUInt64(MarkerHolderOffset) != 0)
            {
                Taken = TryTakeMark(Mapping);
            }
            else
            {
                ulong Owner = Mapping.ReadUInt64(OwnerHolderOffset);
                Taken = Mapping.ReadUInt32(MagicOffset) == Magic && !GuestSession.IsHolderAliveCached(Owner) && TryMark(Mapping);
            }

            if (Taken)
                DeleteMarked(Mapping, Location);
            else
                Mapping.Dispose();
        }

        private bool IsFormatted()
            => Mapping.ReadUInt32(MagicOffset) == Magic && Mapping.ReadUInt32(VersionOffset) == FormatVersion;

        private bool NameMatches()
        {
            uint Length = Mapping.ReadUInt32(NameLengthOffset);
            if (Length > MaxNameBytes || (Length & 1) != 0)
                return false;

            ReadOnlySpan<char> Stored = new ReadOnlySpan<char>(Mapping.Base + NameOffset, (int)Length / 2);
            return Stored.Equals(Name.AsSpan(), StringComparison.OrdinalIgnoreCase);
        }

        public void Dispose()
        {
            Mapping?.Dispose();
            Mapping = null;
        }
    }

    internal sealed unsafe class AlpcChannel
    {
        internal const string Extension = ".chan";

        private const uint Magic = 0x43504C41;
        private const uint FormatVersion = 1;

        private const int MagicOffset = 0x00;
        private const int VersionOffset = 0x04;
        private const int CapacityOffset = 0x08;
        private const int ClientHolderOffset = 0x10;
        private const int ServerHolderOffset = 0x18;
        private const int ToServerBlock = 0x40;
        private const int ToClientBlock = 0x100;
        private const int DataOffset = 0x200;

        private const int MinCapacity = 0x40000;
        private const int MaxCapacity = 0x100000;

        internal readonly ulong Id;
        private readonly string Location;
        private SessionMapping Mapping;
        private readonly int Capacity;

        private AlpcChannel(ulong Id, string Location, SessionMapping Mapping, int Capacity)
        {
            this.Id = Id;
            this.Location = Location;
            this.Mapping = Mapping;
            this.Capacity = Capacity;
        }

        internal SessionRing ToServer => new SessionRing(Mapping.Base, ToServerBlock, DataOffset, Capacity);

        internal SessionRing ToClient => new SessionRing(Mapping.Base, ToClientBlock, DataOffset + Capacity, Capacity);

        private static string PathOf(ulong Id) => Path.Combine(SessionNames.DirectoryOf(SessionNames.AlpcChannels), Id.ToString("x16") + Extension);

        internal static AlpcChannel Create(ulong Id, int RequestedCapacity)
        {
            int Capacity = (int)Math.Clamp(System.Numerics.BitOperations.RoundUpToPowerOf2((uint)RequestedCapacity), MinCapacity, MaxCapacity);
            SessionNames.EnsureDirectory(SessionNames.AlpcChannels);
            string Location = PathOf(Id);
            SessionMapping Mapping = SessionMapping.OpenFile(Location, FileMode.CreateNew, DataOffset + 2L * Capacity);
            if (Mapping == null)
                return null;

            AlpcChannel Channel = new AlpcChannel(Id, Location, Mapping, Capacity);
            Mapping.WriteUInt32(CapacityOffset, (uint)Capacity);
            Mapping.WriteUInt64(ClientHolderOffset, GuestSession.OwnHolder);
            Mapping.WriteUInt32(VersionOffset, FormatVersion);
            Mapping.WriteUInt32(MagicOffset, Magic);
            return Channel;
        }

        internal static AlpcChannel OpenServerEnd(ulong Id, ulong ExpectedClient)
        {
            string Location = PathOf(Id);
            if (!File.Exists(Location))
                return null;

            SessionMapping Head = SessionMapping.OpenFile(Location, FileMode.Open, DataOffset);
            if (Head == null)
                return null;

            uint MagicValue = Head.ReadUInt32(MagicOffset);
            uint Version = Head.ReadUInt32(VersionOffset);
            uint Capacity = Head.ReadUInt32(CapacityOffset);
            ulong Client = Head.ReadUInt64(ClientHolderOffset);
            Head.Dispose();

            if (MagicValue != Magic || Version != FormatVersion || Client != ExpectedClient
                || Capacity < MinCapacity || Capacity > MaxCapacity || !System.Numerics.BitOperations.IsPow2(Capacity))
                return null;

            SessionMapping Mapping = SessionMapping.OpenFile(Location, FileMode.Open, DataOffset + 2L * Capacity);
            if (Mapping == null)
                return null;

            AlpcChannel Channel = new AlpcChannel(Id, Location, Mapping, (int)Capacity);
            if (Interlocked.CompareExchange(ref Mapping.UInt64At(ServerHolderOffset), GuestSession.OwnHolder, 0) != 0)
            {
                Mapping.Dispose();
                return null;
            }

            return Channel;
        }

        internal void Release(bool ClientEnd)
        {
            if (Mapping == null)
                return;

            // Each end clears its own holder before it reads the other, so at least one end of two that leave together
            // deletes the file.
            Interlocked.Exchange(ref Mapping.UInt64At(ClientEnd ? ClientHolderOffset : ServerHolderOffset), 0);
            ulong Other = Mapping.ReadUInt64(ClientEnd ? ServerHolderOffset : ClientHolderOffset);
            Mapping.Dispose();
            Mapping = null;

            if (!GuestSession.IsHolderAliveCached(Other))
                SessionNames.Delete(Location);
        }

        // A channel the client is still writing has no magic yet.
        internal static void RemoveIfAbandoned(string Location)
        {
            SessionMapping Head = SessionMapping.OpenFile(Location, FileMode.Open, DataOffset);
            if (Head == null)
                return;

            bool Abandoned;
            using (Head)
            {
                Abandoned = Head.ReadUInt32(MagicOffset) == Magic
                    && !GuestSession.IsHolderAliveCached(Head.ReadUInt64(ClientHolderOffset))
                    && !GuestSession.IsHolderAliveCached(Head.ReadUInt64(ServerHolderOffset));
            }

            if (Abandoned)
                SessionNames.Delete(Location);
        }
    }

    internal sealed class AlpcRemotePeer
    {
        internal AlpcChannel Channel;
        internal bool IsClient;
        internal int PeerSlot;
        internal ulong PeerHolder;
        internal bool Released;

        // Set by the session watcher, which does not hold KernelLock.
        internal volatile bool PeerEnded;

        // Only the client end uses this.
        internal AlpcMessage ConnectRequest;

        // Only the server end uses these.
        internal uint ConnectRequestId;
        internal uint ConnectCallbackId;
        internal bool ClientAcceptsRequests;

        // The last token sent or read, so a token travels only when its TokenId or ModifiedId changed.
        internal WinToken Token;

        internal SessionRing Outbound => IsClient ? Channel.ToServer : Channel.ToClient;

        internal SessionRing Inbound => IsClient ? Channel.ToClient : Channel.ToServer;
    }

    internal static partial class AlpcMessaging
    {
        private const byte FrameConnect = 1;
        private const byte FrameConnectReply = 2;
        private const byte FrameConnectRefused = 3;
        private const byte FrameRequest = 4;
        private const byte FrameReply = 5;
        private const byte FrameAnswer = 6;
        private const byte FrameDatagram = 7;
        private const byte FrameClientClosed = 8;
        private const byte FrameServerClosed = 9;
        private const byte FrameFailed = 10;

        private const byte FrameWaits = 0x1;
        private const byte FrameSenderToken = 0x2;
        private const byte FrameContextToken = 0x4;

        // Kind, flags, type flags, request id, callback id, status, message context, process id, thread id, the identity
        // length, the data length and the QoS word, then the identity and the data.
        private const int FrameHeaderBytes = 48;
        private const int MaxFrameBytes = FrameHeaderBytes + TokenTransfer.MaxFormBytes + MaxDataLength;

        private const uint QosLevelMask = 0x3;
        private const uint QosDynamic = 0x4;
        private const uint QosEffectiveOnly = 0x8;
        private const uint QosAllowImpersonation = 0x10;
        private const uint QosAcceptsRequests = 0x20;

        private const int MaxFramesPerPass = 64;

        private static readonly List<AlpcConnection> RemoteConnections = new List<AlpcConnection>();
        private static readonly List<WinPort> PublishedPorts = new List<WinPort>();
        private static readonly List<AlpcRemotePeer> Watched = new List<AlpcRemotePeer>();
        private static readonly byte[] InboundFrame = new byte[MaxFrameBytes];
        private static readonly byte[] OutboundFrame = new byte[MaxFrameBytes];

        // Only the session watcher's thread uses it.
        private static readonly List<AlpcRemotePeer> WatchedSnapshot = new List<AlpcRemotePeer>();

        // Only the pump uses them, so a handler that ends a connection does not change the list the pump walks.
        private static readonly List<AlpcConnection> DrainSnapshot = new List<AlpcConnection>();
        private static readonly List<WinPort> AcceptSnapshot = new List<WinPort>();

        private readonly ref struct Frame
        {
            internal readonly byte Kind;
            internal readonly byte Flags;
            internal readonly ushort TypeFlags;
            internal readonly uint RequestId;
            internal readonly uint CallbackId;
            internal readonly uint Status;
            internal readonly ulong MessageContext;
            internal readonly ulong ProcessId;
            internal readonly ulong ThreadId;
            internal readonly uint Qos;
            internal readonly ReadOnlySpan<byte> Identity;
            internal readonly ReadOnlySpan<byte> Data;

            internal Frame(byte Kind, byte Flags, ushort TypeFlags, uint RequestId, uint CallbackId, uint Status, ulong MessageContext, ulong ProcessId,
                ulong ThreadId, uint Qos, ReadOnlySpan<byte> Identity, ReadOnlySpan<byte> Data)
            {
                this.Kind = Kind;
                this.Flags = Flags;
                this.TypeFlags = TypeFlags;
                this.RequestId = RequestId;
                this.CallbackId = CallbackId;
                this.Status = Status;
                this.MessageContext = MessageContext;
                this.ProcessId = ProcessId;
                this.ThreadId = ThreadId;
                this.Qos = Qos;
                this.Identity = Identity;
                this.Data = Data;
            }

            internal static Frame Signal(byte Kind, uint RequestId = 0, uint CallbackId = 0, NTSTATUS Status = NTSTATUS.STATUS_SUCCESS)
                => new Frame(Kind, 0, 0, RequestId, CallbackId, (uint)Status, 0, 0, 0, 0, default, default);

            // Bytes must be a private host copy, never memory that another process can still write.
            internal static bool TryParse(ReadOnlySpan<byte> Bytes, out Frame Parsed)
            {
                Parsed = default;
                if (Bytes.Length < FrameHeaderBytes)
                    return false;

                int IdentityLength = BinaryPrimitives.ReadUInt16LittleEndian(Bytes.Slice(40));
                int DataLength = BinaryPrimitives.ReadUInt16LittleEndian(Bytes.Slice(42));
                if (DataLength > MaxDataLength || FrameHeaderBytes + IdentityLength + DataLength != Bytes.Length)
                    return false;

                Parsed = new Frame(Bytes[0], Bytes[1], BinaryPrimitives.ReadUInt16LittleEndian(Bytes.Slice(2)), BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(4)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(8)), BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(12)),
                    BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(16)), BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(24)),
                    BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(32)), BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(44)),
                    Bytes.Slice(FrameHeaderBytes, IdentityLength), Bytes.Slice(FrameHeaderBytes + IdentityLength, DataLength));
                return true;
            }
        }

        internal static bool HasRemoteWork => PublishedPorts.Count != 0 || RemoteConnections.Count != 0;

        internal static WinPort FindSessionPort(BinaryEmulator Instance, string Name)
        {
            if (!Supported(Instance) || GuestSession.OwnSlot < 0)
                return null;

            AlpcSessionPort Record = AlpcSessionPort.TryOpenLive(Name);
            string Shadow = Record == null ? Instance.WinHelper.GetShadowObjectName(Name) : null;
            if (Shadow != null)
                Record = AlpcSessionPort.TryOpenLive(Shadow);

            if (Record == null)
                return null;

            Record.Dispose();
            return new WinPort { Name = Record.Name, IsRemote = true };
        }

        // NT allows one port per name in a session. A port that cannot be published stays local, and its create succeeds.
        internal static NTSTATUS Publish(BinaryEmulator Instance, WinPort Port)
        {
            if (string.IsNullOrEmpty(Port.Name))
                return NTSTATUS.STATUS_SUCCESS;

            if (!Supported(Instance))
            {
                Utils.LogError($"[-] ALPC: \"{Port.Name}\" stays local, because session ports serve x64 guests only.");
                return NTSTATUS.STATUS_SUCCESS;
            }

            int OwnSlot = GuestSession.OwnSlot;
            if (OwnSlot < 0)
            {
                Utils.LogError($"[-] ALPC: \"{Port.Name}\" stays local, because this process has no place in the session.");
                return NTSTATUS.STATUS_SUCCESS;
            }

            AlpcSessionPort Record = AlpcSessionPort.TryClaim(Port.Name, OwnSlot, out bool Collision);
            if (Collision)
                return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;

            if (Record == null)
            {
                Utils.LogError($"[-] ALPC: \"{Port.Name}\" stays local, because the session cannot take its record.");
                return NTSTATUS.STATUS_SUCCESS;
            }

            Port.SessionRecord = Record;
            PublishedPorts.Add(Port);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void Withdraw(WinPort Port)
        {
            AlpcSessionPort Record = Port.SessionRecord;
            if (Record == null)
                return;

            Port.SessionRecord = null;
            PublishedPorts.Remove(Port);
            if (!Record.TryWithdraw())
            {
                Record.Dispose();
                return;
            }

            // NT: a connect that the port never took is lost with it.
            for (int Slot = 0; Slot < GuestSession.SlotCount; Slot++)
            {
                SessionRing Lane = Record.Lane(Slot);
                while (TryTakeConnectEntry(Lane, Slot, out ulong ChannelId, out ulong Holder))
                {
                    if (TryOpenConnect(ChannelId, Holder, Slot, out AlpcRemotePeer Peer, out Frame Connect))
                        RefuseConnect(Peer, Connect, NTSTATUS.STATUS_MESSAGE_LOST);
                }
            }

            Record.Remove();
        }

        private static NTSTATUS ConnectRemote(BinaryEmulator Instance, WinPort ConnectionPort, AlpcConnection Connection, AlpcWait Wait, AlpcMessage Request,
            uint PortFlags, long? Timeout)
        {
            // The record opens again here, so no connect that fails before this point holds its mapping.
            AlpcSessionPort Target = AlpcSessionPort.TryOpenLive(ConnectionPort.Name);
            if (Target == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            try
            {
                if (RemoteConnections.Count >= MemoryBudget.AlpcRemoteConnections)
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                AlpcSecurityContext Client = Connection.Client;
                byte[] Identity = TokenTransfer.Write(Client.Token ?? Instance.WinHelper.OwnProcess.GetPrimaryToken());
                if (Identity == null)
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                AlpcChannel Channel = AlpcChannel.Create(SessionIds.Next(SessionIdKind.AlpcChannel), MemoryBudget.AlpcChannelRingBytes);
                if (Channel == null)
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                AlpcRemotePeer Peer = new AlpcRemotePeer
                {
                    Channel = Channel,
                    IsClient = true,
                    PeerSlot = Target.OwnerSlot,
                    PeerHolder = Target.OwnerHolder,
                    ConnectRequest = Request,
                };

                uint Qos = (uint)Client.Qos.Level & QosLevelMask;
                if (Client.Qos.DynamicTracking)
                    Qos |= QosDynamic;
                if (Client.Qos.EffectiveOnly)
                    Qos |= QosEffectiveOnly;
                if (Connection.AllowImpersonation)
                    Qos |= QosAllowImpersonation;
                if ((PortFlags & AcceptRequestsFlag) != 0)
                    Qos |= QosAcceptsRequests;

                Frame Connect = new Frame(FrameConnect, 0, 0, Request.MessageId, Request.CallbackId, 0, 0, Request.ProcessId, Request.ThreadId, Qos, Identity, Request.Data);
                Span<byte> Entry = stackalloc byte[AlpcSessionPort.EntryBytes];
                BinaryPrimitives.WriteUInt64LittleEndian(Entry, Channel.Id);
                BinaryPrimitives.WriteUInt64LittleEndian(Entry.Slice(8), GuestSession.OwnHolder);
                BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(16), (uint)GuestSession.OwnSlot);

                if (!TryWriteFrame(Peer.Outbound, Connect) || !Target.Lane(GuestSession.OwnSlot).TryWriteFrame(Entry))
                {
                    Channel.Release(ClientEnd: true);
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                }

                // The owner marks its record before it refuses the entries left in its lanes, so an entry written after
                // that is seen here.
                Interlocked.MemoryBarrier();
                if (Target.IsMarked)
                {
                    Channel.Release(ClientEnd: true);
                    return NTSTATUS.STATUS_MESSAGE_LOST;
                }

                Connection.Remote = Peer;
                Connection.ConnectWait = Wait;
                Track(Connection);
                SessionPump.Ring(Peer.PeerSlot);
                Instance.WinHelper.ParkForIoRequest(Wait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
                return NTSTATUS.STATUS_PENDING;
            }
            finally
            {
                Target.Dispose();
            }
        }

        private static NTSTATUS SendRemote(BinaryEmulator Instance, AlpcConnection Connection, AlpcMessage Message, bool WaitsForReply, long? Timeout)
        {
            AlpcRemotePeer Peer = Connection.Remote;
            if (Peer.Released)
            {
                ReleaseContext(Message);
                return NTSTATUS.STATUS_PORT_DISCONNECTED;
            }

            byte Flags = WaitsForReply ? FrameWaits : (byte)0;
            byte[] Identity = null;
            uint Qos = 0;
            WinToken Sender = null;
            if (Message.SecurityContext != null)
            {
                Identity = TokenTransfer.Write(Message.SecurityContext.Token);
                Flags |= FrameContextToken;
                Qos = (uint)Message.SecurityContext.Qos.Level & QosLevelMask;
                if (Message.SecurityContext.Qos.EffectiveOnly)
                    Qos |= QosEffectiveOnly;
            }
            else if (Message.SenderToken is WinToken Token && (Token.TokenId != Peer.Token?.TokenId || Token.ModifiedId != Peer.Token.ModifiedId))
            {
                Identity = TokenTransfer.Write(Token);
                Flags |= FrameSenderToken;
                Sender = Token;
            }

            ReleaseContext(Message);
            if ((Flags & (FrameContextToken | FrameSenderToken)) != 0 && Identity == null)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            Frame Request = new Frame(FrameRequest, Flags, Message.AnswerFacts.TypeFlags, Message.MessageId, Message.CallbackId, 0, Message.AnswerFacts.MessageContext,
                Message.ProcessId, Message.ThreadId, Qos, Identity, Message.Data);
            if (!TryWriteFrame(Peer.Outbound, Request))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            if (Sender != null)
                Peer.Token = Sender;

            SessionPump.Ring(Peer.PeerSlot);
            if (!WaitsForReply)
                return NTSTATUS.STATUS_SUCCESS;

            Connection.AwaitingReply.Add(Message);
            Instance.WinHelper.ParkForIoRequest(Message.ReplyWait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        private static bool SendFrame(AlpcConnection Connection, in Frame Outgoing)
        {
            AlpcRemotePeer Peer = Connection.Remote;
            if (Peer.Released || !TryWriteFrame(Peer.Outbound, Outgoing))
                return false;

            SessionPump.Ring(Peer.PeerSlot);
            return true;
        }

        private static NTSTATUS SendFrameStatus(AlpcConnection Connection, in Frame Outgoing)
            => SendFrame(Connection, Outgoing) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

        private static bool TryWriteFrame(in SessionRing Ring, in Frame Outgoing)
        {
            int Length = FrameHeaderBytes + Outgoing.Identity.Length + Outgoing.Data.Length;
            if (Outgoing.Identity.Length > ushort.MaxValue || Outgoing.Data.Length > MaxDataLength)
                return false;

            Span<byte> Bytes = OutboundFrame.AsSpan(0, Length);
            Bytes.Slice(0, FrameHeaderBytes).Clear();
            Bytes[0] = Outgoing.Kind;
            Bytes[1] = Outgoing.Flags;
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(2), Outgoing.TypeFlags);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(4), Outgoing.RequestId);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(8), Outgoing.CallbackId);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(12), Outgoing.Status);
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes.Slice(16), Outgoing.MessageContext);
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes.Slice(24), Outgoing.ProcessId);
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes.Slice(32), Outgoing.ThreadId);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(40), (ushort)Outgoing.Identity.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(42), (ushort)Outgoing.Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(44), Outgoing.Qos);
            Outgoing.Identity.CopyTo(Bytes.Slice(FrameHeaderBytes));
            Outgoing.Data.CopyTo(Bytes.Slice(FrameHeaderBytes + Outgoing.Identity.Length));
            return Ring.TryWriteFrame(Bytes);
        }

        internal static void DrainRemote(BinaryEmulator Instance)
        {
            if (PublishedPorts.Count != 0)
                AcceptConnectEntries(Instance);

            if (RemoteConnections.Count == 0)
                return;

            DrainSnapshot.AddRange(RemoteConnections);
            for (int Index = 0; Index < DrainSnapshot.Count; Index++)
            {
                AlpcConnection Connection = DrainSnapshot[Index];
                AlpcRemotePeer Peer = Connection.Remote;
                if (Peer == null || Peer.Released)
                    continue;

                int Count = 0;
                while (Count < MaxFramesPerPass && !Peer.Released && Peer.Inbound.TryReadFrame(InboundFrame, out int Length))
                {
                    Count++;
                    if (Frame.TryParse(InboundFrame.AsSpan(0, Length), out Frame Incoming))
                        HandleFrame(Instance, Connection, Incoming);
                    else
                        Peer.Inbound.MarkBroken();
                }

                if (Count == MaxFramesPerPass)
                    SessionPump.Rescan();

                if (!Peer.Released && (Peer.PeerEnded || Peer.Inbound.IsBroken))
                    EndPeer(Instance, Connection);
            }

            DrainSnapshot.Clear();
        }

        private static void AcceptConnectEntries(BinaryEmulator Instance)
        {
            AcceptSnapshot.AddRange(PublishedPorts);
            for (int Index = 0; Index < AcceptSnapshot.Count; Index++)
            {
                WinPort Port = AcceptSnapshot[Index];
                AlpcSessionPort Record = Port.SessionRecord;
                if (Record == null)
                    continue;

                for (int Slot = 0; Slot < GuestSession.SlotCount; Slot++)
                {
                    SessionRing Lane = Record.Lane(Slot);
                    while (TryTakeConnectEntry(Lane, Slot, out ulong ChannelId, out ulong Holder))
                        AcceptConnectEntry(Instance, Port, ChannelId, Holder, Slot);
                }
            }

            AcceptSnapshot.Clear();
        }

        private static bool TryTakeConnectEntry(SessionRing Lane, int Slot, out ulong ChannelId, out ulong Holder)
        {
            Span<byte> Entry = stackalloc byte[AlpcSessionPort.EntryBytes];
            while (Lane.TryReadFrame(Entry, out int Length))
            {
                if (Length != AlpcSessionPort.EntryBytes)
                {
                    Lane.MarkBroken();
                    break;
                }

                ChannelId = BinaryPrimitives.ReadUInt64LittleEndian(Entry);
                Holder = BinaryPrimitives.ReadUInt64LittleEndian(Entry.Slice(8));
                uint SenderSlot = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(16));
                if (SenderSlot == (uint)Slot && GuestSession.IsHolderAliveCached(Holder))
                    return true;
            }

            ChannelId = 0;
            Holder = 0;
            return false;
        }

        private static bool TryOpenConnect(ulong ChannelId, ulong ClientHolder, int ClientSlot, out AlpcRemotePeer Peer, out Frame Connect)
        {
            Peer = null;
            Connect = default;
            AlpcChannel Channel = AlpcChannel.OpenServerEnd(ChannelId, ClientHolder);
            if (Channel == null)
                return false;

            Peer = new AlpcRemotePeer { Channel = Channel, PeerSlot = ClientSlot, PeerHolder = ClientHolder };
            if (Peer.Inbound.TryReadFrame(InboundFrame, out int Length) && Frame.TryParse(InboundFrame.AsSpan(0, Length), out Connect)
                && Connect.Kind == FrameConnect)
                return true;

            Channel.Release(ClientEnd: false);
            return false;
        }

        private static void RefuseConnect(AlpcRemotePeer Peer, in Frame Connect, NTSTATUS Status)
        {
            TryWriteFrame(Peer.Outbound, Frame.Signal(FrameConnectRefused, Connect.RequestId, Connect.CallbackId, Status));
            SessionPump.Ring(Peer.PeerSlot);
            Peer.Channel.Release(ClientEnd: false);
        }

        private static void RefuseRemoteConnect(AlpcConnection Connection, NTSTATUS Status)
            => SendFrame(Connection, Frame.Signal(FrameConnectRefused, Connection.Remote.ConnectRequestId, Connection.Remote.ConnectCallbackId, Status));

        private static void AcceptConnectEntry(BinaryEmulator Instance, WinPort Port, ulong ChannelId, ulong ClientHolder, int ClientSlot)
        {
            if (!TryOpenConnect(ChannelId, ClientHolder, ClientSlot, out AlpcRemotePeer Peer, out Frame Connect))
                return;

            if (RemoteConnections.Count >= MemoryBudget.AlpcRemoteConnections || IsFull(Port.Queue))
            {
                RefuseConnect(Peer, Connect, NTSTATUS.STATUS_INSUFFICIENT_RESOURCES);
                return;
            }

            if (!TokenTransfer.TryRead(Connect.Identity, Connect.ProcessId, out WinToken Token))
            {
                RefuseConnect(Peer, Connect, NTSTATUS.STATUS_ACCESS_DENIED);
                return;
            }

            SecurityImpersonationLevel Level = (SecurityImpersonationLevel)(Connect.Qos & QosLevelMask);
            bool Dynamic = (Connect.Qos & QosDynamic) != 0;
            AlpcSecurityContext Client = new AlpcSecurityContext
            {
                Token = Token,
                Qos = new SecurityQos(Level, DynamicTracking: Dynamic, EffectiveOnly: (Connect.Qos & QosEffectiveOnly) != 0),
            };

            AlpcConnection Connection = NewConnection(Instance, Port, Client, (Connect.Qos & QosAllowImpersonation) != 0, Host: null);
            Peer.ConnectRequestId = Connect.RequestId;
            Peer.ConnectCallbackId = Connect.CallbackId;
            Peer.ClientAcceptsRequests = (Connect.Qos & QosAcceptsRequests) != 0;
            Peer.Token = Token;
            Connection.Remote = Peer;
            Track(Connection);

            Enqueue(Instance, Port, new AlpcMessage
            {
                Type = LpcConnectionRequest,
                TypeFlags = LpcContinuationRequired,
                Data = Connect.Data.ToArray(),
                ProcessId = Connect.ProcessId,
                ThreadId = Connect.ThreadId,
                MessageId = TakeId(ref NextMessageId),
                CallbackId = TakeId(ref NextCallbackId),
                Connection = Connection,
                SenderToken = Dynamic ? Token : null,
            });
        }

        private static void HandleFrame(BinaryEmulator Instance, AlpcConnection Connection, in Frame Incoming)
        {
            AlpcRemotePeer Peer = Connection.Remote;
            if (Peer.IsClient)
                HandleClientFrame(Instance, Connection, Peer, Incoming);
            else
                HandleServerFrame(Instance, Connection, Peer, Incoming);
        }

        private static void HandleClientFrame(BinaryEmulator Instance, AlpcConnection Connection, AlpcRemotePeer Peer, in Frame Incoming)
        {
            switch (Incoming.Kind)
            {
                case FrameConnectReply:
                {
                    AlpcWait Wait = Connection.ConnectWait;
                    if (Connection.State != AlpcConnectionState.Connecting || Wait == null || !Wait.IsLive)
                    {
                        // The connect gave up first, so the server learns that its new connection is closed.
                        SendFrame(Connection, Frame.Signal(FrameClientClosed));
                        EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
                        ReleasePeer(Connection);
                        return;
                    }

                    Connection.State = AlpcConnectionState.Connected;
                    Connection.ClientReachable = true;
                    Connection.ConnectWait = null;
                    Wait.Complete(Instance, CompleteConnect(Instance, Wait, Peer.ConnectRequest, Incoming.Data, Incoming.ProcessId, Incoming.ThreadId));
                    return;
                }

                case FrameConnectRefused:
                    EndConnection(Instance, Connection, (NTSTATUS)Incoming.Status);
                    ReleasePeer(Connection);
                    return;

                case FrameReply:
                case FrameFailed:
                {
                    AlpcMessage Request = TakeAwaiting(Connection, Incoming.RequestId);
                    AlpcWait Wait = Request?.ReplyWait;
                    if (Wait == null || !Wait.IsLive)
                        return;

                    NTSTATUS Status = Incoming.Kind == FrameFailed
                        ? (NTSTATUS)Incoming.Status
                        : WriteReply(Instance, Wait, LpcReply, 0, Request, Incoming.Data, Incoming.ProcessId, Incoming.ThreadId);
                    Wait.Complete(Instance, Status);
                    return;
                }

                case FrameAnswer:
                {
                    WinPort ClientPort = Connection.ClientPort;
                    if (!Connection.ClientReachable || ClientPort == null || IsFull(ClientPort.Queue))
                        return;

                    FlushConnectReply(Instance, Connection);
                    QueueReply(Instance, ClientPort.Queue, ClientPort.WaitSemaphore, new AlpcRequestFacts(Incoming.TypeFlags, Incoming.CallbackId, Incoming.MessageContext),
                        Incoming.Data.ToArray(), Incoming.ProcessId, Incoming.ThreadId, ++Connection.NextClientSequence);
                    return;
                }

                case FrameDatagram:
                {
                    WinPort ClientPort = Connection.ClientPort;
                    if (!Connection.ClientReachable || ClientPort == null || !ClientPort.AcceptsRequests || IsFull(ClientPort.Queue))
                        return;

                    FlushConnectReply(Instance, Connection);
                    Enqueue(Instance, ClientPort, new AlpcMessage
                    {
                        Type = LpcDatagram,
                        Data = Incoming.Data.ToArray(),
                        ProcessId = Incoming.ProcessId,
                        ThreadId = Incoming.ThreadId,
                        MessageId = TakeId(ref NextMessageId),
                        CallbackId = TakeId(ref NextCallbackId),
                        Sequence = ++Connection.NextClientSequence,
                        Connection = Connection,
                    });
                    return;
                }

                // NT: a client learns that the server closed its end only when it sends next.
                case FrameServerClosed:
                    Connection.ClientReachable = false;
                    EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
                    ReleasePeer(Connection);
                    return;

                default:
                    Peer.Inbound.MarkBroken();
                    return;
            }
        }

        private static void HandleServerFrame(BinaryEmulator Instance, AlpcConnection Connection, AlpcRemotePeer Peer, in Frame Incoming)
        {
            switch (Incoming.Kind)
            {
                case FrameRequest:
                {
                    bool Waits = (Incoming.Flags & FrameWaits) != 0;
                    NTSTATUS Failure = Connection.State != AlpcConnectionState.Connected ? NTSTATUS.STATUS_PORT_DISCONNECTED
                        : IsFull(Connection.ConnectionPort.Queue) ? NTSTATUS.STATUS_INSUFFICIENT_RESOURCES
                        : NTSTATUS.STATUS_SUCCESS;
                    WinToken Sender = null;
                    AlpcSecurityContext Context = null;
                    if (Failure == NTSTATUS.STATUS_SUCCESS && !TryReadSender(Peer, Incoming, out Sender, out Context))
                        Failure = NTSTATUS.STATUS_ACCESS_DENIED;

                    if (Failure != NTSTATUS.STATUS_SUCCESS)
                    {
                        if (Waits)
                            SendFrame(Connection, Frame.Signal(FrameFailed, Incoming.RequestId, Status: Failure));
                        return;
                    }

                    AlpcMessage Message = new AlpcMessage
                    {
                        Type = LpcRequest,
                        TypeFlags = LpcContinuationRequired,
                        Data = Incoming.Data.ToArray(),
                        ProcessId = Incoming.ProcessId,
                        ThreadId = Incoming.ThreadId,
                        MessageId = TakeId(ref NextMessageId),
                        CallbackId = TakeId(ref NextCallbackId),
                        Sequence = ++Connection.NextSequence,
                        AnswerFacts = new AlpcRequestFacts(Incoming.TypeFlags, Incoming.CallbackId, Incoming.MessageContext),
                        Connection = Connection,
                        SenderToken = Sender,
                        SecurityContext = Context,
                        RemoteWaits = Waits,
                        RemoteRequestId = Incoming.RequestId,
                    };

                    if (Context != null)
                        Context.Messages++;
                    if (Waits)
                        Connection.AwaitingReply.Add(Message);
                    Enqueue(Instance, Connection.ConnectionPort, Message);
                    return;
                }

                case FrameClientClosed:
                    EndClient(Instance, Connection);
                    return;

                default:
                    Peer.Inbound.MarkBroken();
                    return;
            }
        }

        private static bool TryReadSender(AlpcRemotePeer Peer, in Frame Incoming, out WinToken Sender, out AlpcSecurityContext Context)
        {
            Sender = null;
            Context = null;
            if ((Incoming.Flags & FrameContextToken) != 0)
            {
                if (!TokenTransfer.TryRead(Incoming.Identity, Incoming.ProcessId, out WinToken ContextToken))
                    return false;

                Context = new AlpcSecurityContext
                {
                    Token = ContextToken,
                    Qos = new SecurityQos((SecurityImpersonationLevel)(Incoming.Qos & QosLevelMask), DynamicTracking: false, EffectiveOnly: (Incoming.Qos & QosEffectiveOnly) != 0),
                };
                return true;
            }

            if ((Incoming.Flags & FrameSenderToken) != 0)
            {
                if (!TokenTransfer.TryRead(Incoming.Identity, Incoming.ProcessId, out WinToken Token))
                    return false;

                Peer.Token = Token;
            }

            Sender = Peer.Token;
            return true;
        }

        private static AlpcMessage TakeAwaiting(AlpcConnection Connection, uint RequestId)
        {
            List<AlpcMessage> Awaiting = Connection.AwaitingReply;
            for (int Index = 0; Index < Awaiting.Count; Index++)
            {
                if (Awaiting[Index].MessageId != RequestId)
                    continue;

                AlpcMessage Request = Awaiting[Index];
                Awaiting.RemoveAt(Index);
                return Request;
            }

            return null;
        }

        private static void EndClient(BinaryEmulator Instance, AlpcConnection Connection)
        {
            bool NotifyServer = Connection.State == AlpcConnectionState.Connected || Connection.ClientDisconnected;
            EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
            if (NotifyServer)
                Enqueue(Instance, Connection.ConnectionPort, ClosedMessage(Connection, ++Connection.NextSequence));
            ReleasePeer(Connection);
        }

        // NT: a request the server process received and never answered is lost with the process (STATUS_MESSAGE_LOST).
        private static void EndPeer(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (Connection.Remote.IsClient)
            {
                Connection.ClientReachable = false;
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED, NTSTATUS.STATUS_MESSAGE_LOST);
                ReleasePeer(Connection);
            }
            else
            {
                EndClient(Instance, Connection);
            }
        }

        private static void Track(AlpcConnection Connection)
        {
            RemoteConnections.Add(Connection);
            lock (Watched)
                Watched.Add(Connection.Remote);
        }

        private static void ReleasePeer(AlpcConnection Connection)
        {
            AlpcRemotePeer Peer = Connection.Remote;
            if (Peer == null || Peer.Released)
                return;

            Peer.Released = true;
            RemoteConnections.Remove(Connection);
            lock (Watched)
                Watched.Remove(Peer);
            Peer.Channel.Release(Peer.IsClient);
        }

        // Runs on the session watcher's host thread, so it only flags ended peers and the pump ends them.
        internal static void PollRemotePeers()
        {
            lock (Watched)
            {
                if (Watched.Count == 0)
                    return;

                WatchedSnapshot.AddRange(Watched);
            }

            // A liveness probe can ask the host, so it runs outside the lock that guest syscalls take.
            bool Ended = false;
            foreach (AlpcRemotePeer Peer in WatchedSnapshot)
            {
                if (Peer.PeerEnded || GuestSession.IsHolderAliveCached(Peer.PeerHolder))
                    continue;

                Peer.PeerEnded = true;
                Ended = true;
            }

            WatchedSnapshot.Clear();
            if (Ended)
                SessionPump.Ring(GuestSession.OwnSlot);
        }

        internal static void ReleaseRemote()
        {
            foreach (WinPort Port in PublishedPorts.ToArray())
                Withdraw(Port);

            foreach (AlpcConnection Connection in RemoteConnections.ToArray())
                ReleasePeer(Connection);
        }
    }
}
