using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // All ring state is in the mapped file, so an inherited end continues where its creator stopped. A frame is a
    // 32 bit length and the bytes. A lock word is the host process id in its high half and a request token below.
    internal sealed unsafe class GuestPipeChannel : IDisposable
    {
        internal const uint StateFree = 0;
        internal const uint StateListening = 1;
        internal const uint StateConnected = 2;
        private const uint StateCreating = 3;
        private const uint StateDeleting = 4;

        internal const int FrameHeaderBytes = SessionRing.FrameHeaderBytes;

        private const uint HeaderMagic = 0x32505642;
        private const uint HeaderVersion = 3;

        private const int MagicOffset = 0x00;
        private const int VersionOffset = 0x04;
        private const int StateOffset = 0x08;
        private const int GenerationOffset = 0x0C;
        private const int PipeTypeOffset = 0x10;
        private const int MaxInstancesOffset = 0x14;
        private const int ServerToClientCapacityOffset = 0x18;
        private const int ClientToServerCapacityOffset = 0x1C;
        private const int NameLengthOffset = 0x20;
        private const int NameOffset = 0x24;
        private const int MaxNameBytes = 0x200;
        private const int HolderSlots = 64;
        private const int ServerHoldersOffset = 0x240;
        private const int ClientHoldersOffset = ServerHoldersOffset + HolderSlots * SessionHolders.EntryBytes;
        private const int ServerToClientOffset = 0x700;
        private const int ClientToServerOffset = 0x800;
        private const int DataOffset = 0x900;

        // The lock words follow the fields of SessionRing in each ring block.
        private const int WriteLockField = 0xC0;
        private const int ReadLockField = 0xC8;

        private const int MinCapacity = 0x1000;
        private const int MaxCapacity = 0x100000;
        private const int MaxInstanceCount = 64;
        internal const string PipeExtension = ".pipe";

        private static readonly uint OwnProcessId = (uint)Environment.ProcessId;

        private SessionMapping Mapping;
        private byte* Base;

        private readonly SessionRing Inbound;
        private readonly SessionRing Outbound;
        private readonly int HolderTable;
        private readonly int PeerHolderTable;
        private int HolderSlot = -1;
        private uint ClientGeneration;
        private bool Disposed;

        internal bool IsServer { get; }

        internal string GuestName { get; }

        internal string BackingPath { get; }

        private GuestPipeChannel(bool IsServer, string GuestName, string BackingPath, SessionMapping Mapping, int ServerToClient, int ClientToServer)
        {
            this.IsServer = IsServer;
            this.GuestName = GuestName;
            this.BackingPath = BackingPath;
            this.Mapping = Mapping;
            Base = Mapping.Base;

            SessionRing ServerToClientRing = new SessionRing(Base, ServerToClientOffset, DataOffset, ServerToClient);
            SessionRing ClientToServerRing = new SessionRing(Base, ClientToServerOffset, DataOffset + ServerToClient, ClientToServer);

            Outbound = IsServer ? ServerToClientRing : ClientToServerRing;
            Inbound = IsServer ? ClientToServerRing : ServerToClientRing;
            HolderTable = IsServer ? ServerHoldersOffset : ClientHoldersOffset;
            PeerHolderTable = IsServer ? ClientHoldersOffset : ServerHoldersOffset;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint ReadField(int Offset) => Volatile.Read(ref Unsafe.AsRef<uint>(Base + Offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void WriteField(int Offset, uint Value) => Volatile.Write(ref Unsafe.AsRef<uint>(Base + Offset), Value);

        private static uint ReadFieldAt(byte* From, int Offset) => Volatile.Read(ref Unsafe.AsRef<uint>(From + Offset));

        private static void WriteFieldAt(byte* At, int Offset, uint Value) => Volatile.Write(ref Unsafe.AsRef<uint>(At + Offset), Value);

        private static uint CompareExchangeAt(byte* At, int Offset, uint Value, uint Comparand)
            => Interlocked.CompareExchange(ref Unsafe.AsRef<uint>(At + Offset), Value, Comparand);

        internal uint PipeType => Base == null ? 0 : ReadField(PipeTypeOffset);

        internal uint MaximumInstances => Base == null ? 1 : ReadField(MaxInstancesOffset);

        internal uint InboundQuota => (uint)Inbound.Capacity;

        internal uint OutboundQuota => (uint)Outbound.Capacity;

        // A disconnect moves the generation on, so an old client stays disconnected after a new one connects.
        internal uint ConnectedGeneration => ClientGeneration;

        internal bool Disconnected => !IsServer && Base != null && ReadField(GenerationOffset) != ClientGeneration;

        internal bool Connected
        {
            get
            {
                if (Base == null || ReadField(StateOffset) != StateConnected)
                    return false;

                return IsServer || ReadField(GenerationOffset) == ClientGeneration;
            }
        }

        internal bool PeerClosed => Base == null || Disconnected || Inbound.IsBroken || !HasLiveHolder(PeerHolderTable);

        internal bool OutboundBroken => Base != null && Outbound.IsBroken;

        internal int InboundPayload => Base == null ? 0 : (int)Math.Min(Inbound.ReadField(SessionRing.PayloadField), (uint)Inbound.Capacity);

        internal bool InboundHasBytes => Base != null && Inbound.Used() != 0;

        internal int OutboundFree => Base == null ? 0 : Outbound.Free;

        internal bool FitsOutbound(int PayloadBytes) => (long)PayloadBytes + FrameHeaderBytes <= Outbound.Capacity;

        private bool TryLock(int Field, ulong Token, out bool Stolen)
        {
            Stolen = false;
            if (Base == null)
                return false;

            ref ulong Word = ref Unsafe.AsRef<ulong>(Base + Field);
            ulong Mine = ((ulong)OwnProcessId << 32) | (uint)Token;
            ulong Current = Interlocked.CompareExchange(ref Word, Mine, 0);
            if (Current == 0 || Current == Mine)
                return true;

            // A lock holder also holds an end, and its holder entry tells whether it still runs.
            uint Holder = (uint)(Current >> 32);
            if (Holder == OwnProcessId || SessionHolders.HasLiveProcess(Base + ServerHoldersOffset, HolderSlots, Holder) ||
                SessionHolders.HasLiveProcess(Base + ClientHoldersOffset, HolderSlots, Holder))
                return false;

            if (Interlocked.CompareExchange(ref Word, Mine, Current) != Current)
                return false;

            Stolen = true;
            return true;
        }

        private void Unlock(int Field, ulong Token)
        {
            if (Base == null)
                return;

            ulong Mine = ((ulong)OwnProcessId << 32) | (uint)Token;
            Interlocked.CompareExchange(ref Unsafe.AsRef<ulong>(Base + Field), 0, Mine);
        }

        internal bool TryLockRead(ulong Token) => TryLock(Inbound.Block + ReadLockField, Token, out _);

        internal void UnlockRead(ulong Token) => Unlock(Inbound.Block + ReadLockField, Token);

        internal bool TryLockWrite(ulong Token)
        {
            if (!TryLock(Outbound.Block + WriteLockField, Token, out bool Stolen))
                return false;

            // The dead holder left part of a frame behind, and no reader can find the next one.
            if (Stolen && Outbound.ReadField(SessionRing.WriteFrameRemainingField) != 0)
                Outbound.MarkBroken();

            return true;
        }

        internal void UnlockWrite(ulong Token)
        {
            // A writer that stops in a frame leaves no way to find the next one.
            if (Base != null && Outbound.ReadField(SessionRing.WriteFrameRemainingField) != 0)
                Outbound.MarkBroken();

            Unlock(Outbound.Block + WriteLockField, Token);
        }

        // Byte mode takes whatever is queued, across frame boundaries.
        internal int ReadBytes(Span<byte> Destination)
        {
            if (Base == null || Inbound.IsBroken)
                return 0;

            int Copied = 0;
            while (Copied < Destination.Length)
            {
                int Available = Inbound.Used();
                if (Available == 0)
                    break;

                uint Cursor = Inbound.ReadField(SessionRing.ReadCursorField);
                uint Remaining = Inbound.ReadField(SessionRing.ReadFrameRemainingField);

                if (Remaining == 0)
                {
                    if (Available < FrameHeaderBytes)
                        break;

                    uint Length = Inbound.ReadLength(Cursor);
                    if (Length > MaxFrameBytes)
                    {
                        Inbound.MarkBroken();
                        break;
                    }

                    Inbound.WriteField(SessionRing.ReadFrameRemainingField, Length);
                    Inbound.WriteField(SessionRing.ReadCursorField, unchecked(Cursor + FrameHeaderBytes));
                    continue;
                }

                int Take = (int)Math.Min(Math.Min(Remaining, (uint)(Destination.Length - Copied)), (uint)Available);
                Inbound.CopyOut(Cursor, Destination.Slice(Copied, Take));
                Inbound.WriteField(SessionRing.ReadFrameRemainingField, Remaining - (uint)Take);
                Inbound.WriteField(SessionRing.ReadCursorField, unchecked(Cursor + (uint)Take));
                Inbound.AddPayload(-Take);
                Copied += Take;
            }

            return Copied;
        }

        // False when no message has started.
        internal bool ReadMessage(Span<byte> Destination, out int Copied, out bool MessageLeft)
        {
            Copied = 0;
            MessageLeft = false;

            if (Base == null || Inbound.IsBroken)
                return false;

            int Available = Inbound.Used();
            uint Cursor = Inbound.ReadField(SessionRing.ReadCursorField);
            uint Remaining = Inbound.ReadField(SessionRing.ReadFrameRemainingField);

            if (Remaining == 0)
            {
                if (Available < FrameHeaderBytes)
                    return false;

                uint Length = Inbound.ReadLength(Cursor);
                if (Length > MaxFrameBytes)
                {
                    Inbound.MarkBroken();
                    return false;
                }

                // A frame that fits the ring is published whole, so a reader never starts one that is still arriving.
                if (Length + FrameHeaderBytes <= (uint)Inbound.Capacity && Available < FrameHeaderBytes + (long)Length)
                    return false;

                Cursor = unchecked(Cursor + FrameHeaderBytes);
                Available -= FrameHeaderBytes;
                Remaining = Length;
                Inbound.WriteField(SessionRing.ReadFrameRemainingField, Remaining);
                Inbound.WriteField(SessionRing.ReadCursorField, Cursor);
            }

            int Take = (int)Math.Min(Math.Min(Remaining, (uint)Destination.Length), (uint)Available);
            if (Take > 0)
            {
                Inbound.CopyOut(Cursor, Destination.Slice(0, Take));
                Inbound.WriteField(SessionRing.ReadFrameRemainingField, Remaining - (uint)Take);
                Inbound.WriteField(SessionRing.ReadCursorField, unchecked(Cursor + (uint)Take));
                Inbound.AddPayload(-Take);
            }

            Copied = Take;
            MessageLeft = Remaining - (uint)Take != 0;
            return true;
        }

        // In message mode the copy stops at the end of the current message, and MessageLength is what is left of it.
        internal int Peek(Span<byte> Destination, bool MessageMode, out uint MessageLength)
        {
            MessageLength = 0;
            if (Base == null || Inbound.IsBroken)
                return 0;

            int Available = Inbound.Used();
            uint Cursor = Inbound.ReadField(SessionRing.ReadCursorField);
            uint Remaining = Inbound.ReadField(SessionRing.ReadFrameRemainingField);
            bool FirstFrame = true;
            int Copied = 0;

            while (true)
            {
                if (Remaining == 0)
                {
                    if (Available < FrameHeaderBytes)
                        break;

                    Remaining = Inbound.ReadLength(Cursor);
                    if (Remaining > MaxFrameBytes)
                        break;

                    Cursor = unchecked(Cursor + FrameHeaderBytes);
                    Available -= FrameHeaderBytes;
                }

                if (FirstFrame)
                {
                    MessageLength = Remaining;
                    FirstFrame = false;
                }

                int Take = (int)Math.Min(Math.Min(Remaining, (uint)(Destination.Length - Copied)), (uint)Available);
                if (Take > 0)
                    Inbound.CopyOut(Cursor, Destination.Slice(Copied, Take));

                Copied += Take;
                Cursor = unchecked(Cursor + (uint)Take);
                Available -= Take;
                Remaining -= (uint)Take;

                if (MessageMode || Copied == Destination.Length || Available == 0 || Remaining != 0)
                    break;
            }

            return Copied;
        }

        // Each chunk becomes a frame of its own.
        internal int WriteBytes(ReadOnlySpan<byte> Source)
        {
            if (Base == null || Outbound.IsBroken)
                return 0;

            int Written = 0;
            while (Written < Source.Length)
            {
                int Free = Outbound.Free;
                if (Free <= FrameHeaderBytes)
                    break;

                int Chunk = Math.Min(Source.Length - Written, Free - FrameHeaderBytes);
                Outbound.PublishFrame(Source.Slice(Written, Chunk));
                Written += Chunk;
            }

            return Written;
        }

        internal bool TryWriteFrame(ReadOnlySpan<byte> Source) => Base != null && Outbound.TryWriteFrame(Source);

        // A message larger than the ring goes in pieces under the write lock. -1 when the length does not fit yet.
        internal int WriteMessagePiece(ReadOnlySpan<byte> Rest, int TotalLength, bool First)
        {
            if (Base == null || Outbound.IsBroken)
                return -1;

            int Free = Outbound.Free;
            uint Cursor = Outbound.ReadField(SessionRing.WriteCursorField);

            if (First)
            {
                if (Free <= FrameHeaderBytes)
                    return -1;

                Span<byte> Header = stackalloc byte[FrameHeaderBytes];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)TotalLength);
                Outbound.CopyIn(Cursor, Header);
                Cursor = unchecked(Cursor + FrameHeaderBytes);
                Free -= FrameHeaderBytes;
                Outbound.WriteField(SessionRing.WriteFrameRemainingField, (uint)TotalLength);
            }

            int Take = Math.Min(Rest.Length, Free);
            if (Take > 0)
                Outbound.CopyIn(Cursor, Rest.Slice(0, Take));

            uint Left = Outbound.ReadField(SessionRing.WriteFrameRemainingField) - (uint)Take;
            Outbound.WriteField(SessionRing.WriteFrameRemainingField, Left);
            Outbound.AddPayload(Take);
            Outbound.WriteField(SessionRing.WriteCursorField, unchecked(Cursor + (uint)Take));
            return Take;
        }

        internal const int MaxFrameBytes = 0x400000;

        private bool HasLiveHolder(int Table) => SessionHolders.HasLive(Base + Table, HolderSlots, true);

        private static bool HasLiveHolderAt(byte* At, int Table) => SessionHolders.HasLive(At + Table, HolderSlots, false);

        private bool TryRegisterHolder()
        {
            HolderSlot = SessionHolders.Register(Base + HolderTable, HolderSlots);
            return HolderSlot >= 0;
        }

        private void ReleaseHolder()
        {
            if (HolderSlot < 0 || Base == null)
                return;

            // A disconnect emptied the client table, and the slot can belong to a new connection of this process.
            if (!Disconnected)
                SessionHolders.Release(Base + HolderTable, HolderSlot);

            HolderSlot = -1;
        }

        private void ClearClientState()
        {
            ClearRing(in Inbound);
            ClearRing(in Outbound);
            SessionHolders.Clear(Base + ClientHoldersOffset, HolderSlots);
        }

        private void ClearRing(in SessionRing Ring)
        {
            Ring.Clear();
            Volatile.Write(ref Unsafe.AsRef<ulong>(Base + Ring.Block + WriteLockField), 0);
            Volatile.Write(ref Unsafe.AsRef<ulong>(Base + Ring.Block + ReadLockField), 0);
        }

        // NT puts the instance back to listening. A client that still holds the old connection stays disconnected.
        internal void Disconnect()
        {
            if (Base == null || !IsServer)
                return;

            ClearClientState();
            WriteField(GenerationOffset, unchecked(ReadField(GenerationOffset) + 1));
            WriteField(StateOffset, StateListening);
        }

        private static int RoundCapacity(uint Quota)
        {
            long Wanted = Quota == 0 ? MinCapacity : Quota;
            if (Wanted < MinCapacity)
                Wanted = MinCapacity;
            if (Wanted > MaxCapacity)
                Wanted = MaxCapacity;

            int Capacity = MinCapacity;
            while (Capacity < Wanted)
                Capacity <<= 1;

            return Capacity;
        }

        private static bool IsPowerOfTwo(int Value) => Value >= MinCapacity && Value <= MaxCapacity && (Value & (Value - 1)) == 0;

        private static string InstancePath(string GuestName, int Instance) => SessionNames.InstancePath(SessionNames.Pipes, GuestName, Instance, PipeExtension);

        // Another process can delete the file at any time, so a failure to open it is no error.
        private static bool TryMap(string Path, FileMode Mode, long Length, out SessionMapping Mapping)
        {
            Mapping = null;
            FileStream Stream;
            try
            {
                Stream = new FileStream(Path, Mode, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

                if (Length > 0 && Stream.Length < Length)
                    Stream.SetLength(Length);
            }
            catch (Exception)
            {
                return false;
            }

            if (Stream.Length < DataOffset + (MinCapacity * 2))
            {
                Stream.Dispose();
                return false;
            }

            Mapping = SessionMapping.MapFile(Stream, Stream.Length, Path);
            return Mapping != null;
        }

        private static bool HeaderValid(byte* At, long FileLength, out int ServerToClient, out int ClientToServer, out string Name)
        {
            ServerToClient = 0;
            ClientToServer = 0;
            Name = null;

            if (ReadFieldAt(At, MagicOffset) != HeaderMagic || ReadFieldAt(At, VersionOffset) != HeaderVersion)
                return false;

            int First = (int)ReadFieldAt(At, ServerToClientCapacityOffset);
            int Second = (int)ReadFieldAt(At, ClientToServerCapacityOffset);

            if (!IsPowerOfTwo(First) || !IsPowerOfTwo(Second))
                return false;

            if (DataOffset + (long)First + Second > FileLength)
                return false;

            uint NameBytes = ReadFieldAt(At, NameLengthOffset);
            if (NameBytes > MaxNameBytes || (NameBytes & 1) != 0)
                return false;

            Name = NameBytes == 0 ? string.Empty : Encoding.Unicode.GetString(At + NameOffset, (int)NameBytes);
            ServerToClient = First;
            ClientToServer = Second;
            return true;
        }

        private static bool HeaderMatches(byte* At, string GuestName, long FileLength, out int ServerToClient, out int ClientToServer)
        {
            if (!HeaderValid(At, FileLength, out ServerToClient, out ClientToServer, out string Stored))
                return false;

            return string.Equals(Stored, GuestName, StringComparison.OrdinalIgnoreCase);
        }

        private static string[] ExistingInstancePaths(string GuestName) => SessionNames.InstancePaths(SessionNames.Pipes, GuestName, PipeExtension);

        internal static bool ServerExists(string GuestName)
        {
            foreach (string Path in ExistingInstancePaths(GuestName))
            {
                if (!TryMap(Path, FileMode.Open, 0, out SessionMapping Mapping))
                    continue;

                using (Mapping)
                {
                    byte* At = Mapping.Base;
                    if (!HeaderMatches(At, GuestName, Mapping.Length, out _, out _))
                        continue;

                    if (ReadFieldAt(At, StateOffset) == StateListening && HasLiveHolderAt(At, ServerHoldersOffset))
                        return true;
                }
            }

            return false;
        }

        internal static NTSTATUS TryCreateServer(string GuestName, uint PipeType, uint MaxInstances,
            uint InboundQuota, uint OutboundQuota, out GuestPipeChannel Channel)
        {
            Channel = null;

            int ServerToClient = RoundCapacity(OutboundQuota);
            int ClientToServer = RoundCapacity(InboundQuota);
            long Length = DataOffset + ServerToClient + ClientToServer;
            int Limit = MaxInstances == 0 || MaxInstances > MaxInstanceCount ? MaxInstanceCount : (int)MaxInstances;

            try
            {
                SessionNames.EnsureDirectory(SessionNames.Pipes);
            }
            catch (Exception Error)
            {
                Utils.LogError($"[GuestPipeChannel] Cannot create the pipe directory: {Error.Message}");
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
            }

            bool NameTaken = false;

            for (int Instance = 0; Instance < Limit; Instance++)
            {
                string Path = InstancePath(GuestName, Instance);

                if (!TryMap(Path, FileMode.OpenOrCreate, Length, out SessionMapping Mapping))
                    continue;

                byte* At = Mapping.Base;
                bool Claimed = false;
                try
                {
                    uint Observed = ReadFieldAt(At, StateOffset);
                    if (Observed == StateCreating || Observed == StateDeleting)
                        continue;

                    bool Valid = HeaderValid(At, Mapping.Length, out _, out _, out string Stored);

                    if (Observed != StateFree && HasLiveHolderAt(At, ServerHoldersOffset))
                    {
                        if (Valid && string.Equals(Stored, GuestName, StringComparison.OrdinalIgnoreCase))
                            NameTaken = true;
                        continue;
                    }

                    if (Mapping.Length < Length || CompareExchangeAt(At, StateOffset, StateCreating, Observed) != Observed)
                        continue;

                    // The state word stays StateCreating, or another creator could take the instance too.
                    uint Generation = unchecked(ReadFieldAt(At, GenerationOffset) + 1);
                    new Span<byte>(At, StateOffset).Clear();
                    new Span<byte>(At + StateOffset + sizeof(uint), DataOffset - StateOffset - sizeof(uint)).Clear();

                    byte[] Name = Encoding.Unicode.GetBytes(GuestName);
                    int NameBytes = Math.Min(Name.Length, MaxNameBytes) & ~1;
                    if (NameBytes > 0)
                        Name.AsSpan(0, NameBytes).CopyTo(new Span<byte>(At + NameOffset, NameBytes));

                    WriteFieldAt(At, NameLengthOffset, (uint)NameBytes);
                    WriteFieldAt(At, PipeTypeOffset, PipeType);
                    WriteFieldAt(At, MaxInstancesOffset, (uint)Limit);
                    WriteFieldAt(At, ServerToClientCapacityOffset, (uint)ServerToClient);
                    WriteFieldAt(At, ClientToServerCapacityOffset, (uint)ClientToServer);
                    WriteFieldAt(At, GenerationOffset, Generation);
                    SessionHolders.Claim(At + ServerHoldersOffset, 0);
                    WriteFieldAt(At, VersionOffset, HeaderVersion);

                    // Written last, so a client sees a finished header or none.
                    WriteFieldAt(At, MagicOffset, HeaderMagic);
                    WriteFieldAt(At, StateOffset, StateListening);

                    Channel = new GuestPipeChannel(true, GuestName, Path, Mapping, ServerToClient, ClientToServer);
                    Channel.HolderSlot = 0;
                    Claimed = true;
                    return NTSTATUS.STATUS_SUCCESS;
                }
                finally
                {
                    if (!Claimed)
                        Mapping.Dispose();
                }
            }

            return NameTaken ? NTSTATUS.STATUS_PIPE_BUSY : NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
        }

        internal static NTSTATUS TryConnectClient(string GuestName, out GuestPipeChannel Channel)
        {
            Channel = null;
            bool Seen = false;

            foreach (string Path in ExistingInstancePaths(GuestName))
            {
                NTSTATUS Status = TryConnectInstance(Path, GuestName, out Channel);
                if (Status == NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (Status == NTSTATUS.STATUS_PIPE_BUSY)
                    Seen = true;
            }

            return Seen ? NTSTATUS.STATUS_PIPE_BUSY : NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
        }

        internal static NTSTATUS TryConnectInstance(string BackingPath, string GuestName, out GuestPipeChannel Channel)
        {
            Channel = null;

            if (!TryMap(BackingPath, FileMode.Open, 0, out SessionMapping Mapping))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            byte* At = Mapping.Base;
            bool Claimed = false;
            try
            {
                if (!HeaderMatches(At, GuestName, Mapping.Length, out int ServerToClient, out int ClientToServer))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (!HasLiveHolderAt(At, ServerHoldersOffset))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (CompareExchangeAt(At, StateOffset, StateConnected, StateListening) != StateListening)
                    return NTSTATUS.STATUS_PIPE_BUSY;

                GuestPipeChannel Client = new GuestPipeChannel(false, GuestName, BackingPath, Mapping, ServerToClient, ClientToServer);
                Client.ClientGeneration = ReadFieldAt(At, GenerationOffset);
                if (!Client.TryRegisterHolder())
                {
                    WriteFieldAt(At, StateOffset, StateListening);
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                }

                Channel = Client;
                Claimed = true;
                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                if (!Claimed)
                    Mapping.Dispose();
            }
        }

        internal static NTSTATUS TryOpenEnd(string BackingPath, bool Server, uint Generation, out GuestPipeChannel Channel)
        {
            Channel = null;

            if (!TryMap(BackingPath, FileMode.Open, 0, out SessionMapping Mapping))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Claimed = false;
            try
            {
                if (!HeaderValid(Mapping.Base, Mapping.Length, out int ServerToClient, out int ClientToServer, out string Name))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                GuestPipeChannel End = new GuestPipeChannel(Server, Name, BackingPath, Mapping, ServerToClient, ClientToServer);
                End.ClientGeneration = Generation;
                if (!End.TryRegisterHolder())
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                Channel = End;
                Claimed = true;
                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                if (!Claimed)
                    Mapping.Dispose();
            }
        }

        // No magic or StateCreating means a server is still setting the file up. StateDeleting is taken by compare and
        // exchange, so no creator can claim the file before it is gone.
        internal static void RemoveIfAbandoned(string Location)
        {
            if (!TryMap(Location, FileMode.Open, 0, out SessionMapping Mapping))
                return;

            bool Abandoned;
            using (Mapping)
            {
                byte* At = Mapping.Base;
                uint Observed = ReadFieldAt(At, StateOffset);
                Abandoned = ReadFieldAt(At, MagicOffset) == HeaderMagic &&
                            (ReadFieldAt(At, VersionOffset) != HeaderVersion ||
                             (Observed != StateCreating && !HasLiveHolderAt(At, ServerHoldersOffset) &&
                              CompareExchangeAt(At, StateOffset, StateDeleting, Observed) == Observed));
            }

            if (Abandoned)
                SessionNames.Delete(Location);
        }

        public void Dispose()
        {
            if (Disposed)
                return;

            Disposed = true;

            bool RemoveInstance = false;
            if (Base != null)
            {
                ReleaseHolder();

                if (IsServer && !HasLiveHolder(ServerHoldersOffset))
                {
                    uint Observed = ReadField(StateOffset);
                    RemoveInstance = Observed != StateCreating && CompareExchangeAt(Base, StateOffset, StateDeleting, Observed) == Observed;
                }
            }

            Mapping?.Dispose();
            Mapping = null;
            Base = null;

            if (RemoveInstance && BackingPath != null)
            {
                try
                {
                    File.Delete(BackingPath);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestPipeChannel] Cannot remove a closed pipe: {Error.Message}");
                }
            }
        }
    }
}
