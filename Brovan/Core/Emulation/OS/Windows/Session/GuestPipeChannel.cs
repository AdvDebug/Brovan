using System;
using System.IO;
using System.IO.MemoryMappedFiles;
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

        internal const int FrameHeaderBytes = 4;

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

        // Each side's cursor has its own cache line.
        private const int WriteCursorField = 0x00;
        private const int WriteFrameRemainingField = 0x08;
        private const int ReadCursorField = 0x40;
        private const int ReadFrameRemainingField = 0x48;
        private const int PayloadField = 0x80;
        private const int BrokenField = 0x84;
        private const int WriteLockField = 0xC0;
        private const int ReadLockField = 0xC8;

        private const int MinCapacity = 0x1000;
        private const int MaxCapacity = 0x100000;
        private const int MaxInstanceCount = 64;
        private const string PipeDirectoryName = "pipes";

        private readonly struct Ring
        {
            internal readonly int Block;
            internal readonly int Data;
            internal readonly int Capacity;

            internal Ring(int Block, int Data, int Capacity)
            {
                this.Block = Block;
                this.Data = Data;
                this.Capacity = Capacity;
            }
        }

        private static readonly uint OwnProcessId = (uint)Environment.ProcessId;

        private FileStream Stream;
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;
        private byte* Base;

        private readonly Ring Inbound;
        private readonly Ring Outbound;
        private readonly int HolderTable;
        private readonly int PeerHolderTable;
        private int HolderSlot = -1;
        private uint ClientGeneration;
        private bool Disposed;

        internal bool IsServer { get; }

        internal string GuestName { get; }

        internal string BackingPath { get; }

        private GuestPipeChannel(bool IsServer, string GuestName, string BackingPath, FileStream Stream,
            MemoryMappedFile Map, MemoryMappedViewAccessor View, byte* Base, int ServerToClient, int ClientToServer)
        {
            this.IsServer = IsServer;
            this.GuestName = GuestName;
            this.BackingPath = BackingPath;
            this.Stream = Stream;
            this.Map = Map;
            this.View = View;
            this.Base = Base;

            Ring ServerToClientRing = new Ring(ServerToClientOffset, DataOffset, ServerToClient);
            Ring ClientToServerRing = new Ring(ClientToServerOffset, DataOffset + ServerToClient, ClientToServer);

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

        internal bool PeerClosed => Base == null || Disconnected || IsBroken(Inbound) || !HasLiveHolder(PeerHolderTable);

        internal bool OutboundBroken => Base != null && IsBroken(in Outbound);

        internal int InboundPayload => Base == null ? 0 : (int)Math.Min(ReadField(Inbound.Block + PayloadField), (uint)Inbound.Capacity);

        internal bool InboundHasBytes => Base != null && Used(Inbound) != 0;

        internal int OutboundFree => Base == null ? 0 : Outbound.Capacity - Used(Outbound);

        internal bool FitsOutbound(int PayloadBytes) => (long)PayloadBytes + FrameHeaderBytes <= Outbound.Capacity;

        private bool IsBroken(in Ring R) => ReadField(R.Block + BrokenField) != 0;

        private void MarkBroken(in Ring R) => WriteField(R.Block + BrokenField, 1);

        private int Used(in Ring R)
        {
            uint Written = ReadField(R.Block + WriteCursorField);
            uint Consumed = ReadField(R.Block + ReadCursorField);
            uint Count = unchecked(Written - Consumed);

            // A peer that died mid update must not turn into an out of range copy.
            if (Count > (uint)R.Capacity)
            {
                MarkBroken(in R);
                return 0;
            }

            return (int)Count;
        }

        private void CopyOut(in Ring R, uint Cursor, Span<byte> Destination)
        {
            int Mask = R.Capacity - 1;
            int Start = (int)(Cursor & (uint)Mask);
            int First = Math.Min(Destination.Length, R.Capacity - Start);

            new ReadOnlySpan<byte>(Base + R.Data + Start, First).CopyTo(Destination);
            if (Destination.Length > First)
                new ReadOnlySpan<byte>(Base + R.Data, Destination.Length - First).CopyTo(Destination.Slice(First));
        }

        private void CopyIn(in Ring R, uint Cursor, ReadOnlySpan<byte> Source)
        {
            int Mask = R.Capacity - 1;
            int Start = (int)(Cursor & (uint)Mask);
            int First = Math.Min(Source.Length, R.Capacity - Start);

            Source.Slice(0, First).CopyTo(new Span<byte>(Base + R.Data + Start, First));
            if (Source.Length > First)
                Source.Slice(First).CopyTo(new Span<byte>(Base + R.Data, Source.Length - First));
        }

        private uint ReadLength(in Ring R, uint Cursor)
        {
            Span<byte> Header = stackalloc byte[FrameHeaderBytes];
            CopyOut(in R, Cursor, Header);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(Header);
        }

        private void AddPayload(in Ring R, int Delta) => Interlocked.Add(ref Unsafe.AsRef<int>(Base + R.Block + PayloadField), Delta);

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
            if (Stolen && ReadField(Outbound.Block + WriteFrameRemainingField) != 0)
                MarkBroken(in Outbound);

            return true;
        }

        internal void UnlockWrite(ulong Token)
        {
            // A writer that stops in a frame leaves no way to find the next one.
            if (Base != null && ReadField(Outbound.Block + WriteFrameRemainingField) != 0)
                MarkBroken(in Outbound);

            Unlock(Outbound.Block + WriteLockField, Token);
        }

        // Byte mode takes whatever is queued, across frame boundaries.
        internal int ReadBytes(Span<byte> Destination)
        {
            if (Base == null || IsBroken(in Inbound))
                return 0;

            int Copied = 0;
            while (Copied < Destination.Length)
            {
                int Available = Used(in Inbound);
                if (Available == 0)
                    break;

                uint Cursor = ReadField(Inbound.Block + ReadCursorField);
                uint Remaining = ReadField(Inbound.Block + ReadFrameRemainingField);

                if (Remaining == 0)
                {
                    if (Available < FrameHeaderBytes)
                        break;

                    uint Length = ReadLength(in Inbound, Cursor);
                    if (Length > MaxFrameBytes)
                    {
                        MarkBroken(in Inbound);
                        break;
                    }

                    WriteField(Inbound.Block + ReadFrameRemainingField, Length);
                    WriteField(Inbound.Block + ReadCursorField, unchecked(Cursor + FrameHeaderBytes));
                    continue;
                }

                int Take = (int)Math.Min(Math.Min(Remaining, (uint)(Destination.Length - Copied)), (uint)Available);
                CopyOut(in Inbound, Cursor, Destination.Slice(Copied, Take));
                WriteField(Inbound.Block + ReadFrameRemainingField, Remaining - (uint)Take);
                WriteField(Inbound.Block + ReadCursorField, unchecked(Cursor + (uint)Take));
                AddPayload(in Inbound, -Take);
                Copied += Take;
            }

            return Copied;
        }

        // False when no message has started.
        internal bool ReadMessage(Span<byte> Destination, out int Copied, out bool MessageLeft)
        {
            Copied = 0;
            MessageLeft = false;

            if (Base == null || IsBroken(in Inbound))
                return false;

            int Available = Used(in Inbound);
            uint Cursor = ReadField(Inbound.Block + ReadCursorField);
            uint Remaining = ReadField(Inbound.Block + ReadFrameRemainingField);

            if (Remaining == 0)
            {
                if (Available < FrameHeaderBytes)
                    return false;

                uint Length = ReadLength(in Inbound, Cursor);
                if (Length > MaxFrameBytes)
                {
                    MarkBroken(in Inbound);
                    return false;
                }

                // A frame that fits the ring is published whole, so a reader never starts one that is still arriving.
                if (Length + FrameHeaderBytes <= (uint)Inbound.Capacity && Available < FrameHeaderBytes + (long)Length)
                    return false;

                Cursor = unchecked(Cursor + FrameHeaderBytes);
                Available -= FrameHeaderBytes;
                Remaining = Length;
                WriteField(Inbound.Block + ReadFrameRemainingField, Remaining);
                WriteField(Inbound.Block + ReadCursorField, Cursor);
            }

            int Take = (int)Math.Min(Math.Min(Remaining, (uint)Destination.Length), (uint)Available);
            if (Take > 0)
            {
                CopyOut(in Inbound, Cursor, Destination.Slice(0, Take));
                WriteField(Inbound.Block + ReadFrameRemainingField, Remaining - (uint)Take);
                WriteField(Inbound.Block + ReadCursorField, unchecked(Cursor + (uint)Take));
                AddPayload(in Inbound, -Take);
            }

            Copied = Take;
            MessageLeft = Remaining - (uint)Take != 0;
            return true;
        }

        // In message mode the copy stops at the end of the current message, and MessageLength is what is left of it.
        internal int Peek(Span<byte> Destination, bool MessageMode, out uint MessageLength)
        {
            MessageLength = 0;
            if (Base == null || IsBroken(in Inbound))
                return 0;

            int Available = Used(in Inbound);
            uint Cursor = ReadField(Inbound.Block + ReadCursorField);
            uint Remaining = ReadField(Inbound.Block + ReadFrameRemainingField);
            bool FirstFrame = true;
            int Copied = 0;

            while (true)
            {
                if (Remaining == 0)
                {
                    if (Available < FrameHeaderBytes)
                        break;

                    Remaining = ReadLength(in Inbound, Cursor);
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
                    CopyOut(in Inbound, Cursor, Destination.Slice(Copied, Take));

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
            if (Base == null || IsBroken(in Outbound))
                return 0;

            int Written = 0;
            while (Written < Source.Length)
            {
                int Free = Outbound.Capacity - Used(in Outbound);
                if (Free <= FrameHeaderBytes)
                    break;

                int Chunk = Math.Min(Source.Length - Written, Free - FrameHeaderBytes);
                PublishFrame(Source.Slice(Written, Chunk));
                Written += Chunk;
            }

            return Written;
        }

        internal bool TryWriteFrame(ReadOnlySpan<byte> Source)
        {
            if (Base == null || IsBroken(in Outbound))
                return false;

            if (Outbound.Capacity - Used(in Outbound) < FrameHeaderBytes + (long)Source.Length)
                return false;

            PublishFrame(Source);
            return true;
        }

        private void PublishFrame(ReadOnlySpan<byte> Payload)
        {
            uint Cursor = ReadField(Outbound.Block + WriteCursorField);
            Span<byte> Header = stackalloc byte[FrameHeaderBytes];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)Payload.Length);
            CopyIn(in Outbound, Cursor, Header);
            CopyIn(in Outbound, unchecked(Cursor + FrameHeaderBytes), Payload);
            AddPayload(in Outbound, Payload.Length);

            // The cursor moves last, so a reader in another process sees the whole frame or none of it.
            WriteField(Outbound.Block + WriteCursorField, unchecked(Cursor + FrameHeaderBytes + (uint)Payload.Length));
        }

        // A message larger than the ring goes in pieces under the write lock. -1 when the length does not fit yet.
        internal int WriteMessagePiece(ReadOnlySpan<byte> Rest, int TotalLength, bool First)
        {
            if (Base == null || IsBroken(in Outbound))
                return -1;

            int Free = Outbound.Capacity - Used(in Outbound);
            uint Cursor = ReadField(Outbound.Block + WriteCursorField);

            if (First)
            {
                if (Free <= FrameHeaderBytes)
                    return -1;

                Span<byte> Header = stackalloc byte[FrameHeaderBytes];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)TotalLength);
                CopyIn(in Outbound, Cursor, Header);
                Cursor = unchecked(Cursor + FrameHeaderBytes);
                Free -= FrameHeaderBytes;
                WriteField(Outbound.Block + WriteFrameRemainingField, (uint)TotalLength);
            }

            int Take = Math.Min(Rest.Length, Free);
            if (Take > 0)
                CopyIn(in Outbound, Cursor, Rest.Slice(0, Take));

            uint Left = ReadField(Outbound.Block + WriteFrameRemainingField) - (uint)Take;
            WriteField(Outbound.Block + WriteFrameRemainingField, Left);
            AddPayload(in Outbound, Take);
            WriteField(Outbound.Block + WriteCursorField, unchecked(Cursor + (uint)Take));
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
            for (int Block = ServerToClientOffset; Block <= ClientToServerOffset; Block += ClientToServerOffset - ServerToClientOffset)
            {
                WriteField(Block + WriteCursorField, 0);
                WriteField(Block + WriteFrameRemainingField, 0);
                WriteField(Block + ReadCursorField, 0);
                WriteField(Block + ReadFrameRemainingField, 0);
                WriteField(Block + PayloadField, 0);
                WriteField(Block + BrokenField, 0);
                Volatile.Write(ref Unsafe.AsRef<ulong>(Base + Block + WriteLockField), 0);
                Volatile.Write(ref Unsafe.AsRef<ulong>(Base + Block + ReadLockField), 0);
            }

            SessionHolders.Clear(Base + ClientHoldersOffset, HolderSlots);
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

        private static string PipeDirectory => Path.Combine(GuestSession.Directory, PipeDirectoryName);

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

        private static ulong NameHash(string Name)
        {
            ulong Hash = 14695981039346656037UL;
            for (int i = 0; i < Name.Length; i++)
            {
                Hash ^= char.ToLowerInvariant(Name[i]);
                Hash *= 1099511628211UL;
            }

            return Hash;
        }

        private static string InstancePath(string GuestName, int Instance)
            => Path.Combine(PipeDirectory, NameHash(GuestName).ToString("x16") + "." + Instance.ToString() + ".pipe");

        private static void EnsureDirectory()
        {
            string Directory = PipeDirectory;
            System.IO.Directory.CreateDirectory(Directory);

            if (!OperatingSystem.IsWindows())
            {
                try
                {
                    File.SetUnixFileMode(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestPipeChannel] Cannot restrict the pipe directory: {Error.Message}");
                }
            }
        }

        private static bool TryMap(string Path, FileMode Mode, long Length, out FileStream Stream,
            out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* Base)
        {
            Stream = null;
            Map = null;
            View = null;
            Base = null;

            try
            {
                Stream = new FileStream(Path, Mode, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

                if (Length > 0 && Stream.Length < Length)
                    Stream.SetLength(Length);

                if (Stream.Length < DataOffset + (MinCapacity * 2))
                {
                    Stream.Dispose();
                    Stream = null;
                    return false;
                }

                Map = MemoryMappedFile.CreateFromFile(Stream, null, Stream.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                View = Map.CreateViewAccessor(0, Stream.Length, MemoryMappedFileAccess.ReadWrite);

                byte* Pointer = null;
                View.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);
                if (Pointer == null)
                {
                    Release(View, Map, Stream);
                    Stream = null;
                    Map = null;
                    View = null;
                    return false;
                }

                Base = Pointer;
                return true;
            }
            catch (Exception)
            {
                View?.Dispose();
                Map?.Dispose();
                Stream?.Dispose();
                Stream = null;
                Map = null;
                View = null;
                Base = null;
                return false;
            }
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

        // A closed instance leaves a gap in the numbers, so the files are listed, not counted.
        private static string[] ExistingInstancePaths(string GuestName)
        {
            try
            {
                return System.IO.Directory.GetFiles(PipeDirectory, NameHash(GuestName).ToString("x16") + ".*.pipe");
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return Array.Empty<string>();
            }
        }

        internal static bool ServerExists(string GuestName)
        {
            foreach (string Path in ExistingInstancePaths(GuestName))
            {
                if (!TryMap(Path, FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                try
                {
                    if (!HeaderMatches(At, GuestName, Stream.Length, out _, out _))
                        continue;

                    if (ReadFieldAt(At, StateOffset) == StateListening && HasLiveHolderAt(At, ServerHoldersOffset))
                        return true;
                }
                finally
                {
                    Release(View, Map, Stream);
                }
            }

            return false;
        }

        private static void Release(MemoryMappedViewAccessor View, MemoryMappedFile Map, FileStream Stream)
        {
            try
            {
                View?.SafeMemoryMappedViewHandle.ReleasePointer();
            }
            catch (Exception Error)
            {
                Utils.LogError($"[GuestPipeChannel] Releasing a pipe view failed: {Error.Message}");
            }

            View?.Dispose();
            Map?.Dispose();
            Stream?.Dispose();
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
                EnsureDirectory();
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

                if (!TryMap(Path, FileMode.OpenOrCreate, Length, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                bool Claimed = false;
                try
                {
                    uint Observed = ReadFieldAt(At, StateOffset);
                    if (Observed == StateCreating || Observed == StateDeleting)
                        continue;

                    bool Valid = HeaderValid(At, Stream.Length, out _, out _, out string Stored);

                    if (Observed != StateFree && HasLiveHolderAt(At, ServerHoldersOffset))
                    {
                        if (Valid && string.Equals(Stored, GuestName, StringComparison.OrdinalIgnoreCase))
                            NameTaken = true;
                        continue;
                    }

                    if (Stream.Length < Length || CompareExchangeAt(At, StateOffset, StateCreating, Observed) != Observed)
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

                    Channel = new GuestPipeChannel(true, GuestName, Path, Stream, Map, View, At, ServerToClient, ClientToServer);
                    Channel.HolderSlot = 0;
                    Claimed = true;
                    return NTSTATUS.STATUS_SUCCESS;
                }
                finally
                {
                    if (!Claimed)
                        Release(View, Map, Stream);
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

            if (!TryMap(BackingPath, FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Claimed = false;
            try
            {
                if (!HeaderMatches(At, GuestName, Stream.Length, out int ServerToClient, out int ClientToServer))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (!HasLiveHolderAt(At, ServerHoldersOffset))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (CompareExchangeAt(At, StateOffset, StateConnected, StateListening) != StateListening)
                    return NTSTATUS.STATUS_PIPE_BUSY;

                GuestPipeChannel Client = new GuestPipeChannel(false, GuestName, BackingPath, Stream, Map, View, At, ServerToClient, ClientToServer);
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
                    Release(View, Map, Stream);
            }
        }

        internal static NTSTATUS TryOpenEnd(string BackingPath, bool Server, uint Generation, out GuestPipeChannel Channel)
        {
            Channel = null;

            if (!TryMap(BackingPath, FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Claimed = false;
            try
            {
                if (!HeaderValid(At, Stream.Length, out int ServerToClient, out int ClientToServer, out string Name))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                GuestPipeChannel End = new GuestPipeChannel(Server, Name, BackingPath, Stream, Map, View, At, ServerToClient, ClientToServer);
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
                    Release(View, Map, Stream);
            }
        }

        internal static void PurgeAbandoned()
        {
            string Directory = PipeDirectory;

            if (!System.IO.Directory.Exists(Directory))
                return;

            string[] Files;
            try
            {
                Files = System.IO.Directory.GetFiles(Directory, "*.pipe");
            }
            catch (Exception Error)
            {
                Utils.LogError($"[GuestPipeChannel] Cannot list the pipe directory: {Error.Message}");
                return;
            }

            for (int i = 0; i < Files.Length; i++)
            {
                if (!TryMap(Files[i], FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                bool Abandoned;
                try
                {
                    // No magic or StateCreating means a server is still setting the file up. StateDeleting is taken by
                    // compare and exchange, so no creator can claim the file before it is gone.
                    uint Observed = ReadFieldAt(At, StateOffset);
                    Abandoned = ReadFieldAt(At, MagicOffset) == HeaderMagic &&
                                (ReadFieldAt(At, VersionOffset) != HeaderVersion ||
                                 (Observed != StateCreating && !HasLiveHolderAt(At, ServerHoldersOffset) &&
                                  CompareExchangeAt(At, StateOffset, StateDeleting, Observed) == Observed));
                }
                finally
                {
                    Release(View, Map, Stream);
                }

                if (!Abandoned)
                    continue;

                try
                {
                    File.Delete(Files[i]);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestPipeChannel] Cannot remove an abandoned pipe: {Error.Message}");
                }
            }
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

            Release(View, Map, Stream);

            View = null;
            Map = null;
            Stream = null;
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
