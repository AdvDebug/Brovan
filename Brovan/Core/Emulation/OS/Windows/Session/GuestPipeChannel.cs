using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// One end of a guest named pipe, carried by a memory mapped file in the session directory.
    /// </summary>
    /// <remarks>
    /// The cursors need no lock because each side only advances the one for the direction it produces, and
    /// every guest thread of a process runs on one host thread, so each side has a single producer.
    /// </remarks>
    internal sealed unsafe class GuestPipeChannel : IDisposable
    {
        internal const uint StateFree = 0;
        internal const uint StateListening = 1;
        internal const uint StateConnected = 2;

        private const uint HeaderMagic = 0x31505642;
        private const uint HeaderVersion = 1;

        private const int MagicOffset = 0x00;
        private const int VersionOffset = 0x04;
        private const int StateOffset = 0x08;
        private const int ServerProcessOffset = 0x0C;
        private const int ClientProcessOffset = 0x10;
        private const int PipeTypeOffset = 0x14;
        private const int MaxInstancesOffset = 0x18;
        private const int ServerToClientCapacityOffset = 0x1C;
        private const int ClientToServerCapacityOffset = 0x20;
        private const int ServerClosedOffset = 0x24;
        private const int ClientClosedOffset = 0x28;
        private const int NameLengthOffset = 0x2C;
        private const int NameOffset = 0x30;
        private const int MaxNameBytes = 0x200;

        // One cache line each, or the two sides fight over one.
        private const int ServerToClientWriteOffset = 0x240;
        private const int ServerToClientReadOffset = 0x280;
        private const int ClientToServerWriteOffset = 0x2C0;
        private const int ClientToServerReadOffset = 0x300;
        private const int DataOffset = 0x400;

        private const int MinCapacity = 0x1000;
        private const int MaxCapacity = 0x100000;
        private const int MaxInstanceCount = 64;
        private const string PipeDirectoryName = "pipes";

        private FileStream Stream;
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;
        private byte* Base;

        private readonly int InboundCapacity;
        private readonly int OutboundCapacity;
        private readonly int InboundDataOffset;
        private readonly int OutboundDataOffset;
        private readonly int InboundWriteOffset;
        private readonly int InboundReadOffset;
        private readonly int OutboundWriteOffset;
        private readonly int OutboundReadOffset;

        private bool Broken;
        private bool Disposed;

        internal bool IsServer { get; }

        internal string GuestName { get; }

        internal string BackingPath { get; }

        private GuestPipeChannel(bool IsServer, string GuestName, string BackingPath, FileStream Stream,
            MemoryMappedFile Map, MemoryMappedViewAccessor View, byte* Base,
            int ServerToClientCapacity, int ClientToServerCapacity)
        {
            this.IsServer = IsServer;
            this.GuestName = GuestName;
            this.BackingPath = BackingPath;
            this.Stream = Stream;
            this.Map = Map;
            this.View = View;
            this.Base = Base;

            if (IsServer)
            {
                OutboundCapacity = ServerToClientCapacity;
                InboundCapacity = ClientToServerCapacity;
                OutboundDataOffset = DataOffset;
                InboundDataOffset = DataOffset + ServerToClientCapacity;
                OutboundWriteOffset = ServerToClientWriteOffset;
                OutboundReadOffset = ServerToClientReadOffset;
                InboundWriteOffset = ClientToServerWriteOffset;
                InboundReadOffset = ClientToServerReadOffset;
            }
            else
            {
                OutboundCapacity = ClientToServerCapacity;
                InboundCapacity = ServerToClientCapacity;
                OutboundDataOffset = DataOffset + ServerToClientCapacity;
                InboundDataOffset = DataOffset;
                OutboundWriteOffset = ClientToServerWriteOffset;
                OutboundReadOffset = ClientToServerReadOffset;
                InboundWriteOffset = ServerToClientWriteOffset;
                InboundReadOffset = ServerToClientReadOffset;
            }
        }

        internal uint State => Base == null ? StateFree : ReadField(StateOffset);

        internal bool Connected => !Broken && Base != null && ReadField(StateOffset) == StateConnected;

        internal bool PeerClosed
        {
            get
            {
                if (Broken || Base == null)
                    return true;

                if (ReadField(IsServer ? ClientClosedOffset : ServerClosedOffset) != 0)
                    return true;

                uint PeerProcess = ReadField(IsServer ? ClientProcessOffset : ServerProcessOffset);
                return PeerProcess != 0 && !GuestSession.IsHostAlive(PeerProcess);
            }
        }

        internal uint PipeType => Base == null ? 0 : ReadField(PipeTypeOffset);

        internal uint MaximumInstances => Base == null ? 1 : ReadField(MaxInstancesOffset);

        internal uint InboundQuota => (uint)InboundCapacity;

        internal uint OutboundQuota => (uint)OutboundCapacity;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint ReadField(int Offset) => Volatile.Read(ref Unsafe.AsRef<uint>(Base + Offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void WriteField(int Offset, uint Value) => Volatile.Write(ref Unsafe.AsRef<uint>(Base + Offset), Value);

        private static uint ReadFieldAt(byte* From, int Offset) => Volatile.Read(ref Unsafe.AsRef<uint>(From + Offset));

        private static void WriteFieldAt(byte* At, int Offset, uint Value) => Volatile.Write(ref Unsafe.AsRef<uint>(At + Offset), Value);

        private static uint ExchangeState(byte* At, uint Value, uint Comparand)
            => Interlocked.CompareExchange(ref Unsafe.AsRef<uint>(At + StateOffset), Value, Comparand);

        internal int Available
        {
            get
            {
                if (Broken || Base == null)
                    return 0;

                return MeasureUsed(InboundWriteOffset, InboundReadOffset, InboundCapacity);
            }
        }

        private int MeasureUsed(int WriteOffset, int ReadOffset, int Capacity)
        {
            uint Written = ReadField(WriteOffset);
            uint Consumed = ReadField(ReadOffset);
            uint Used = unchecked(Written - Consumed);

            // A peer that died mid update must not turn into an out of range copy.
            if (Used > (uint)Capacity)
            {
                Broken = true;
                return 0;
            }

            return (int)Used;
        }

        internal int Read(Span<byte> Destination)
        {
            if (Broken || Base == null || Destination.Length == 0)
                return 0;

            int Used = MeasureUsed(InboundWriteOffset, InboundReadOffset, InboundCapacity);
            if (Used <= 0)
                return 0;

            int Count = Math.Min(Used, Destination.Length);
            uint Consumed = ReadField(InboundReadOffset);
            int Mask = InboundCapacity - 1;
            int Start = (int)(Consumed & (uint)Mask);
            int First = Math.Min(Count, InboundCapacity - Start);

            new ReadOnlySpan<byte>(Base + InboundDataOffset + Start, First).CopyTo(Destination);
            if (Count > First)
                new ReadOnlySpan<byte>(Base + InboundDataOffset, Count - First).CopyTo(Destination.Slice(First));

            WriteField(InboundReadOffset, unchecked(Consumed + (uint)Count));
            return Count;
        }

        internal int Write(ReadOnlySpan<byte> Source)
        {
            if (Broken || Base == null || Source.Length == 0)
                return 0;

            int Used = MeasureUsed(OutboundWriteOffset, OutboundReadOffset, OutboundCapacity);
            int Free = OutboundCapacity - Used;
            if (Broken || Free <= 0)
                return 0;

            int Count = Math.Min(Free, Source.Length);
            uint Written = ReadField(OutboundWriteOffset);
            int Mask = OutboundCapacity - 1;
            int Start = (int)(Written & (uint)Mask);
            int First = Math.Min(Count, OutboundCapacity - Start);

            Source.Slice(0, First).CopyTo(new Span<byte>(Base + OutboundDataOffset + Start, First));
            if (Count > First)
                Source.Slice(First, Count - First).CopyTo(new Span<byte>(Base + OutboundDataOffset, Count - First));

            WriteField(OutboundWriteOffset, unchecked(Written + (uint)Count));
            return Count;
        }

        /// <summary>
        /// The instance goes back to listening rather than closing.
        /// </summary>
        internal void Disconnect()
        {
            if (Base == null || !IsServer)
                return;

            WriteField(ServerToClientWriteOffset, 0);
            WriteField(ServerToClientReadOffset, 0);
            WriteField(ClientToServerWriteOffset, 0);
            WriteField(ClientToServerReadOffset, 0);
            WriteField(ClientProcessOffset, 0);
            WriteField(ClientClosedOffset, 0);
            WriteField(StateOffset, StateListening);
            Broken = false;
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
                catch (Exception)
                {
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
                    View.Dispose();
                    Map.Dispose();
                    Stream.Dispose();
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

        private static bool HeaderMatches(byte* At, string GuestName, long FileLength, out int ServerToClient, out int ClientToServer)
        {
            ServerToClient = 0;
            ClientToServer = 0;

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

            string Stored = NameBytes == 0 ? string.Empty : Encoding.Unicode.GetString(At + NameOffset, (int)NameBytes);
            if (!string.Equals(Stored, GuestName, StringComparison.OrdinalIgnoreCase))
                return false;

            ServerToClient = First;
            ClientToServer = Second;
            return true;
        }

        private static void InitialiseHeader(byte* At, string GuestName, uint PipeType, uint MaxInstances,
            int ServerToClient, int ClientToServer)
        {
            new Span<byte>(At, DataOffset).Clear();

            byte[] Name = Encoding.Unicode.GetBytes(GuestName);
            int NameBytes = Math.Min(Name.Length, MaxNameBytes);
            if (NameBytes > 0)
                Name.AsSpan(0, NameBytes).CopyTo(new Span<byte>(At + NameOffset, NameBytes));

            WriteFieldAt(At, NameLengthOffset, (uint)NameBytes);
            WriteFieldAt(At, PipeTypeOffset, PipeType);
            WriteFieldAt(At, MaxInstancesOffset, MaxInstances);
            WriteFieldAt(At, ServerToClientCapacityOffset, (uint)ServerToClient);
            WriteFieldAt(At, ClientToServerCapacityOffset, (uint)ClientToServer);
            WriteFieldAt(At, ServerProcessOffset, (uint)Environment.ProcessId);
            WriteFieldAt(At, VersionOffset, HeaderVersion);

            // Written last, so a reader sees a finished header or none.
            WriteFieldAt(At, MagicOffset, HeaderMagic);
            WriteFieldAt(At, StateOffset, StateListening);
        }

        internal static bool ServerExists(string GuestName)
        {
            for (int Instance = 0; Instance < MaxInstanceCount; Instance++)
            {
                string Path = InstancePath(GuestName, Instance);

                // Instances are taken from the lowest free index, so the first gap ends the scan.
                if (!File.Exists(Path))
                    break;

                if (!TryMap(Path, FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                try
                {
                    if (!HeaderMatches(At, GuestName, Stream.Length, out _, out _))
                        continue;

                    uint State = ReadFieldAt(At, StateOffset);
                    if (State != StateListening && State != StateConnected)
                        continue;

                    if (GuestSession.IsHostAlive(ReadFieldAt(At, ServerProcessOffset)))
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
            catch (Exception)
            {
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
                    bool Existing = HeaderMatches(At, GuestName, Stream.Length, out int HeldServerToClient, out int HeldClientToServer);
                    uint State = Existing ? ReadFieldAt(At, StateOffset) : StateFree;
                    bool Live = Existing && State != StateFree && GuestSession.IsHostAlive(ReadFieldAt(At, ServerProcessOffset));

                    if (Live)
                    {
                        NameTaken = true;
                        continue;
                    }

                    InitialiseHeader(At, GuestName, PipeType, (uint)Limit, ServerToClient, ClientToServer);

                    Channel = new GuestPipeChannel(true, GuestName, Path, Stream, Map, View, At, ServerToClient, ClientToServer);
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

            for (int Instance = 0; Instance < MaxInstanceCount; Instance++)
            {
                string Path = InstancePath(GuestName, Instance);

                // Instances are taken from the lowest free index, so the first gap ends the scan.
                if (!File.Exists(Path))
                    break;

                if (!TryMap(Path, FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                bool Claimed = false;
                try
                {
                    if (!HeaderMatches(At, GuestName, Stream.Length, out int ServerToClient, out int ClientToServer))
                        continue;

                    if (!GuestSession.IsHostAlive(ReadFieldAt(At, ServerProcessOffset)))
                        continue;

                    Seen = true;

                    if (ExchangeState(At, StateConnected, StateListening) != StateListening)
                        continue;

                    WriteFieldAt(At, ClientProcessOffset, (uint)Environment.ProcessId);
                    WriteFieldAt(At, ClientClosedOffset, 0);

                    Channel = new GuestPipeChannel(false, GuestName, Path, Stream, Map, View, At, ServerToClient, ClientToServer);
                    Claimed = true;
                    return NTSTATUS.STATUS_SUCCESS;
                }
                finally
                {
                    if (!Claimed)
                        Release(View, Map, Stream);
                }
            }

            return Seen ? NTSTATUS.STATUS_PIPE_BUSY : NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
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
            catch (Exception)
            {
                return;
            }

            for (int i = 0; i < Files.Length; i++)
            {
                if (!TryMap(Files[i], FileMode.Open, 0, out FileStream Stream, out MemoryMappedFile Map, out MemoryMappedViewAccessor View, out byte* At))
                    continue;

                bool Abandoned;
                try
                {
                    Abandoned = ReadFieldAt(At, MagicOffset) != HeaderMagic ||
                                !GuestSession.IsHostAlive(ReadFieldAt(At, ServerProcessOffset));
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
                catch (Exception)
                {
                }
            }
        }

        public void Dispose()
        {
            if (Disposed)
                return;

            Disposed = true;

            if (Base != null)
            {
                WriteField(IsServer ? ServerClosedOffset : ClientClosedOffset, 1);

                if (IsServer)
                    WriteField(StateOffset, StateFree);
                else
                    ExchangeState(Base, StateListening, StateConnected);
            }

            Release(View, Map, Stream);

            View = null;
            Map = null;
            Stream = null;
            Base = null;

            if (IsServer && BackingPath != null)
            {
                try
                {
                    File.Delete(BackingPath);
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
