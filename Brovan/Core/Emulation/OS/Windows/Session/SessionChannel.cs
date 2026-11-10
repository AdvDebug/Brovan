using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed unsafe class SessionMapping : IDisposable
    {
        private FileStream Stream;
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;

        internal byte* Base { get; private set; }

        internal long Length { get; }

        internal uint ReadUInt32(int Offset) => Volatile.Read(ref *(uint*)(Base + Offset));

        internal ulong ReadUInt64(int Offset) => Volatile.Read(ref *(ulong*)(Base + Offset));

        internal void WriteUInt32(int Offset, uint Value) => Volatile.Write(ref *(uint*)(Base + Offset), Value);

        internal void WriteUInt64(int Offset, ulong Value) => Volatile.Write(ref *(ulong*)(Base + Offset), Value);

        internal ref ulong UInt64At(int Offset) => ref *(ulong*)(Base + Offset);

        private SessionMapping(FileStream Stream, MemoryMappedFile Map, MemoryMappedViewAccessor View, byte* Base, long Length)
        {
            this.Stream = Stream;
            this.Map = Map;
            this.View = View;
            this.Base = Base;
            this.Length = Length;
        }

        internal static SessionMapping OpenFile(string Location, FileMode Mode, long Length)
        {
            FileStream Stream = null;
            try
            {
                Stream = new FileStream(Location, Mode, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
                if (Stream.Length < Length)
                    Stream.SetLength(Length);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[SessionMapping] Cannot open {Location}: {Error.Message}");
                Stream?.Dispose();
                return null;
            }

            return MapFile(Stream, Length, Location);
        }

        // Owns Stream, even when it fails.
        internal static SessionMapping MapFile(FileStream Stream, long Length, string Location)
        {
            MemoryMappedFile Mapping;
            try
            {
                Mapping = MemoryMappedFile.CreateFromFile(Stream, null, Math.Max(Length, Stream.Length), MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException || Error is ArgumentException)
            {
                Utils.LogError($"[SessionMapping] Cannot map {Location}: {Error.Message}");
                Stream.Dispose();
                return null;
            }

            return Wrap(Stream, Mapping, Length, Location);
        }

        // Owns Stream and Mapping, even when it fails.
        internal static SessionMapping Wrap(FileStream Stream, MemoryMappedFile Mapping, long Length, string Location)
        {
            MemoryMappedViewAccessor Accessor = null;
            try
            {
                Accessor = Mapping.CreateViewAccessor(0, Length, MemoryMappedFileAccess.ReadWrite);

                byte* Pointer = null;
                Accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);
                if (Pointer != null)
                    return new SessionMapping(Stream, Mapping, Accessor, Pointer + Accessor.PointerOffset, Length);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException || Error is ArgumentException)
            {
                Utils.LogError($"[SessionMapping] Cannot map a view of {Location}: {Error.Message}");
            }

            Accessor?.Dispose();
            Mapping.Dispose();
            Stream?.Dispose();
            return null;
        }

        public void Dispose()
        {
            if (Base == null)
                return;

            try
            {
                View.SafeMemoryMappedViewHandle.ReleasePointer();
            }
            catch (Exception Error)
            {
                Utils.LogError($"[SessionMapping] Releasing a view failed: {Error.Message}");
            }

            View.Dispose();
            Map.Dispose();
            Stream?.Dispose();
            View = null;
            Map = null;
            Stream = null;
            Base = null;
        }
    }

    internal readonly unsafe struct SessionRing
    {
        internal const int FrameHeaderBytes = 4;

        internal const int WriteCursorField = 0x00;
        internal const int WriteFrameRemainingField = 0x08;
        internal const int ReadCursorField = 0x40;
        internal const int ReadFrameRemainingField = 0x48;
        internal const int PayloadField = 0x80;
        internal const int BrokenField = 0x84;

        private readonly byte* Base;
        internal readonly int Block;
        private readonly int Data;
        internal readonly int Capacity;

        internal SessionRing(byte* Base, int Block, int Data, int Capacity)
        {
            this.Base = Base;
            this.Block = Block;
            this.Data = Data;
            this.Capacity = Capacity;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal uint ReadField(int Field) => Volatile.Read(ref Unsafe.AsRef<uint>(Base + Block + Field));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void WriteField(int Field, uint Value) => Volatile.Write(ref Unsafe.AsRef<uint>(Base + Block + Field), Value);

        internal bool IsBroken => ReadField(BrokenField) != 0;

        internal void MarkBroken() => WriteField(BrokenField, 1);

        internal void AddPayload(int Delta) => Interlocked.Add(ref Unsafe.AsRef<int>(Base + Block + PayloadField), Delta);

        internal int Free => Capacity - Used();

        internal int Used()
        {
            uint Written = ReadField(WriteCursorField);
            uint Consumed = ReadField(ReadCursorField);
            uint Count = unchecked(Written - Consumed);

            // A peer that died mid update must not turn into an out of range copy.
            if (Count > (uint)Capacity)
            {
                MarkBroken();
                return 0;
            }

            return (int)Count;
        }

        internal void CopyOut(uint Cursor, Span<byte> Destination)
        {
            int Start = (int)(Cursor & (uint)(Capacity - 1));
            int First = Math.Min(Destination.Length, Capacity - Start);

            new ReadOnlySpan<byte>(Base + Data + Start, First).CopyTo(Destination);
            if (Destination.Length > First)
                new ReadOnlySpan<byte>(Base + Data, Destination.Length - First).CopyTo(Destination.Slice(First));
        }

        internal void CopyIn(uint Cursor, ReadOnlySpan<byte> Source)
        {
            int Start = (int)(Cursor & (uint)(Capacity - 1));
            int First = Math.Min(Source.Length, Capacity - Start);

            Source.Slice(0, First).CopyTo(new Span<byte>(Base + Data + Start, First));
            if (Source.Length > First)
                Source.Slice(First).CopyTo(new Span<byte>(Base + Data, Source.Length - First));
        }

        internal uint ReadLength(uint Cursor)
        {
            Span<byte> Header = stackalloc byte[FrameHeaderBytes];
            CopyOut(Cursor, Header);
            return BinaryPrimitives.ReadUInt32LittleEndian(Header);
        }

        internal bool TryWriteFrame(ReadOnlySpan<byte> Payload)
        {
            if (IsBroken || Free < FrameHeaderBytes + (long)Payload.Length)
                return false;

            PublishFrame(Payload);
            return true;
        }

        internal void PublishFrame(ReadOnlySpan<byte> Payload)
        {
            uint Cursor = ReadField(WriteCursorField);
            Span<byte> Header = stackalloc byte[FrameHeaderBytes];
            BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)Payload.Length);
            CopyIn(Cursor, Header);
            CopyIn(unchecked(Cursor + FrameHeaderBytes), Payload);
            AddPayload(Payload.Length);

            // The cursor moves last, so a reader in another process sees the whole frame or none of it.
            WriteField(WriteCursorField, unchecked(Cursor + FrameHeaderBytes + (uint)Payload.Length));
        }

        // The writer moves its cursor only after a whole frame, so a length that does not fit means a broken peer.
        internal bool TryReadFrame(Span<byte> Destination, out int Length)
        {
            Length = 0;
            if (IsBroken)
                return false;

            int Written = Used();
            if (Written < FrameHeaderBytes)
                return false;

            uint Cursor = ReadField(ReadCursorField);
            uint FrameLength = ReadLength(Cursor);
            if (FrameLength > (uint)Destination.Length || FrameLength > (uint)(Written - FrameHeaderBytes))
            {
                MarkBroken();
                return false;
            }

            CopyOut(unchecked(Cursor + FrameHeaderBytes), Destination.Slice(0, (int)FrameLength));
            AddPayload(-(int)FrameLength);
            WriteField(ReadCursorField, unchecked(Cursor + FrameHeaderBytes + FrameLength));
            Length = (int)FrameLength;
            return true;
        }

        internal void Clear()
        {
            WriteField(WriteCursorField, 0);
            WriteField(WriteFrameRemainingField, 0);
            WriteField(ReadCursorField, 0);
            WriteField(ReadFrameRemainingField, 0);
            WriteField(PayloadField, 0);
            WriteField(BrokenField, 0);
        }
    }

    internal static class SessionNames
    {
        internal const string Pipes = "pipes";
        internal const string AlpcPorts = "alpc";
        internal const string AlpcChannels = "alpcchan";

        internal static string DirectoryOf(string Kind) => Path.Combine(GuestSession.Directory, Kind);

        internal static void EnsureDirectory(string Kind) => GuestSession.CreatePrivateDirectory(DirectoryOf(Kind));

        // Guest names compare without regard to case.
        internal static ulong Hash(string Name)
        {
            ulong Hash = 14695981039346656037UL;
            for (int i = 0; i < Name.Length; i++)
            {
                Hash ^= char.ToLowerInvariant(Name[i]);
                Hash *= 1099511628211UL;
            }

            return Hash;
        }

        internal static string InstancePath(string Kind, string Name, int Instance, string Extension)
            => Path.Combine(DirectoryOf(Kind), Hash(Name).ToString("x16") + "." + Instance.ToString() + Extension);

        // A closed instance leaves a gap in the numbers, so the files are listed, not counted.
        internal static string[] InstancePaths(string Kind, string Name, string Extension)
        {
            try
            {
                return System.IO.Directory.GetFiles(DirectoryOf(Kind), Hash(Name).ToString("x16") + ".*" + Extension);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return Array.Empty<string>();
            }
        }

        internal static void PurgeAbandoned(string Kind, string Extension, Action<string> RemoveIfAbandoned)
        {
            string Directory = DirectoryOf(Kind);
            if (!System.IO.Directory.Exists(Directory))
                return;

            string[] Files;
            try
            {
                Files = System.IO.Directory.GetFiles(Directory, "*" + Extension);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[SessionNames] Cannot list the {Kind} directory: {Error.Message}");
                return;
            }

            foreach (string Location in Files)
                RemoveIfAbandoned(Location);
        }

        internal static void Delete(string Location)
        {
            try
            {
                File.Delete(Location);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[SessionNames] Cannot remove {Path.GetFileName(Location)}: {Error.Message}");
            }
        }
    }
}
