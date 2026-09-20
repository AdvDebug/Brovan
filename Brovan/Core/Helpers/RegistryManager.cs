using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers
{
    // Reads and in place writes go through the mapping. The file handle only grows the file.
    public sealed unsafe class RegistryHiveMap : IDisposable
    {
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;
        private byte* Base;

        public long Length { get; private set; }

        public static RegistryHiveMap TryCreate(FileStream Stream, long Length, bool Writable)
        {
            if (Stream == null || Length <= 0)
                return null;

            MemoryMappedFile Created = null;
            MemoryMappedViewAccessor Opened = null;

            try
            {
                MemoryMappedFileAccess Access = Writable ? MemoryMappedFileAccess.ReadWrite : MemoryMappedFileAccess.Read;

                Created = MemoryMappedFile.CreateFromFile(Stream, null, Length, Access, HandleInheritability.None, true);
                Opened = Created.CreateViewAccessor(0, Length, Access);

                byte* Pointer = null;
                Opened.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);

                if (Pointer == null)
                {
                    Opened.Dispose();
                    Created.Dispose();
                    return null;
                }

                return new RegistryHiveMap { Map = Created, View = Opened, Base = Pointer, Length = Length };
            }
            catch (Exception)
            {
                try { Opened?.Dispose(); } catch { }
                try { Created?.Dispose(); } catch { }
                return null;
            }
        }

        public bool Covers(long Offset, int Count)
        {
            return Base != null && Offset >= 0 && Count >= 0 && Offset + Count <= Length;
        }

        public ReadOnlySpan<byte> Read(long Offset, int Count)
        {
            return new ReadOnlySpan<byte>(Base + Offset, Count);
        }

        public int ReadInt32(long Offset)
        {
            return Unsafe.ReadUnaligned<int>(Base + Offset);
        }

        public short ReadInt16(long Offset)
        {
            return Unsafe.ReadUnaligned<short>(Base + Offset);
        }

        public bool Matches(long Offset, byte First, byte Second)
        {
            byte* At = Base + Offset;
            return At[0] == First && At[1] == Second;
        }

        public void Write(long Offset, ReadOnlySpan<byte> Data)
        {
            Data.CopyTo(new Span<byte>(Base + Offset, Data.Length));
        }

        public void Dispose()
        {
            try
            {
                if (View != null)
                {
                    View.SafeMemoryMappedViewHandle.ReleasePointer();
                    View.Dispose();
                    View = null;
                }
            }
            catch
            {
            }

            try
            {
                if (Map != null)
                {
                    Map.Dispose();
                    Map = null;
                }
            }
            catch
            {
            }

            Base = null;
            Length = 0;
        }
    }

    public class Hive : IDisposable
    {
        private const int LockTimeoutMilliseconds = 5000;

        internal string NtMountPoint;
        internal RegistryHiveReader Reader;
        internal RegistryHiveWriter Writer;

        internal FileStream Stream;
        internal SafeFileHandle Handle;
        internal RegistryHiveMap Map;
        internal long Length;
        internal Mutex WriteLock;

        private uint SeenSequence;
        private uint SeenSecondSequence;

        internal bool Writable => Writer != null;

        internal uint ReaderGeneration => Reader != null ? Reader.Generation : 0;

        internal void NoteCurrentSequence()
        {
            try
            {
                Reader.TryReadSequence(out SeenSequence, out SeenSecondSequence);
            }
            catch
            {
            }
        }

        // NT leaves the two header sequence numbers apart while a write is in flight, so both have to match.
        internal void SyncFromDisk()
        {
            uint First;
            uint Second;

            try
            {
                if (!Reader.TryReadSequence(out First, out Second))
                    return;
            }
            catch
            {
                return;
            }

            if (First == SeenSequence && Second == SeenSecondSequence)
                return;

            SeenSequence = First;
            SeenSecondSequence = Second;

            if (Writer != null)
            {
                Writer.ReloadHeader();
                Length = Writer.FileLength;
            }

            Reader.Invalidate(Length);
        }

        internal bool CreateKey(string RelativePath, out bool CreatedNew)
        {
            bool Created = false;
            bool Result = Mutate(RelativePath, null, 0, null, MutationKind.CreateKey, ref Created);
            CreatedNew = Created;
            return Result;
        }

        internal bool DeleteKey(string RelativePath)
        {
            bool Created = false;
            return Mutate(RelativePath, null, 0, null, MutationKind.DeleteKey, ref Created);
        }

        internal bool SetValue(string RelativePath, string Name, int Type, byte[] Data)
        {
            bool Created = false;
            return Mutate(RelativePath, Name, Type, Data, MutationKind.SetValue, ref Created);
        }

        internal bool DeleteValue(string RelativePath, string Name)
        {
            bool Created = false;
            return Mutate(RelativePath, Name, 0, null, MutationKind.DeleteValue, ref Created);
        }

        private enum MutationKind
        {
            CreateKey,
            DeleteKey,
            SetValue,
            DeleteValue
        }

        private bool Mutate(string RelativePath, string Name, int Type, byte[] Data, MutationKind Kind, ref bool CreatedNew)
        {
            if (Writer == null)
                return false;

            bool Held = false;

            try
            {
                try
                {
                    Held = WriteLock == null || WriteLock.WaitOne(LockTimeoutMilliseconds);
                }
                catch (AbandonedMutexException)
                {
                    Held = true;
                }

                if (!Held)
                    return false;

                SyncFromDisk();

                try
                {
                    switch (Kind)
                    {
                        case MutationKind.CreateKey:
                            return Writer.TryCreateKey(RelativePath, out CreatedNew);
                        case MutationKind.DeleteKey:
                            return Writer.TryDeleteKey(RelativePath);
                        case MutationKind.SetValue:
                            return Writer.TrySetValue(RelativePath, Name, Type, Data);
                        default:
                            return Writer.TryDeleteValue(RelativePath, Name);
                    }
                }
                finally
                {
                    // Cells are written before they are linked, so a half done change still has to be published.
                    Writer.CommitHeader();

                    SeenSequence = Writer.CurrentSequence;
                    SeenSecondSequence = Writer.CurrentSequence;
                    Length = Writer.FileLength;
                    Remap();

                    Reader.NoteWrite(Length, Kind == MutationKind.DeleteKey ? RelativePath : null);
                }
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                if (Held && WriteLock != null)
                {
                    try { WriteLock.ReleaseMutex(); } catch { }
                }
            }
        }

        // A new hive bin lands past the end of the mapping.
        private void Remap()
        {
            if (Map == null || Map.Length >= Length)
                return;

            RegistryHiveMap Replacement = RegistryHiveMap.TryCreate(Stream, Length, Writer != null);
            if (Replacement == null)
                return;

            Map.Dispose();
            Map = Replacement;
            Reader?.UseMap(Replacement);
            Writer?.UseMap(Replacement);
        }

        public void Dispose()
        {
            try { Reader = null; } catch { }
            try { Writer = null; } catch { }
            try { Handle = null; } catch { }

            try
            {
                if (Map != null)
                {
                    Map.Dispose();
                    Map = null;
                }
            }
            catch
            {
            }

            try
            {
                if (Stream != null)
                {
                    Stream.Dispose();
                    Stream = null;
                }
            }
            catch
            {
            }

            try
            {
                if (WriteLock != null)
                {
                    WriteLock.Dispose();
                    WriteLock = null;
                }
            }
            catch
            {
            }
        }
    }

    public class KeyNode
    {
        public string FullPath;
        public int CellOffset;
        public Dictionary<string, ValueNode> Values = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, KeyNode> Subkeys = new(StringComparer.OrdinalIgnoreCase);
        public bool ValuesParsed;
    }

    public class ValueNode
    {
        public string Name;
        public int Type;
        public byte[] Data;
    }

    public sealed class RegistryHiveReader
    {
        internal const int MainRootOffset = 0x1000;
        internal const int MaxDataSegment = 16344;

        internal const ushort ListFast = 'l' | ('f' << 8);
        internal const ushort ListHashed = 'l' | ('h' << 8);
        internal const ushort ListPlain = 'l' | ('i' << 8);
        internal const ushort ListIndex = 'r' | ('i' << 8);

        private const int NameCompressedFlag = 0x0020;
        private const int ValueNameCompressedFlag = 0x0001;

        private readonly SafeFileHandle Handle;
        private RegistryHiveMap Map;
        private long Length;

        private readonly Dictionary<string, PathEntry> PathCache = new(StringComparer.OrdinalIgnoreCase);
        private HiveKey CachedRootKey;

        private struct PathEntry
        {
            public HiveKey Key;
            public uint Generation;
        }

        // Bumped when the hive changes, so a HiveKey re-reads its cell.
        internal uint Generation;

        public RegistryHiveReader(SafeFileHandle Handle, long Length)
        {
            this.Handle = Handle ?? throw new ArgumentNullException(nameof(Handle));
            this.Length = Length;
            ValidateRegf();
        }

        internal void Invalidate(long NewLength)
        {
            Length = NewLength;
            PathCache.Clear();
            CachedRootKey = null;
            Generation++;
        }

        // A key cell never moves while it lives, so only a removed path leaves the cache. It is cached under
        // every spelling the traversal used, so all of them go.
        internal void NoteWrite(long NewLength, string RemovedPath)
        {
            Length = NewLength;
            Generation++;

            if (string.IsNullOrEmpty(RemovedPath))
                return;

            RemovedPath = NormalizeRelativePath(RemovedPath);

            DropPathAndDescendants(RemovedPath);

            string Rewritten = RewriteControlSet(RemovedPath);
            if (!ReferenceEquals(Rewritten, RemovedPath))
                DropPathAndDescendants(Rewritten);

            if (RemovedPath.StartsWith("\\Wow6432Node\\", StringComparison.OrdinalIgnoreCase))
            {
                string Stripped = "\\" + RemovedPath.Substring("\\Wow6432Node\\".Length);
                DropPathAndDescendants(Stripped);

                string StrippedRewritten = RewriteControlSet(Stripped);
                if (!ReferenceEquals(StrippedRewritten, Stripped))
                    DropPathAndDescendants(StrippedRewritten);
            }
        }

        private void DropPathAndDescendants(string Path)
        {
            PathCache.Remove(Path);

            string Prefix = Path + "\\";
            List<string> Stale = null;

            foreach (string Cached in PathCache.Keys)
            {
                if (!Cached.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                Stale ??= new List<string>();
                Stale.Add(Cached);
            }

            if (Stale == null)
                return;

            for (int i = 0; i < Stale.Count; i++)
                PathCache.Remove(Stale[i]);
        }

        internal static string RewriteControlSet(string Path)
        {
            if (Path.IndexOf("\\CurrentControlSet\\", StringComparison.OrdinalIgnoreCase) == -1)
                return Path;

            return Path.Replace("\\CurrentControlSet\\", "\\ControlSet001\\", StringComparison.OrdinalIgnoreCase);
        }

        internal int RootCellOffset
        {
            get
            {
                int FromHeader = ReadI32(0x24);
                return FromHeader > 0 ? FromHeader : 0x20;
            }
        }

        internal bool TryReadSequence(out uint First, out uint Second)
        {
            First = 0;
            Second = 0;

            if (Length < 0x0C)
                return false;

            First = (uint)ReadI32(0x04);
            Second = (uint)ReadI32(0x08);
            return true;
        }

        internal void UseMap(RegistryHiveMap Mapping)
        {
            Map = Mapping;
        }

        private int ReadRaw(Span<byte> Buffer, long Offset)
        {
            if (Map != null && Map.Covers(Offset, Buffer.Length))
            {
                Map.Read(Offset, Buffer.Length).CopyTo(Buffer);
                return Buffer.Length;
            }

            return RandomAccess.Read(Handle, Buffer, Offset);
        }

        public HiveKey GetRootKey()
        {
            return CachedRootKey ??= ReadKeyAtAbsolute(MainRootOffset + RootCellOffset);
        }

        private void StorePathResult(string Path, HiveKey Key)
        {
            if (PathCache.Count >= Settings.MemoryBudget.RegistryPathCacheEntries)
                PathCache.Clear();

            PathCache[Path] = new PathEntry { Key = Key, Generation = Generation };
        }

        public bool TryOpenPath(string RelativePath, out HiveKey Key)
        {
            Key = default;

            if (string.IsNullOrEmpty(RelativePath))
                return false;

            RelativePath = NormalizeRelativePath(RelativePath);

            if (RelativePath == "\\")
            {
                Key = GetRootKey();
                return true;
            }

            if (PathCache.TryGetValue(RelativePath, out PathEntry Cached) && (Cached.Key != null || Cached.Generation == Generation))
            {
                Key = Cached.Key;
                return Cached.Key != null;
            }

            bool Resolved = TryOpenPathUncached(RelativePath, out HiveKey Opened);
            StorePathResult(RelativePath, Resolved ? Opened : null);
            Key = Resolved ? Opened : default;
            return Resolved;
        }

        private bool TryOpenPathUncached(string RelativePath, out HiveKey Key)
        {
            Key = default;

            static bool TryTraverse(RegistryHiveReader Self, string Path, out HiveKey OutKey)
            {
                OutKey = default;

                HiveKey Current = Self.GetRootKey();

                Path = RewriteControlSet(Path);

                string[] Parts = Path.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
                string Prefix = string.Empty;
                for (int i = 0; i < Parts.Length; i++)
                {
                    Prefix = string.Concat(Prefix, "\\", Parts[i]);

                    if (Self.PathCache.TryGetValue(Prefix, out PathEntry CachedNode)
                        && (CachedNode.Key != null || CachedNode.Generation == Self.Generation))
                    {
                        if (CachedNode.Key == null)
                            return false;

                        Current = CachedNode.Key;
                        continue;
                    }

                    if (!Self.TryGetSubKey(Current, Parts[i], out HiveKey Next))
                    {
                        Self.StorePathResult(Prefix, null);
                        return false;
                    }

                    Self.StorePathResult(Prefix, Next);
                    Current = Next;
                }

                OutKey = Current;
                return true;
            }

            if (TryTraverse(this, RelativePath, out HiveKey Found))
            {
                Key = Found;
                return true;
            }

            if (RelativePath.StartsWith("\\Wow6432Node\\", StringComparison.OrdinalIgnoreCase))
            {
                string Alt = "\\" + RelativePath.Substring("\\Wow6432Node\\".Length);
                if (TryTraverse(this, Alt, out Found))
                {
                    Key = Found;
                    return true;
                }
            }
            else if (RelativePath.Equals("\\Wow6432Node", StringComparison.OrdinalIgnoreCase))
            {
                if (TryTraverse(this, "\\", out Found))
                {
                    Key = Found;
                    return true;
                }
            }

            return false;
        }

        public bool TryGetValue(HiveKey Key, string Name, out ValueNode Value)
        {
            Value = null;

            if (!Refresh(Key))
                return false;

            if (Name == null)
                Name = string.Empty;

            HiveKey Local = Key;

            EnsureValuesParsed(ref Local);

            if (Local.Values == null)
                return false;

            if (!Local.Values.TryGetValue(Name, out RawHiveValue Raw))
                return false;

            byte[] ValueData = ReadValueData(Raw);

            Value = new ValueNode
            {
                Name = Name,
                Type = Raw.Type,
                Data = ValueData
            };

            return true;
        }

        public bool TryGetSubKey(HiveKey Parent, string Name, out HiveKey SubKey)
        {
            SubKey = default;

            if (!Refresh(Parent))
                return false;

            HiveKey Local = Parent;

            if (Local.SubKeys == null)
            {
                if (TrySearchSubKey(Local.SubKeyBlockOffset, Name, 0, out int Found, out bool Searched))
                {
                    SubKey = ReadKeyAtAbsolute(MainRootOffset + Found);
                    return true;
                }

                if (Searched)
                    return false;
            }

            EnsureSubKeysParsed(ref Local);

            if (Local.SubKeys == null)
                return false;

            if (!Local.SubKeys.TryGetValue(Name, out int SubKeyRelOffset))
                return false;

            int Abs = MainRootOffset + SubKeyRelOffset;
            SubKey = ReadKeyAtAbsolute(Abs);
            return true;
        }

        // "lf" and "lh" lists are name ordered, so a name is found without reading the rest. A name outside
        // plain ASCII may order differently here than in the kernel, so Searched reports whether the whole
        // list was covered.
        private bool TrySearchSubKey(int BlockOffset, string Name, int Depth, out int Offset, out bool Searched)
        {
            Offset = 0;
            Searched = false;

            if (BlockOffset <= 0)
            {
                Searched = true;
                return false;
            }

            if (Depth > 4)
                return false;

            int ItemAbs = MainRootOffset + BlockOffset;
            EnsureInBounds(ItemAbs, 0x08);

            ushort BlockType = ReadKind(ItemAbs + 4);
            bool Hashed = BlockType == ListFast || BlockType == ListHashed;

            int Count = (ushort)ReadI16(ItemAbs + 0x06);
            int EntriesAbs = ItemAbs + 0x08;

            if (BlockType == ListIndex)
            {
                EnsureInBounds(EntriesAbs, Count * 4);

                bool AllSearched = true;

                for (int i = 0; i < Count; i++)
                {
                    if (TrySearchSubKey(ReadI32(EntriesAbs + (i * 4)), Name, Depth + 1, out Offset, out bool ChildSearched))
                    {
                        Searched = true;
                        return true;
                    }

                    AllSearched &= ChildSearched;
                }

                Searched = AllSearched;
                return false;
            }

            if (!Hashed || !IsPlainName(Name))
                return false;

            Searched = true;
            EnsureInBounds(EntriesAbs, Count * 8);

            int Low = 0;
            int High = Count - 1;

            while (Low <= High)
            {
                int Middle = (Low + High) / 2;
                int Candidate = ReadI32(EntriesAbs + (Middle * 8));
                string CandidateName = ReadKeyName(MainRootOffset + Candidate);
                int Order = string.Compare(CandidateName, Name, StringComparison.OrdinalIgnoreCase);

                if (Order == 0)
                {
                    Offset = Candidate;
                    return true;
                }

                if (!IsPlainName(CandidateName))
                    Searched = false;

                if (Order < 0)
                    Low = Middle + 1;
                else
                    High = Middle - 1;
            }

            return false;
        }

        private static bool IsPlainName(string Name)
        {
            for (int i = 0; i < Name.Length; i++)
            {
                if (Name[i] > 0x7F)
                    return false;
            }

            return true;
        }

        public bool TryEnumerateSubKey(HiveKey Key, int Index, out string Name)
        {
            Name = null;

            if (Index < 0 || !Refresh(Key))
                return false;

            if (Key.SubKeyBlockOffset <= 0)
                return false;

            if (!TryFindSubKeyOffset(Key.SubKeyBlockOffset, ref Index, 0, out int Offset))
                return false;

            int SubKeyAbs = MainRootOffset + Offset;

            EnsureInBounds(SubKeyAbs, 0x60);

            if (!IsSignature(SubKeyAbs + 4, (byte)'n', (byte)'k'))
                return false;

            Name = ReadKeyName(SubKeyAbs);
            return true;
        }

        /// <summary>
        /// Resolves the Index'th "nk" offset in a subkey list, descending through "ri" index roots and
        /// decrementing Index by the size of each sublist it skips.
        /// </summary>
        private bool TryFindSubKeyOffset(int BlockOffset, ref int Index, int Depth, out int Offset)
        {
            const int MaxIndexDepth = 4;

            Offset = 0;

            if (BlockOffset <= 0 || Depth > MaxIndexDepth)
                return false;

            int ItemAbs = MainRootOffset + BlockOffset;
            EnsureInBounds(ItemAbs, 0x0C);

            ushort BlockType = ReadKind(ItemAbs + 4);
            bool Hashed = BlockType == ListFast || BlockType == ListHashed;
            bool IndexRoot = BlockType == ListIndex;

            if (!Hashed && !IndexRoot && BlockType != ListPlain)
                return false;

            int EntrySize = Hashed ? 8 : 4;
            int Count = (ushort)ReadI16(ItemAbs + 0x06);
            int EntriesAbs = ItemAbs + 0x08;

            EnsureInBounds(EntriesAbs, Count * EntrySize);

            if (!IndexRoot)
            {
                if (Index >= Count)
                {
                    Index -= Count;
                    return false;
                }

                Offset = ReadI32(EntriesAbs + (Index * EntrySize));
                return true;
            }

            for (int i = 0; i < Count; i++)
            {
                if (TryFindSubKeyOffset(ReadI32(EntriesAbs + (i * EntrySize)), ref Index, Depth + 1, out Offset))
                    return true;
            }

            return false;
        }

        public bool TryGetSubKeyNames(ref HiveKey Key, out Dictionary<string, int> Names)
        {
            Names = null;

            if (!Refresh(Key))
                return false;

            EnsureSubKeysParsed(ref Key);

            Names = Key.SubKeys;
            return Names != null;
        }

        public bool TryQueryKeyHeader(HiveKey Key, out int SubKeyCount, out int ValueCount, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            Name = null;

            if (!Refresh(Key))
                return false;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            if (!IsSignature(Abs + 4, (byte)'n', (byte)'k'))
                return false;

            SubKeyCount = ReadI32(Abs + 0x18);
            ValueCount = ReadI32(Abs + 0x28);

            Name = ReadKeyName(Abs);
            return true;
        }

        public bool TryEnumerateValueBasic(HiveKey Key, int Index, out string Name, out int Type, out int DataLength)
        {
            Name = null;
            Type = 0;
            DataLength = 0;

            if (Index < 0 || !Refresh(Key))
                return false;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            if (!IsSignature(Abs + 4, (byte)'n', (byte)'k'))
                return false;

            int ValueCount = ReadI32(Abs + 0x28);
            int ValueOffsets = ReadI32(Abs + 0x2C);

            if (ValueCount <= 0)
                return false;

            if (Index >= ValueCount)
                return false;

            int ListAbs = MainRootOffset + ValueOffsets + 4;
            EnsureInBounds(ListAbs, ValueCount * 4);

            int RelOffset = ReadI32(ListAbs + (Index * 4));
            int VkAbs = MainRootOffset + RelOffset;

            EnsureInBounds(VkAbs, 0x20);

            if (!IsSignature(VkAbs + 4, (byte)'v', (byte)'k'))
                return false;

            int Size = ReadI32(VkAbs + 0x08);
            int ValueType = ReadI32(VkAbs + 0x10);

            Name = ReadValueName(VkAbs);

            Type = ValueType;
            DataLength = Size & 0x7FFFFFFF;

            return true;
        }

        public bool TryEnumerateValueFull(HiveKey Key, int Index, out string Name, out int Type, out byte[] Data)
        {
            Name = null;
            Type = 0;
            Data = null;

            if (Index < 0 || !Refresh(Key))
                return false;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            if (!IsSignature(Abs + 4, (byte)'n', (byte)'k'))
                return false;

            int ValueCount = ReadI32(Abs + 0x28);
            int ValueOffsets = ReadI32(Abs + 0x2C);

            if (ValueCount <= 0)
                return false;

            if (Index >= ValueCount)
                return false;

            int ListAbs = MainRootOffset + ValueOffsets + 4;
            EnsureInBounds(ListAbs, ValueCount * 4);

            int RelOffset = ReadI32(ListAbs + (Index * 4));
            int VkAbs = MainRootOffset + RelOffset;

            EnsureInBounds(VkAbs, 0x20);

            if (!IsSignature(VkAbs + 4, (byte)'v', (byte)'k'))
                return false;

            int Size = ReadI32(VkAbs + 0x08);
            int Offset = ReadI32(VkAbs + 0x0C);
            int ValueType = ReadI32(VkAbs + 0x10);

            Name = ReadValueName(VkAbs);

            RawHiveValue Raw = new RawHiveValue
            {
                Type = ValueType,
                Name = Name,
                DataLength = Size & 0x7FFFFFFF,
                DataOffset = Offset + 4,
                Inline = (Size & unchecked((int)0x80000000)) != 0
            };

            if (Raw.Inline)
                Raw.DataOffset = RelOffset + 0x0C;

            Type = ValueType;
            Data = ReadValueData(Raw);

            return true;
        }

        public bool TryReadValueData(HiveKey Key, string Name, out byte[] Data)
        {
            Data = null;

            if (!Refresh(Key))
                return false;

            if (Name == null)
                Name = string.Empty;

            HiveKey Local = Key;

            EnsureValuesParsed(ref Local);

            if (Local.Values == null)
                return false;

            if (!Local.Values.TryGetValue(Name, out RawHiveValue Raw))
                return false;

            Data = ReadValueData(Raw);
            return true;
        }

        private void ValidateRegf()
        {
            if (Length < 4)
                throw new InvalidDataException("Hive too small");

            if (ReadAscii(0, 4) != "regf")
                throw new InvalidDataException("Invalid regf signature");
        }

        private bool Refresh(HiveKey Key)
        {
            if (Key == null)
                return false;

            if (Key.Generation == Generation)
                return !Key.Invalid;

            Key.Generation = Generation;
            Key.ValuesParsed = false;
            Key.SubKeysParsed = false;
            Key.Values = null;
            Key.SubKeys = null;

            if (Key.KeyBlockAbs <= 0 || (long)Key.KeyBlockAbs + 0x60 > Length || !IsSignature(Key.KeyBlockAbs + 4, (byte)'n', (byte)'k'))
            {
                Key.Invalid = true;
                return false;
            }

            Key.Invalid = false;
            Key.SubKeyCount = ReadI32(Key.KeyBlockAbs + 0x18);
            Key.SubKeyBlockOffset = ReadI32(Key.KeyBlockAbs + 0x20);
            Key.ValueCount = ReadI32(Key.KeyBlockAbs + 0x28);
            Key.ValueOffsets = ReadI32(Key.KeyBlockAbs + 0x2C);
            return true;
        }

        private HiveKey ReadKeyAtAbsolute(int Abs)
        {
            EnsureInBounds(Abs, 0x60);

            if (!IsSignature(Abs + 4, (byte)'n', (byte)'k'))
                throw new InvalidDataException($"Expected nk at {Abs:X}");

            int SubKeyCount = ReadI32(Abs + 0x18);
            int SubKeys = ReadI32(Abs + 0x20);
            int ValueCount = ReadI32(Abs + 0x28);
            int Offsets = ReadI32(Abs + 0x2C);

            return new HiveKey
            {
                KeyBlockAbs = Abs,
                SubKeyBlockOffset = SubKeys,
                SubKeyCount = SubKeyCount,
                ValueCount = ValueCount,
                ValueOffsets = Offsets,
                Generation = Generation,
                ValuesParsed = false,
                SubKeysParsed = false,
                Values = null,
                SubKeys = null
            };
        }

        private string ReadKeyName(int Abs)
        {
            int Flags = (ushort)ReadI16(Abs + 0x06);
            short NameLen = ReadI16(Abs + 0x4C);
            return ReadRecordName(Abs + 0x50, NameLen, (Flags & NameCompressedFlag) != 0);
        }

        private void EnsureValuesParsed(ref HiveKey Key)
        {
            if (Key.ValuesParsed)
                return;

            Key.ValuesParsed = true;

            Dictionary<string, RawHiveValue> Values = new(Key.ValueCount > 0 ? Key.ValueCount : 0, StringComparer.OrdinalIgnoreCase);

            if (Key.ValueCount <= 0)
            {
                Key.Values = Values;
                return;
            }

            int ListAbs = MainRootOffset + Key.ValueOffsets + 4;
            EnsureInBounds(ListAbs, Key.ValueCount * 4);

            for (int i = 0; i < Key.ValueCount; i++)
            {
                int RelOffset = ReadI32(ListAbs + (i * 4));
                int VkAbs = MainRootOffset + RelOffset;

                EnsureInBounds(VkAbs, 0x20);

                if (!IsSignature(VkAbs + 4, (byte)'v', (byte)'k'))
                    continue;

                int Size = ReadI32(VkAbs + 0x08);
                int Offset = ReadI32(VkAbs + 0x0C);
                int ValueType = ReadI32(VkAbs + 0x10);

                string ValueName = ReadValueName(VkAbs);

                RawHiveValue Raw = new RawHiveValue
                {
                    Type = ValueType,
                    Name = ValueName,
                    DataLength = Size & 0x7FFFFFFF,
                    DataOffset = Offset + 4,
                    Inline = (Size & unchecked((int)0x80000000)) != 0
                };

                if (Raw.Inline)
                {
                    Raw.DataOffset = RelOffset + 0x0C;
                }

                if (!Values.ContainsKey(ValueName))
                    Values.Add(ValueName, Raw);
            }

            Key.Values = Values;
        }

        private void EnsureSubKeysParsed(ref HiveKey Key)
        {
            if (Key.SubKeysParsed)
                return;

            Key.SubKeysParsed = true;

            Dictionary<string, int> SubKeys = new(Key.SubKeyCount > 0 ? Key.SubKeyCount : 0, StringComparer.OrdinalIgnoreCase);

            CollectSubKeys(Key.SubKeyBlockOffset, SubKeys, 0);

            Key.SubKeys = SubKeys;
        }

        private void CollectSubKeys(int BlockOffset, Dictionary<string, int> SubKeys, int Depth)
        {
            const int MaxIndexDepth = 4;

            if (BlockOffset <= 0 || Depth > MaxIndexDepth)
                return;

            int ItemAbs = MainRootOffset + BlockOffset;
            EnsureInBounds(ItemAbs, 0x0C);

            ushort BlockType = ReadKind(ItemAbs + 4);
            bool Hashed = BlockType == ListFast || BlockType == ListHashed;
            bool IndexRoot = BlockType == ListIndex;

            if (!Hashed && !IndexRoot && BlockType != ListPlain)
                return;

            int EntrySize = Hashed ? 8 : 4;
            int Count = (ushort)ReadI16(ItemAbs + 0x06);
            int EntriesAbs = ItemAbs + 0x08;

            EnsureInBounds(EntriesAbs, Count * EntrySize);

            for (int i = 0; i < Count; i++)
            {
                int Offset = ReadI32(EntriesAbs + (i * EntrySize));

                if (IndexRoot)
                {
                    CollectSubKeys(Offset, SubKeys, Depth + 1);
                    continue;
                }

                int SubKeyAbs = MainRootOffset + Offset;

                EnsureInBounds(SubKeyAbs, 0x60);

                if (!IsSignature(SubKeyAbs + 4, (byte)'n', (byte)'k'))
                    continue;

                string SubKeyName = ReadKeyName(SubKeyAbs);

                if (!SubKeys.ContainsKey(SubKeyName))
                    SubKeys.Add(SubKeyName, Offset);
            }
        }

        private byte[] ReadValueData(RawHiveValue Raw)
        {
            if (Raw.DataLength <= 0)
                return Array.Empty<byte>();

            if (Raw.Inline)
            {
                int AbsInline = MainRootOffset + Raw.DataOffset;
                int InlineSize = Math.Min(Raw.DataLength, 4);

                EnsureInBounds(AbsInline, InlineSize);

                byte[] Tmp = new byte[InlineSize];
                ReadBytes(AbsInline, Tmp, 0, Tmp.Length);
                return Tmp;
            }

            int Abs = MainRootOffset + Raw.DataOffset;

            if (Raw.DataLength > MaxDataSegment && IsSignature(Abs, (byte)'d', (byte)'b'))
                return ReadBigData(Abs, Raw.DataLength);

            EnsureInBounds(Abs, Raw.DataLength);

            byte[] Result = new byte[Raw.DataLength];
            ReadBytes(Abs, Result, 0, Result.Length);
            return Result;
        }

        // Past 16344 bytes a value points at a "db" record that chains fixed size segments.
        private byte[] ReadBigData(int Abs, int TotalLength)
        {
            EnsureInBounds(Abs, 8);

            int SegmentCount = (ushort)ReadI16(Abs + 2);
            int ListRel = ReadI32(Abs + 4);
            if (SegmentCount <= 0 || ListRel <= 0)
                return Array.Empty<byte>();

            int ListAbs = MainRootOffset + ListRel + 4;
            EnsureInBounds(ListAbs, SegmentCount * 4);

            // The size field is whatever the record says, so cap it at what the segments can hold.
            long Capacity = Math.Min((long)SegmentCount * MaxDataSegment, Length);
            if (TotalLength > Capacity)
                TotalLength = (int)Capacity;

            byte[] Result = new byte[TotalLength];
            int Written = 0;

            for (int i = 0; i < SegmentCount && Written < TotalLength; i++)
            {
                int SegmentRel = ReadI32(ListAbs + (i * 4));
                if (SegmentRel <= 0)
                    break;

                int SegmentAbs = MainRootOffset + SegmentRel;
                EnsureInBounds(SegmentAbs, 4);

                int CellSize = -ReadI32(SegmentAbs);
                int Usable = Math.Min(Math.Min(CellSize - 4, MaxDataSegment), TotalLength - Written);
                if (Usable <= 0)
                    break;

                ReadBytes(SegmentAbs + 4, Result, Written, Usable);
                Written += Usable;
            }

            return Result;
        }

        private static string NormalizeRelativePath(string Path)
        {
            Path = Path.TrimEnd('\0');

            if (!Path.StartsWith("\\", StringComparison.Ordinal))
                Path = "\\" + Path;

            while (Path.Contains("\\\\", StringComparison.Ordinal))
                Path = Path.Replace("\\\\", "\\", StringComparison.Ordinal);

            if (Path.Length > 1 && Path.EndsWith("\\", StringComparison.Ordinal))
                Path = Path.TrimEnd('\\');

            Path = Path.Trim().TrimEnd('\0');
            return Path;
        }

        private string ReadValueName(int VkAbs)
        {
            int Flags = (ushort)ReadI16(VkAbs + 0x14);
            short NameLen = ReadI16(VkAbs + 0x06);
            return ReadRecordName(VkAbs + 0x18, NameLen, (Flags & ValueNameCompressedFlag) != 0);
        }

        private string ReadRecordName(int Offset, int Length, bool Compressed)
        {
            if (Length <= 0)
                return string.Empty;

            EnsureInBounds(Offset, Length);

            const int StackLimit = 256;

            if (Length <= StackLimit)
            {
                Span<byte> Buf = stackalloc byte[Length];
                ReadBytes(Offset, Buf);
                return DecodeRecordName(Buf, Compressed);
            }

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Length);
            try
            {
                Span<byte> Buf = Rented.AsSpan(0, Length);
                ReadBytes(Offset, Buf);
                return DecodeRecordName(Buf, Compressed);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        private static string DecodeRecordName(Span<byte> Buffer, bool Compressed)
        {
            if (Compressed)
            {
                int Actual = Buffer.Length;
                while (Actual > 0 && Buffer[Actual - 1] == 0)
                    Actual--;

                return Actual == 0 ? string.Empty : Encoding.Latin1.GetString(Buffer.Slice(0, Actual));
            }

            int Bytes = Buffer.Length & ~1;
            if (Bytes == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(Buffer.Slice(0, Bytes)).TrimEnd('\0');
        }

        private string ReadAscii(int Offset, int Length)
        {
            EnsureInBounds(Offset, Length);

            const int StackLimit = 256;

            if (Length <= StackLimit)
            {
                Span<byte> Buf = stackalloc byte[Length];
                ReadBytes(Offset, Buf);
                return Encoding.ASCII.GetString(Buf);
            }

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Length);
            try
            {
                Span<byte> Buf = Rented.AsSpan(0, Length);
                ReadBytes(Offset, Buf);
                return Encoding.ASCII.GetString(Buf);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        private void EnsureInBounds(int Offset, int Size)
        {
            if (Offset < 0 || Size < 0)
                throw new InvalidDataException("Hive read out of bounds");

            long End = (long)Offset + (long)Size;
            if (End > Length)
                throw new InvalidDataException("Hive read out of bounds");
        }

        private int ReadI32(int Offset)
        {
            if (Map != null && Map.Covers(Offset, 4))
                return Map.ReadInt32(Offset);

            Span<byte> Buf = stackalloc byte[4];
            ReadSpan(Offset, Buf);
            return MemoryMarshal.Read<int>(Buf);
        }

        private short ReadI16(int Offset)
        {
            if (Map != null && Map.Covers(Offset, 2))
                return Map.ReadInt16(Offset);

            Span<byte> Buf = stackalloc byte[2];
            ReadSpan(Offset, Buf);
            return MemoryMarshal.Read<short>(Buf);
        }

        private ushort ReadKind(int Abs)
        {
            return (ushort)ReadI16(Abs);
        }

        private bool IsSignature(int Abs, byte First, byte Second)
        {
            if (Map != null && Map.Covers(Abs, 2))
                return Map.Matches(Abs, First, Second);

            Span<byte> Buf = stackalloc byte[2];
            ReadSpan(Abs, Buf);
            return Buf[0] == First && Buf[1] == Second;
        }

        private void ReadSpan(int Offset, Span<byte> Buffer)
        {
            EnsureInBounds(Offset, Buffer.Length);

            int Total = 0;

            while (Total < Buffer.Length)
            {
                int Read = ReadRaw(Buffer.Slice(Total), Offset + Total);
                if (Read <= 0)
                    throw new InvalidDataException("Failed to read hive data");

                Total += Read;
            }
        }

        private void ReadBytes(int Offset, byte[] Buffer, int BufferOffset, int Count)
        {
            EnsureInBounds(Offset, Count);

            int Total = 0;

            while (Total < Count)
            {
                int Read = ReadRaw(Buffer.AsSpan(BufferOffset + Total, Count - Total), Offset + Total);
                if (Read <= 0)
                    throw new InvalidDataException("Failed to read hive data");

                Total += Read;
            }
        }

        private void ReadBytes(int Offset, Span<byte> Buffer)
        {
            EnsureInBounds(Offset, Buffer.Length);

            int Total = 0;

            while (Total < Buffer.Length)
            {
                int Read = ReadRaw(Buffer.Slice(Total), Offset + Total);
                if (Read <= 0)
                    throw new InvalidDataException("Failed to read hive data");

                Total += Read;
            }
        }

        public class HiveKey
        {
            internal int KeyBlockAbs;
            public int SubKeyBlockOffset;
            public int SubKeyCount;
            public int ValueCount;
            public int ValueOffsets;

            internal uint Generation;
            internal bool Invalid;

            internal bool ValuesParsed;
            internal bool SubKeysParsed;

            internal Dictionary<string, RawHiveValue> Values;
            internal Dictionary<string, int> SubKeys;
        }

        public struct RawHiveValue
        {
            public int Type;
            public string Name;
            public int DataLength;
            public int DataOffset;
            public bool Inline;
        }
    }

    // Free cells come from this session and from appended bins, so a write never walks a large hive's free space.
    public sealed class RegistryHiveWriter
    {
        private const int RootOffset = RegistryHiveReader.MainRootOffset;
        private const int MaxSegment = RegistryHiveReader.MaxDataSegment;

        private const int HbinHeaderSize = 0x20;
        private const int HbinAlignment = 0x1000;
        private const int HbinGrowth = 0x10000;

        private const int KeyHeaderSize = 0x4C;
        private const int ValueHeaderSize = 0x14;
        private const int MaxInlineRecord = 640;

        private const int KeyNameCompressed = 0x0020;
        private const int ValueNameCompressed = 0x0001;

        private readonly SafeFileHandle Handle;
        private readonly List<FreeCell> FreeCells = new List<FreeCell>();
        private RegistryHiveMap Map;

        private long Length;
        private int BinsSize;
        private uint Sequence;
        private bool Dirty;

        private struct FreeCell
        {
            public int Offset;
            public int Size;
        }

        public RegistryHiveWriter(SafeFileHandle Handle)
        {
            this.Handle = Handle ?? throw new ArgumentNullException(nameof(Handle));
            ReloadHeader();
        }

        internal void UseMap(RegistryHiveMap Mapping)
        {
            Map = Mapping;
        }

        internal long FileLength => Length;

        internal uint CurrentSequence => Sequence;

        internal uint ReadSequence()
        {
            return (uint)ReadI32(0x04);
        }

        internal void ReloadHeader()
        {
            BinsSize = ReadI32(0x28);
            Length = RootOffset + (long)BinsSize;
            Sequence = ReadSequence();
            FreeCells.Clear();
        }

        internal void CommitHeader()
        {
            if (!Dirty)
                return;

            Sequence++;
            WriteI32(0x04, (int)Sequence);
            WriteI32(0x08, (int)Sequence);
            WriteI64(0x0C, DateTime.UtcNow.ToFileTimeUtc());
            WriteI32(0x28, BinsSize);

            Span<byte> Head = stackalloc byte[0x1FC];
            ReadInto(0, Head);

            uint Checksum = 0;
            for (int i = 0; i < Head.Length; i += 4)
                Checksum ^= BinaryPrimitives.ReadUInt32LittleEndian(Head.Slice(i, 4));

            if (Checksum == 0)
                Checksum = 1;
            else if (Checksum == uint.MaxValue)
                Checksum = uint.MaxValue - 1;

            WriteI32(0x1FC, (int)Checksum);
            Dirty = false;
        }

        public bool TryCreateKey(string RelativePath, out bool CreatedNew)
        {
            CreatedNew = false;

            int Current = RootCell();
            string[] Parts = SplitWithWow64Fallback(Current, RelativePath);

            for (int i = 0; i < Parts.Length; i++)
            {
                if (TryFindSubKey(Current, Parts[i], out int Child))
                {
                    Current = Child;
                    continue;
                }

                if (!TryAddSubKey(Current, Parts[i], out Child))
                    return false;

                Current = Child;
                CreatedNew = true;
            }

            return true;
        }

        // NT refuses to delete a key that still has subkeys.
        public bool TryDeleteKey(string RelativePath)
        {
            int Parent = RootCell();
            string[] Parts = SplitWithWow64Fallback(Parent, RelativePath);
            if (Parts.Length == 0)
                return false;

            for (int i = 0; i < Parts.Length - 1; i++)
            {
                if (!TryFindSubKey(Parent, Parts[i], out Parent))
                    return false;
            }

            string Leaf = Parts[Parts.Length - 1];
            if (!TryFindSubKey(Parent, Leaf, out int Target))
                return false;

            if (ReadI32(RootOffset + Target + 0x18) > 0)
                return false;

            if (!TryRemoveSubKey(Parent, Leaf))
                return false;

            ReleaseKeyContents(Target);
            ReleaseSecurity(ReadI32(RootOffset + Target + 0x30));
            ReleaseCell(Target);

            WriteI32(RootOffset + Parent + 0x18, Math.Max(0, ReadI32(RootOffset + Parent + 0x18) - 1));
            WriteI64(RootOffset + Parent + 0x08, DateTime.UtcNow.ToFileTimeUtc());
            Dirty = true;
            return true;
        }

        public bool TrySetValue(string RelativePath, string Name, int Type, byte[] Data)
        {
            if (!TryFindKey(RelativePath, out int KeyRel))
                return false;

            Name ??= string.Empty;
            Data ??= Array.Empty<byte>();

            if (TryFindValue(KeyRel, Name, out _, out int ValueRel))
            {
                ReleaseValueData(ValueRel);
                WriteValueData(Data, out int SizeField, out int OffsetField, out byte[] Inline);
                StoreValueFields(ValueRel, SizeField, OffsetField, Inline, Type);
            }
            else
            {
                WriteValueData(Data, out int SizeField, out int OffsetField, out byte[] Inline);
                int NewValue = CreateValueCell(Name, Type, SizeField, OffsetField, Inline);
                if (!TryAppendValue(KeyRel, NewValue))
                {
                    ReleaseCell(NewValue);
                    return false;
                }
            }

            long KeyAbs = RootOffset + KeyRel;
            int NameBytes = Encoding.Unicode.GetByteCount(Name);
            if (NameBytes > ReadI32(KeyAbs + 0x40))
                WriteI32(KeyAbs + 0x40, NameBytes);
            if (Data.Length > ReadI32(KeyAbs + 0x44))
                WriteI32(KeyAbs + 0x44, Data.Length);

            WriteI64(KeyAbs + 0x08, DateTime.UtcNow.ToFileTimeUtc());
            Dirty = true;
            return true;
        }

        public bool TryDeleteValue(string RelativePath, string Name)
        {
            if (!TryFindKey(RelativePath, out int KeyRel))
                return false;

            Name ??= string.Empty;

            if (!TryFindValue(KeyRel, Name, out int Index, out int ValueRel))
                return false;

            long KeyAbs = RootOffset + KeyRel;
            int Count = ReadI32(KeyAbs + 0x28);
            int ListRel = ReadI32(KeyAbs + 0x2C);
            long EntriesAbs = RootOffset + ListRel + 4;

            CopyEntries(EntriesAbs + ((Index + 1) * 4), EntriesAbs + (Index * 4), (Count - 1 - Index) * 4);
            WriteI32(KeyAbs + 0x28, Count - 1);

            if (Count - 1 == 0)
            {
                WriteI32(KeyAbs + 0x2C, -1);
                ReleaseCell(ListRel);
            }

            ReleaseValueData(ValueRel);
            ReleaseCell(ValueRel);

            WriteI64(KeyAbs + 0x08, DateTime.UtcNow.ToFileTimeUtc());
            Dirty = true;
            return true;
        }

        private int RootCell()
        {
            int FromHeader = ReadI32(0x24);
            return FromHeader > 0 ? FromHeader : 0x20;
        }

        private static string[] SplitPath(string RelativePath)
        {
            if (string.IsNullOrEmpty(RelativePath))
                return Array.Empty<string>();

            RelativePath = RegistryHiveReader.RewriteControlSet(RelativePath);

            return RelativePath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        }

        private bool TryFindKey(string RelativePath, out int KeyRel)
        {
            KeyRel = RootCell();

            string[] Parts = SplitWithWow64Fallback(KeyRel, RelativePath);
            for (int i = 0; i < Parts.Length; i++)
            {
                if (!TryFindSubKey(KeyRel, Parts[i], out KeyRel))
                    return false;
            }

            return true;
        }

        // A hive with no Wow6432Node answers the 32-bit view from its root.
        private string[] SplitWithWow64Fallback(int RootRel, string RelativePath)
        {
            string[] Parts = SplitPath(RelativePath);

            if (Parts.Length != 0
                && Parts[0].Equals("Wow6432Node", StringComparison.OrdinalIgnoreCase)
                && !TryFindSubKey(RootRel, Parts[0], out _))
                return Parts[1..];

            return Parts;
        }

        private bool TryFindSubKey(int ParentRel, string Name, out int ChildRel)
        {
            return TryFindInList(ReadI32(RootOffset + ParentRel + 0x20), Name, 0, out ChildRel);
        }

        private bool TryFindInList(int ListRel, string Name, int Depth, out int ChildRel)
        {
            ChildRel = 0;

            if (ListRel <= 0 || Depth > 4)
                return false;

            long ListAbs = RootOffset + ListRel;
            if (!TryReadListHeader(ListAbs, out ushort Kind, out int Count, out int EntrySize))
                return false;

            long EntriesAbs = ListAbs + 8;

            if (Kind == RegistryHiveReader.ListIndex)
            {
                for (int i = 0; i < Count; i++)
                {
                    if (TryFindInList(ReadI32(EntriesAbs + (i * EntrySize)), Name, Depth + 1, out ChildRel))
                        return true;
                }

                return false;
            }

            if (EntrySize == 8 && IsSearchable(Name))
            {
                int Low = 0;
                int High = Count - 1;

                while (Low <= High)
                {
                    int Middle = (Low + High) / 2;
                    int Candidate = ReadI32(EntriesAbs + (Middle * 8));
                    int Order = string.Compare(ReadKeyName(Candidate), Name, StringComparison.OrdinalIgnoreCase);

                    if (Order == 0)
                    {
                        ChildRel = Candidate;
                        return true;
                    }

                    if (Order < 0)
                        Low = Middle + 1;
                    else
                        High = Middle - 1;
                }

                return false;
            }

            for (int i = 0; i < Count; i++)
            {
                int Offset = ReadI32(EntriesAbs + (i * EntrySize));

                if (string.Equals(ReadKeyName(Offset), Name, StringComparison.OrdinalIgnoreCase))
                {
                    ChildRel = Offset;
                    return true;
                }
            }

            return false;
        }

        private static bool IsSearchable(string Name)
        {
            for (int i = 0; i < Name.Length; i++)
            {
                if (Name[i] > 0x7F)
                    return false;
            }

            return true;
        }

        private bool TryReadListHeader(long ListAbs, out ushort Kind, out int Count, out int EntrySize)
        {
            Kind = 0;
            Count = 0;
            EntrySize = 0;

            if (ListAbs + 8 > Length)
                return false;

            Kind = (ushort)ReadI16(ListAbs + 4);

            bool Hashed = Kind == RegistryHiveReader.ListFast || Kind == RegistryHiveReader.ListHashed;
            if (!Hashed && Kind != RegistryHiveReader.ListPlain && Kind != RegistryHiveReader.ListIndex)
                return false;

            Count = (ushort)ReadI16(ListAbs + 6);
            EntrySize = Hashed ? 8 : 4;
            return true;
        }

        private bool TryAddSubKey(int ParentRel, string Name, out int ChildRel)
        {
            long ParentAbs = RootOffset + ParentRel;
            int Security = ReadI32(ParentAbs + 0x30);

            ChildRel = CreateKeyCell(Name, ParentRel, Security);

            if (!TryInsertSubKey(ParentRel, Name, ChildRel))
            {
                ReleaseCell(ChildRel);
                ChildRel = 0;
                return false;
            }

            AddSecurityReference(Security);

            WriteI32(ParentAbs + 0x18, ReadI32(ParentAbs + 0x18) + 1);

            int NameBytes = Encoding.Unicode.GetByteCount(Name);
            if (NameBytes > ReadI32(ParentAbs + 0x38))
                WriteI32(ParentAbs + 0x38, NameBytes);

            WriteI64(ParentAbs + 0x08, DateTime.UtcNow.ToFileTimeUtc());
            Dirty = true;
            return true;
        }

        private bool TryInsertSubKey(int ParentRel, string Name, int ChildRel)
        {
            long ParentAbs = RootOffset + ParentRel;
            int ListRel = ReadI32(ParentAbs + 0x20);

            if (ListRel <= 0)
            {
                WriteI32(ParentAbs + 0x20, CreateLeafList(Name, ChildRel));
                return true;
            }

            if (!TryReadListHeader(RootOffset + ListRel, out ushort Kind, out int Count, out _))
                return false;

            if (Kind != RegistryHiveReader.ListIndex)
            {
                int Updated = InsertIntoLeaf(ListRel, Name, ChildRel);
                if (Updated != ListRel)
                    WriteI32(ParentAbs + 0x20, Updated);

                return true;
            }

            if (Count <= 0)
                return false;

            long EntriesAbs = RootOffset + ListRel + 8;
            int Target = Count - 1;

            for (int i = 0; i < Count; i++)
            {
                int SubList = ReadI32(EntriesAbs + (i * 4));
                if (!TryReadListHeader(RootOffset + SubList, out _, out int SubCount, out int SubEntrySize) || SubCount == 0)
                    continue;

                int Last = ReadI32(RootOffset + SubList + 8 + ((SubCount - 1) * SubEntrySize));
                if (string.Compare(ReadKeyName(Last), Name, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Target = i;
                    break;
                }
            }

            int TargetList = ReadI32(EntriesAbs + (Target * 4));
            int Moved = InsertIntoLeaf(TargetList, Name, ChildRel);
            if (Moved != TargetList)
                WriteI32(EntriesAbs + (Target * 4), Moved);

            return true;
        }

        private int CreateLeafList(string Name, int ChildRel)
        {
            bool Hashed = ReadI32(0x18) >= 5;
            int EntrySize = Hashed ? 8 : 4;
            int ListRel = AllocateCell(4 + EntrySize);

            long Abs = RootOffset + ListRel;
            // "lf" and "lh" carry an 8 byte entry. The 4 byte entry without a hash is "li".
            WriteAscii(Abs + 4, Hashed ? "lh" : "li");
            WriteI16(Abs + 6, 1);
            WriteEntry(Abs + 8, Hashed, Name, ChildRel);
            return ListRel;
        }

        private int InsertIntoLeaf(int ListRel, string Name, int ChildRel)
        {
            long ListAbs = RootOffset + ListRel;
            if (!TryReadListHeader(ListAbs, out ushort Kind, out int Count, out int EntrySize))
                return ListRel;

            bool Hashed = EntrySize == 8;
            int Position = FindInsertPosition(ListAbs, Count, EntrySize, Name);

            int Needed = 4 + ((Count + 1) * EntrySize);
            int CellSize = -ReadI32(ListAbs);

            int TargetRel = ListRel;
            if (CellSize - 4 < Needed)
            {
                TargetRel = AllocateCell(4 + (GrownCapacity(Count + 1) * EntrySize));
                long TargetAbs = RootOffset + TargetRel;
                WriteI16(TargetAbs + 4, (short)Kind);
                CopyEntries(ListAbs + 8, TargetAbs + 8, Position * EntrySize);
                CopyEntries(ListAbs + 8 + (Position * EntrySize), TargetAbs + 8 + ((Position + 1) * EntrySize), (Count - Position) * EntrySize);
                ReleaseCell(ListRel);
            }
            else
            {
                CopyEntries(ListAbs + 8 + (Position * EntrySize), ListAbs + 8 + ((Position + 1) * EntrySize), (Count - Position) * EntrySize);
            }

            long FinalAbs = RootOffset + TargetRel;
            WriteI16(FinalAbs + 6, (short)(Count + 1));
            WriteEntry(FinalAbs + 8 + (Position * EntrySize), Hashed, Name, ChildRel);
            return TargetRel;
        }

        // Slack keeps the cell a list frees large enough for the next insert to take back.
        private static int GrownCapacity(int Entries)
        {
            int Slack = Entries / 2;

            if (Slack < 8)
                Slack = 8;
            else if (Slack > 1024)
                Slack = 1024;

            return Entries + Slack;
        }

        // Bisected only on a list this code can order, the same condition the lookup and the delete apply.
        private int FindInsertPosition(long ListAbs, int Count, int EntrySize, string Name)
        {
            if (EntrySize != 8 || !IsSearchable(Name))
            {
                for (int i = 0; i < Count; i++)
                {
                    int Entry = ReadI32(ListAbs + 8 + (i * EntrySize));

                    if (string.Compare(ReadKeyName(Entry), Name, StringComparison.OrdinalIgnoreCase) >= 0)
                        return i;
                }

                return Count;
            }

            int Low = 0;
            int High = Count;

            while (Low < High)
            {
                int Middle = (Low + High) / 2;
                int Offset = ReadI32(ListAbs + 8 + (Middle * EntrySize));

                if (string.Compare(ReadKeyName(Offset), Name, StringComparison.OrdinalIgnoreCase) < 0)
                    Low = Middle + 1;
                else
                    High = Middle;
            }

            return Low;
        }

        private bool TryRemoveSubKey(int ParentRel, string Name)
        {
            return TryRemoveFromList(ReadI32(RootOffset + ParentRel + 0x20), Name, 0);
        }

        private bool TryRemoveFromList(int ListRel, string Name, int Depth)
        {
            if (ListRel <= 0 || Depth > 4)
                return false;

            long ListAbs = RootOffset + ListRel;
            if (!TryReadListHeader(ListAbs, out ushort Kind, out int Count, out int EntrySize))
                return false;

            if (Kind == RegistryHiveReader.ListIndex)
            {
                for (int i = 0; i < Count; i++)
                {
                    if (TryRemoveFromList(ReadI32(ListAbs + 8 + (i * EntrySize)), Name, Depth + 1))
                        return true;
                }

                return false;
            }

            int Index = FindEntry(ListAbs, Count, EntrySize, Name);
            if (Index < 0)
                return false;

            CopyEntries(ListAbs + 8 + ((Index + 1) * EntrySize), ListAbs + 8 + (Index * EntrySize), (Count - 1 - Index) * EntrySize);
            WriteI16(ListAbs + 6, (short)(Count - 1));
            return true;
        }

        private int FindEntry(long ListAbs, int Count, int EntrySize, string Name)
        {
            if (EntrySize == 8 && IsSearchable(Name))
            {
                int Low = 0;
                int High = Count - 1;

                while (Low <= High)
                {
                    int Middle = (Low + High) / 2;
                    int Order = string.Compare(ReadKeyName(ReadI32(ListAbs + 8 + (Middle * 8))), Name, StringComparison.OrdinalIgnoreCase);

                    if (Order == 0)
                        return Middle;

                    if (Order < 0)
                        Low = Middle + 1;
                    else
                        High = Middle - 1;
                }

                return -1;
            }

            for (int i = 0; i < Count; i++)
            {
                if (string.Equals(ReadKeyName(ReadI32(ListAbs + 8 + (i * EntrySize))), Name, StringComparison.OrdinalIgnoreCase))
                    return i;
            }

            return -1;
        }

        private void WriteEntry(long Abs, bool Hashed, string Name, int ChildRel)
        {
            WriteI32(Abs, ChildRel);

            if (Hashed)
                WriteI32(Abs + 4, (int)NameHash(Name));
        }

        private static uint NameHash(string Name)
        {
            uint Hash = 0;

            for (int i = 0; i < Name.Length; i++)
                Hash = (Hash * 37) + char.ToUpperInvariant(Name[i]);

            return Hash;
        }

        private int CreateKeyCell(string Name, int ParentRel, int SecurityRel)
        {
            bool Compressed = IsCompressible(Name);
            byte[] NameBytes = Compressed ? Encoding.Latin1.GetBytes(Name) : Encoding.Unicode.GetBytes(Name);

            int CellRel = AllocateCell(KeyHeaderSize + NameBytes.Length);

            int RecordSize = KeyHeaderSize + NameBytes.Length;
            Span<byte> Scratch = stackalloc byte[MaxInlineRecord];
            byte[] Rented = RecordSize > MaxInlineRecord ? ArrayPool<byte>.Shared.Rent(RecordSize) : null;
            Span<byte> Record = Rented != null ? Rented.AsSpan(0, RecordSize) : Scratch.Slice(0, RecordSize);
            Record.Clear();
            Record[0] = (byte)'n';
            Record[1] = (byte)'k';
            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x02), (ushort)(Compressed ? KeyNameCompressed : 0));
            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x04), DateTime.UtcNow.ToFileTimeUtc());
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x10), ParentRel);
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x1C), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x20), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x28), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x2C), SecurityRel);
            BinaryPrimitives.WriteInt32LittleEndian(Record.Slice(0x30), -1);
            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x48), (ushort)NameBytes.Length);
            NameBytes.CopyTo(Record.Slice(KeyHeaderSize));

            WriteBytes(RootOffset + CellRel + 4, Record);

            if (Rented != null)
                ArrayPool<byte>.Shared.Return(Rented);

            return CellRel;
        }

        private int CreateValueCell(string Name, int Type, int SizeField, int OffsetField, byte[] Inline)
        {
            bool Compressed = IsCompressible(Name);
            byte[] NameBytes = Compressed ? Encoding.Latin1.GetBytes(Name) : Encoding.Unicode.GetBytes(Name);

            int CellRel = AllocateCell(ValueHeaderSize + NameBytes.Length);

            int RecordSize = ValueHeaderSize + NameBytes.Length;
            Span<byte> Scratch = stackalloc byte[MaxInlineRecord];
            byte[] Rented = RecordSize > MaxInlineRecord ? ArrayPool<byte>.Shared.Rent(RecordSize) : null;
            Span<byte> Record = Rented != null ? Rented.AsSpan(0, RecordSize) : Scratch.Slice(0, RecordSize);
            Record.Clear();
            Record[0] = (byte)'v';
            Record[1] = (byte)'k';
            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x02), (ushort)NameBytes.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x10), (ushort)(Compressed ? ValueNameCompressed : 0));
            NameBytes.CopyTo(Record.Slice(ValueHeaderSize));

            WriteBytes(RootOffset + CellRel + 4, Record);

            if (Rented != null)
                ArrayPool<byte>.Shared.Return(Rented);

            StoreValueFields(CellRel, SizeField, OffsetField, Inline, Type);
            return CellRel;
        }

        private void StoreValueFields(int ValueRel, int SizeField, int OffsetField, byte[] Inline, int Type)
        {
            long Abs = RootOffset + ValueRel;
            WriteI32(Abs + 0x08, SizeField);

            if (Inline != null)
                WriteBytes(Abs + 0x0C, Inline);
            else
                WriteI32(Abs + 0x0C, OffsetField);

            WriteI32(Abs + 0x10, Type);
        }

        // Four bytes or less live in the offset field itself, past 16344 they need a segmented "db" record.
        private void WriteValueData(byte[] Data, out int SizeField, out int OffsetField, out byte[] Inline)
        {
            OffsetField = -1;
            Inline = null;

            if (Data.Length <= 4)
            {
                SizeField = Data.Length | int.MinValue;
                Inline = new byte[4];
                Data.CopyTo(Inline, 0);
                return;
            }

            SizeField = Data.Length;

            if (Data.Length <= MaxSegment)
            {
                OffsetField = AllocateCell(Data.Length);
                WriteBytes(RootOffset + OffsetField + 4, Data);
                return;
            }

            int Segments = (Data.Length + MaxSegment - 1) / MaxSegment;
            int ListRel = AllocateCell(Segments * 4);
            int DbRel = AllocateCell(8);

            for (int i = 0; i < Segments; i++)
            {
                int Taken = Math.Min(MaxSegment, Data.Length - (i * MaxSegment));
                int SegmentRel = AllocateCell(MaxSegment);
                WriteBytes(RootOffset + SegmentRel + 4, Data.AsSpan(i * MaxSegment, Taken));
                WriteI32(RootOffset + ListRel + 4 + (i * 4), SegmentRel);
            }

            long DbAbs = RootOffset + DbRel;
            WriteAscii(DbAbs + 4, "db");
            WriteI16(DbAbs + 6, (short)Segments);
            WriteI32(DbAbs + 8, ListRel);

            OffsetField = DbRel;
        }

        private void ReleaseValueData(int ValueRel)
        {
            long Abs = RootOffset + ValueRel;
            int SizeField = ReadI32(Abs + 0x08);

            if ((SizeField & int.MinValue) != 0)
                return;

            int DataRel = ReadI32(Abs + 0x0C);
            if (DataRel <= 0)
                return;

            if ((SizeField & 0x7FFFFFFF) > MaxSegment && IsSignature(RootOffset + DataRel + 4, (byte)'d', (byte)'b'))
            {
                int Segments = (ushort)ReadI16(RootOffset + DataRel + 6);
                int ListRel = ReadI32(RootOffset + DataRel + 8);

                for (int i = 0; i < Segments && ListRel > 0; i++)
                    ReleaseCell(ReadI32(RootOffset + ListRel + 4 + (i * 4)));

                ReleaseCell(ListRel);
            }

            ReleaseCell(DataRel);
        }

        private void ReleaseKeyContents(int KeyRel)
        {
            long Abs = RootOffset + KeyRel;
            int Count = ReadI32(Abs + 0x28);
            int ListRel = ReadI32(Abs + 0x2C);

            if (ListRel > 0)
            {
                for (int i = 0; i < Count; i++)
                {
                    int ValueRel = ReadI32(RootOffset + ListRel + 4 + (i * 4));
                    if (ValueRel <= 0)
                        continue;

                    ReleaseValueData(ValueRel);
                    ReleaseCell(ValueRel);
                }

                ReleaseCell(ListRel);
            }

            ReleaseCell(ReadI32(Abs + 0x20));
        }

        private bool TryFindValue(int KeyRel, string Name, out int Index, out int ValueRel)
        {
            Index = -1;
            ValueRel = 0;

            long Abs = RootOffset + KeyRel;
            int Count = ReadI32(Abs + 0x28);
            int ListRel = ReadI32(Abs + 0x2C);

            if (Count <= 0 || ListRel <= 0)
                return false;

            long EntriesAbs = RootOffset + ListRel + 4;

            for (int i = 0; i < Count; i++)
            {
                int Candidate = ReadI32(EntriesAbs + (i * 4));
                if (Candidate <= 0 || !IsSignature(RootOffset + Candidate + 4, (byte)'v', (byte)'k'))
                    continue;

                if (!ValueNameMatches(Candidate, Name))
                    continue;

                Index = i;
                ValueRel = Candidate;
                return true;
            }

            return false;
        }

        // Values are stored in insertion order, so finding one means walking them.
        private bool ValueNameMatches(int CellRel, string Name)
        {
            long Abs = RootOffset + CellRel;
            int NameLen = (ushort)ReadI16(Abs + 0x06);
            bool Compressed = ((ushort)ReadI16(Abs + 0x14) & ValueNameCompressed) != 0;

            if (NameLen != (Compressed ? Name.Length : Name.Length * 2))
                return false;

            if (NameLen == 0)
                return true;

            if (NameLen > MaxInlineRecord)
                return string.Equals(ReadValueName(CellRel), Name, StringComparison.OrdinalIgnoreCase);

            if (Map != null && Map.Covers(Abs + 0x18, NameLen))
                return NameEquals(Map.Read(Abs + 0x18, NameLen), Name, Compressed);

            Span<byte> Scratch = stackalloc byte[MaxInlineRecord];
            Span<byte> Local = Scratch.Slice(0, NameLen);
            ReadInto(Abs + 0x18, Local);
            return NameEquals(Local, Name, Compressed);
        }

        private static bool NameEquals(ReadOnlySpan<byte> Bytes, string Name, bool Compressed)
        {
            for (int i = 0; i < Name.Length; i++)
            {
                char Candidate = Compressed ? (char)Bytes[i] : (char)(Bytes[i * 2] | (Bytes[(i * 2) + 1] << 8));
                char Wanted = Name[i];

                if (Candidate == Wanted)
                    continue;

                if (Candidate < 0x80 && Wanted < 0x80)
                {
                    // Only letters differ by that bit.
                    if ((Candidate | 0x20) != (Wanted | 0x20) || (uint)((Candidate | 0x20) - 'a') > 'z' - 'a')
                        return false;

                    continue;
                }

                if (char.ToUpperInvariant(Candidate) != char.ToUpperInvariant(Wanted))
                    return false;
            }

            return true;
        }

        private bool TryAppendValue(int KeyRel, int ValueRel)
        {
            long Abs = RootOffset + KeyRel;
            int Count = ReadI32(Abs + 0x28);
            int ListRel = ReadI32(Abs + 0x2C);

            if (Count < 0)
                Count = 0;

            int Needed = (Count + 1) * 4;

            if (ListRel <= 0)
            {
                ListRel = AllocateCell(Needed);
                WriteI32(Abs + 0x2C, ListRel);
            }
            else if (-ReadI32(RootOffset + ListRel) - 4 < Needed)
            {
                int Grown = AllocateCell(GrownCapacity(Count + 1) * 4);
                CopyEntries(RootOffset + ListRel + 4, RootOffset + Grown + 4, Count * 4);
                ReleaseCell(ListRel);
                ListRel = Grown;
                WriteI32(Abs + 0x2C, ListRel);
            }

            WriteI32(RootOffset + ListRel + 4 + (Count * 4), ValueRel);
            WriteI32(Abs + 0x28, Count + 1);
            return true;
        }

        private void AddSecurityReference(int SecurityRel)
        {
            if (SecurityRel <= 0 || !IsSignature(RootOffset + SecurityRel + 4, (byte)'s', (byte)'k'))
                return;

            WriteI32(RootOffset + SecurityRel + 0x10, ReadI32(RootOffset + SecurityRel + 0x10) + 1);
        }

        private void ReleaseSecurity(int SecurityRel)
        {
            if (SecurityRel <= 0 || !IsSignature(RootOffset + SecurityRel + 4, (byte)'s', (byte)'k'))
                return;

            int Count = ReadI32(RootOffset + SecurityRel + 0x10);
            if (Count > 0)
                WriteI32(RootOffset + SecurityRel + 0x10, Count - 1);
        }

        private static bool IsCompressible(string Text)
        {
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] > 0xFF)
                    return false;
            }

            return true;
        }

        private string ReadKeyName(int CellRel)
        {
            long Abs = RootOffset + CellRel;
            int Flags = (ushort)ReadI16(Abs + 0x06);
            int NameLen = (ushort)ReadI16(Abs + 0x4C);
            return ReadName(Abs + 0x50, NameLen, (Flags & KeyNameCompressed) != 0);
        }

        private string ReadValueName(int CellRel)
        {
            long Abs = RootOffset + CellRel;
            int Flags = (ushort)ReadI16(Abs + 0x14);
            int NameLen = (ushort)ReadI16(Abs + 0x06);
            return ReadName(Abs + 0x18, NameLen, (Flags & ValueNameCompressed) != 0);
        }

        private string ReadName(long Abs, int NameLen, bool Compressed)
        {
            if (NameLen <= 0)
                return string.Empty;

            byte[] Rented = ArrayPool<byte>.Shared.Rent(NameLen);
            try
            {
                Span<byte> Buffer = Rented.AsSpan(0, NameLen);
                ReadInto(Abs, Buffer);

                if (Compressed)
                {
                    int Actual = Buffer.Length;
                    while (Actual > 0 && Buffer[Actual - 1] == 0)
                        Actual--;

                    return Actual == 0 ? string.Empty : Encoding.Latin1.GetString(Buffer.Slice(0, Actual));
                }

                return Encoding.Unicode.GetString(Buffer.Slice(0, NameLen & ~1)).TrimEnd('\0');
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        private int AllocateCell(int PayloadBytes)
        {
            int CellSize = (PayloadBytes + 4 + 7) & ~7;

            for (int i = 0; i < FreeCells.Count; i++)
            {
                if (FreeCells[i].Size < CellSize)
                    continue;

                FreeCell Cell = FreeCells[i];
                FreeCells.RemoveAt(i);
                return CarveCell(Cell.Offset, Cell.Size, CellSize);
            }

            int BinSize = Math.Max(HbinGrowth, ((HbinHeaderSize + CellSize + HbinAlignment - 1) / HbinAlignment) * HbinAlignment);
            int BinRel = BinsSize;
            long BinAbs = RootOffset + (long)BinRel;

            // Writing the last byte extends the file, and the bytes in between read back as zero.
            Span<byte> Tail = stackalloc byte[1];
            WriteBytes(BinAbs + BinSize - 1, Tail);

            Span<byte> Header = stackalloc byte[HbinHeaderSize + 4];
            Header.Clear();
            Header[0] = (byte)'h';
            Header[1] = (byte)'b';
            Header[2] = (byte)'i';
            Header[3] = (byte)'n';
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x04), BinRel);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x08), BinSize);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(HbinHeaderSize), BinSize - HbinHeaderSize);
            WriteBytes(BinAbs, Header);

            BinsSize += BinSize;
            Length = RootOffset + (long)BinsSize;
            Dirty = true;

            return CarveCell(BinRel + HbinHeaderSize, BinSize - HbinHeaderSize, CellSize);
        }

        private int CarveCell(int Offset, int Available, int CellSize)
        {
            int Leftover = Available - CellSize;

            if (Leftover >= 8)
            {
                WriteI32(RootOffset + Offset + CellSize, Leftover);
                FreeCells.Add(new FreeCell { Offset = Offset + CellSize, Size = Leftover });
            }
            else
            {
                CellSize = Available;
            }

            WriteI32(RootOffset + Offset, -CellSize);
            Dirty = true;
            return Offset;
        }

        private void ReleaseCell(int CellRel)
        {
            if (CellRel <= 0)
                return;

            int Size = ReadI32(RootOffset + CellRel);
            if (Size >= 0)
                return;

            Size = -Size;
            WriteI32(RootOffset + CellRel, Size);

            // A reader tells a live cell from a dead one by the record signature.
            if (Size >= 6)
                WriteI16(RootOffset + CellRel + 4, 0);

            FreeCells.Add(new FreeCell { Offset = CellRel, Size = Size });
            Dirty = true;
        }

        private void CopyEntries(long From, long To, int Bytes)
        {
            if (Bytes <= 0)
                return;

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Bytes);
            try
            {
                Span<byte> Buffer = Rented.AsSpan(0, Bytes);
                ReadInto(From, Buffer);
                WriteBytes(To, Buffer);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        private void WriteAscii(long Offset, string Text)
        {
            Span<byte> Buffer = stackalloc byte[Text.Length];
            Encoding.ASCII.GetBytes(Text, Buffer);
            WriteBytes(Offset, Buffer);
        }

        private int ReadI32(long Offset)
        {
            if (Map != null && Map.Covers(Offset, 4))
                return Map.ReadInt32(Offset);

            Span<byte> Buffer = stackalloc byte[4];
            ReadInto(Offset, Buffer);
            return BinaryPrimitives.ReadInt32LittleEndian(Buffer);
        }

        private short ReadI16(long Offset)
        {
            if (Map != null && Map.Covers(Offset, 2))
                return Map.ReadInt16(Offset);

            Span<byte> Buffer = stackalloc byte[2];
            ReadInto(Offset, Buffer);
            return BinaryPrimitives.ReadInt16LittleEndian(Buffer);
        }

        private bool IsSignature(long Abs, byte First, byte Second)
        {
            if (Map != null && Map.Covers(Abs, 2))
                return Map.Matches(Abs, First, Second);

            Span<byte> Buffer = stackalloc byte[2];
            ReadInto(Abs, Buffer);
            return Buffer[0] == First && Buffer[1] == Second;
        }

        private void WriteI32(long Offset, int Value)
        {
            Span<byte> Buffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(Buffer, Value);
            WriteBytes(Offset, Buffer);
        }

        private void WriteI16(long Offset, short Value)
        {
            Span<byte> Buffer = stackalloc byte[2];
            BinaryPrimitives.WriteInt16LittleEndian(Buffer, Value);
            WriteBytes(Offset, Buffer);
        }

        private void WriteI64(long Offset, long Value)
        {
            Span<byte> Buffer = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(Buffer, Value);
            WriteBytes(Offset, Buffer);
        }

        private void ReadInto(long Offset, Span<byte> Buffer)
        {
            if (Map != null && Map.Covers(Offset, Buffer.Length))
            {
                Map.Read(Offset, Buffer.Length).CopyTo(Buffer);
                return;
            }

            int Total = 0;

            while (Total < Buffer.Length)
            {
                int Read = RandomAccess.Read(Handle, Buffer.Slice(Total), Offset + Total);
                if (Read <= 0)
                    throw new InvalidDataException("Failed to read hive data");

                Total += Read;
            }
        }

        private void WriteBytes(long Offset, ReadOnlySpan<byte> Data)
        {
            if (Map != null && Map.Covers(Offset, Data.Length))
            {
                Map.Write(Offset, Data);
                return;
            }

            RandomAccess.Write(Handle, Data, Offset);
        }
    }

    public class RegistryManager
    {
        private readonly string RootPath;

        public RegistryManager(string RootPath)
        {
            this.RootPath = RootPath;
        }

        public Hive LoadHive(string HiveFileName)
        {
            if (string.IsNullOrEmpty(HiveFileName))
                return null;

            string NtMountPoint = ResolveNtMountPoint(HiveFileName);
            if (string.IsNullOrEmpty(NtMountPoint))
                return null;

            string HivePath = Path.Combine(RootPath, HiveFileName);
            if (!File.Exists(HivePath))
                return null;

            FileStream Stream = null;
            bool Writable = true;

            try
            {
                try
                {
                    Stream = new FileStream(HivePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, 4096, FileOptions.RandomAccess);
                }
                catch (Exception)
                {
                    Writable = false;
                    Stream = new FileStream(HivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.RandomAccess);
                }

                Hive Loaded = new Hive
                {
                    NtMountPoint = NtMountPoint.TrimEnd('\\'),
                    Stream = Stream,
                    Handle = Stream.SafeFileHandle,
                    Length = Stream.Length
                };

                Loaded.Reader = new RegistryHiveReader(Loaded.Handle, Loaded.Length);
                Loaded.Map = RegistryHiveMap.TryCreate(Stream, Loaded.Length, Writable);
                Loaded.Reader.UseMap(Loaded.Map);
                Loaded.NoteCurrentSequence();

                if (Writable)
                {
                    Loaded.Writer = new RegistryHiveWriter(Loaded.Handle);
                    Loaded.Writer.UseMap(Loaded.Map);

                    // A host with no named mutex still loads the hive, it just cannot keep a second process out.
                    try
                    {
                        Loaded.WriteLock = new Mutex(false, HiveLockName(HivePath));
                    }
                    catch (Exception)
                    {
                        Loaded.WriteLock = null;
                    }
                }

                return Loaded;
            }
            catch
            {
                try { Stream?.Dispose(); } catch { }
                return null;
            }
        }

        // A hive set dumped from Windows has no per user hive, so HKCU is built here.
        public bool EnsureUserHive(string HiveFileName)
        {
            if (string.IsNullOrEmpty(HiveFileName))
                return false;

            string HivePath = Path.Combine(RootPath, HiveFileName);
            if (File.Exists(HivePath))
                return true;

            try
            {
                Directory.CreateDirectory(RootPath);
                File.WriteAllBytes(HivePath, BuildEmptyHive(HiveFileName));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static byte[] BuildEmptyHive(string HiveFileName)
        {
            const int HeaderSize = 0x1000;
            const int BinSize = 0x1000;
            const int RootCell = 0x20;

            byte[] Hive = new byte[HeaderSize + BinSize];
            Span<byte> Header = Hive.AsSpan(0, HeaderSize);

            Encoding.ASCII.GetBytes("regf", Header);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x04), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x08), 1);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(0x0C), DateTime.UtcNow.ToFileTimeUtc());
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x14), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x18), 5);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x1C), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x20), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x24), RootCell);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x28), BinSize);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x2C), 1);

            string Label = Path.GetFileName(HiveFileName);
            Encoding.Unicode.GetBytes(Label.Length > 31 ? Label.Substring(0, 31) : Label, Header.Slice(0x30, 64));

            Span<byte> Bin = Hive.AsSpan(HeaderSize, BinSize);
            Encoding.ASCII.GetBytes("hbin", Bin);
            BinaryPrimitives.WriteInt32LittleEndian(Bin.Slice(0x04), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Bin.Slice(0x08), BinSize);
            BinaryPrimitives.WriteInt64LittleEndian(Bin.Slice(0x14), DateTime.UtcNow.ToFileTimeUtc());

            string RootName = "CMI-CreateHive{00000000-0000-0000-0000-000000000000}";
            int RootPayload = 0x4C + RootName.Length;
            int RootSize = (RootPayload + 4 + 7) & ~7;
            int SecurityCell = RootCell + RootSize;
            int SecuritySize = 0x30;

            Span<byte> Root = Bin.Slice(RootCell);
            BinaryPrimitives.WriteInt32LittleEndian(Root, -RootSize);
            Encoding.ASCII.GetBytes("nk", Root.Slice(0x04));
            BinaryPrimitives.WriteUInt16LittleEndian(Root.Slice(0x06), 0x002C);
            BinaryPrimitives.WriteInt64LittleEndian(Root.Slice(0x08), DateTime.UtcNow.ToFileTimeUtc());
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x14), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x20), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x24), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x2C), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x30), SecurityCell);
            BinaryPrimitives.WriteInt32LittleEndian(Root.Slice(0x34), -1);
            BinaryPrimitives.WriteUInt16LittleEndian(Root.Slice(0x4C), (ushort)RootName.Length);
            Encoding.Latin1.GetBytes(RootName, Root.Slice(0x50));

            Span<byte> Security = Bin.Slice(SecurityCell);
            BinaryPrimitives.WriteInt32LittleEndian(Security, -SecuritySize);
            Encoding.ASCII.GetBytes("sk", Security.Slice(0x04));
            BinaryPrimitives.WriteInt32LittleEndian(Security.Slice(0x08), SecurityCell);
            BinaryPrimitives.WriteInt32LittleEndian(Security.Slice(0x0C), SecurityCell);
            BinaryPrimitives.WriteInt32LittleEndian(Security.Slice(0x10), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Security.Slice(0x14), 20);
            Security[0x18] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(Security.Slice(0x1A), 0x8004);

            int FreeCell = SecurityCell + SecuritySize;
            BinaryPrimitives.WriteInt32LittleEndian(Bin.Slice(FreeCell), BinSize - FreeCell);

            uint Checksum = 0;
            for (int i = 0; i < 0x1FC; i += 4)
                Checksum ^= BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(i, 4));

            if (Checksum == 0)
                Checksum = 1;
            else if (Checksum == uint.MaxValue)
                Checksum = uint.MaxValue - 1;

            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x1FC), Checksum);
            return Hive;
        }

        private static string HiveLockName(string HivePath)
        {
            ulong Hash = 14695981039346656037UL;

            foreach (char Character in HivePath.ToLowerInvariant())
            {
                Hash ^= Character;
                Hash *= 1099511628211UL;
            }

            return "BrovanHive_" + Hash.ToString("x16");
        }

        internal Hive GetHiveByNtPath(Hive[] RegHives, string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            if (RegHives == null || RegHives.Length == 0)
                return null;

            NtPath = NtPath.TrimEnd('\0');

            Hive BestHive = null;
            int BestLen = -1;

            foreach (Hive h in RegHives)
            {
                if (h == null || h.Reader == null)
                    continue;

                if (string.IsNullOrEmpty(h.NtMountPoint))
                    continue;

                string Mount = h.NtMountPoint.TrimEnd('\\');

                if (NtPath.Equals(Mount, StringComparison.OrdinalIgnoreCase) ||
                    NtPath.StartsWith(Mount + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    if (Mount.Length > BestLen)
                    {
                        BestLen = Mount.Length;
                        BestHive = h;
                    }
                }
            }

            return BestHive;
        }

        internal string NormalizeNtRegistryPath(Hive Hive, string NtPath)
        {
            if (Hive == null || string.IsNullOrEmpty(Hive.NtMountPoint) || string.IsNullOrEmpty(NtPath))
                return null;

            NtPath = NtPath.TrimEnd('\0');

            string Mount = Hive.NtMountPoint.TrimEnd('\\');

            if (NtPath.Equals(Mount, StringComparison.OrdinalIgnoreCase))
                return "\\";

            if (!NtPath.StartsWith(Mount + "\\", StringComparison.OrdinalIgnoreCase))
                return null;

            string Rel = NtPath.Substring(Mount.Length);
            return NormalizeKeyPath(Rel);
        }

        internal static string NormalizeKeyPath(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return "\\";

            if (IsNormalizedKeyPath(Path))
                return Path;

            Path = Path.TrimEnd('\0');

            if (!Path.StartsWith("\\", StringComparison.Ordinal))
                Path = "\\" + Path;

            while (Path.Contains("\\\\", StringComparison.Ordinal))
                Path = Path.Replace("\\\\", "\\", StringComparison.Ordinal);

            if (Path.Length > 1 && Path.EndsWith("\\", StringComparison.Ordinal))
                Path = Path.TrimEnd('\\');

            return Path;
        }

        private static bool IsNormalizedKeyPath(string Path)
        {
            if (Path[0] != '\\' || (Path.Length > 1 && Path[Path.Length - 1] == '\\'))
                return false;

            for (int i = 1; i < Path.Length; i++)
            {
                char Current = Path[i];

                if (Current == '\0' || (Current == '\\' && Path[i - 1] == '\\'))
                    return false;
            }

            return true;
        }

        private string ResolveNtMountPoint(string HiveFileName)
        {
            string Name = Path.GetFileName(HiveFileName);

            if (string.IsNullOrEmpty(Name))
                return null;

            if (Name.Equals("SOFTWARE", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\Machine\SOFTWARE";

            if (Name.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\Machine\SYSTEM";

            if (Name.Equals("SAM", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\Machine\SAM";

            if (Name.Equals("SECURITY", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\Machine\SECURITY";

            if (Name.Equals("HARDWARE", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\Machine\HARDWARE";

            if (Name.Equals("NTUSER.DAT", StringComparison.OrdinalIgnoreCase))
                return @"\Registry\User\S-1-5-21-1000-1000-1000-1001";

            return null;
        }
    }
}