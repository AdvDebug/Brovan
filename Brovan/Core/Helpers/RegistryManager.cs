using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers
{
    public class Hive : IDisposable
    {
        internal string NtMountPoint;
        internal RegistryHiveReader Reader;

        internal FileStream Stream;
        internal SafeFileHandle Handle;
        internal long Length;

        public void Dispose()
        {
            try { Reader = null; } catch { }
            try { Handle = null; } catch { }

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
        private const int MainRootOffset = 0x1000;
        private const int MainKeyBlockOffset = MainRootOffset + 0x20;

        private readonly SafeFileHandle Handle;
        private readonly long Length;

        private readonly Dictionary<string, HiveKey> PathCache = new(StringComparer.OrdinalIgnoreCase);
        private const int MaxCachedPaths = 8192;
        private HiveKey CachedRootKey;

        public RegistryHiveReader(SafeFileHandle Handle, long Length)
        {
            this.Handle = Handle ?? throw new ArgumentNullException(nameof(Handle));
            this.Length = Length;
            ValidateRegf();
        }

        public HiveKey GetRootKey()
        {
            return CachedRootKey ??= ReadKeyAtAbsolute(MainKeyBlockOffset);
        }

        private void StorePathResult(string Path, HiveKey Key)
        {
            if (PathCache.Count >= MaxCachedPaths)
                PathCache.Clear();

            PathCache[Path] = Key;
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

            if (PathCache.TryGetValue(RelativePath, out HiveKey Cached))
            {
                Key = Cached;
                return Cached != null;
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

                if (Path.IndexOf("\\CurrentControlSet\\", StringComparison.OrdinalIgnoreCase) != -1)
                    Path = Path.Replace("\\CurrentControlSet\\", "\\ControlSet001\\", StringComparison.OrdinalIgnoreCase);

                string[] Parts = Path.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
                string Prefix = string.Empty;
                for (int i = 0; i < Parts.Length; i++)
                {
                    Prefix = string.Concat(Prefix, "\\", Parts[i]);

                    if (Self.PathCache.TryGetValue(Prefix, out HiveKey CachedNode))
                    {
                        if (CachedNode == null)
                            return false;

                        Current = CachedNode;
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

            HiveKey Local = Parent;

            EnsureSubKeysParsed(ref Local);

            if (Local.SubKeys == null)
                return false;

            if (!Local.SubKeys.TryGetValue(Name, out int SubKeyRelOffset))
                return false;

            int Abs = MainRootOffset + SubKeyRelOffset;
            SubKey = ReadKeyAtAbsolute(Abs);
            return true;
        }

        public bool TryEnumerateSubKey(HiveKey Key, int Index, out string Name)
        {
            Name = null;

            if (Index < 0)
                return false;

            if (Key.SubKeyBlockOffset <= 0)
                return false;

            int ItemAbs = MainRootOffset + Key.SubKeyBlockOffset;
            EnsureInBounds(ItemAbs, 0x0C);

            string BlockType = ReadAscii(ItemAbs + 4, 2);

            if (BlockType.Length != 2 || (BlockType[1] != 'f' && BlockType[1] != 'h'))
                return false;

            short Count = ReadI16(ItemAbs + 0x06);
            if (Index >= Count)
                return false;

            int EntriesAbs = ItemAbs + 0x08;
            EnsureInBounds(EntriesAbs, Count * 8);

            int EntryAbs = EntriesAbs + (Index * 8);

            int Offset = ReadI32(EntryAbs);
            int SubKeyAbs = MainRootOffset + Offset;

            EnsureInBounds(SubKeyAbs, 0x60);

            string NkType = ReadAscii(SubKeyAbs + 4, 2);
            if (NkType != "nk")
                return false;

            short NameLen = ReadI16(SubKeyAbs + 0x4C);
            int NameOffset = SubKeyAbs + 0x50;

            EnsureInBounds(NameOffset, Math.Max((short)0, NameLen));

            Name = ReadNameUtf8(NameOffset, NameLen);
            return true;
        }

        public bool TryQueryKeyHeader(HiveKey Key, out int SubKeyCount, out int ValueCount, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            Name = null;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            string BlockType = ReadAscii(Abs + 4, 2);
            if (BlockType != "nk")
                return false;

            SubKeyCount = ReadI32(Abs + 0x18);
            ValueCount = ReadI32(Abs + 0x28);

            short NameLen = ReadI16(Abs + 0x4C);
            int NameOffset = Abs + 0x50;

            EnsureInBounds(NameOffset, Math.Max((short)0, NameLen));

            Name = ReadNameUtf8(NameOffset, NameLen);
            return true;
        }

        public bool TryQueryKeyFullInfo(HiveKey Key, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            MaxSubKeyNameChars = 0;
            MaxValueNameChars = 0;
            MaxValueDataBytes = 0;

            if (!TryQueryKeyHeader(Key, out SubKeyCount, out ValueCount, out _))
                return false;

            for (int i = 0; i < SubKeyCount; i++)
            {
                if (TryEnumerateSubKey(Key, i, out string SubName))
                {
                    int Chars = SubName == null ? 0 : SubName.Length;
                    if (Chars > MaxSubKeyNameChars)
                        MaxSubKeyNameChars = Chars;
                }
            }

            if (ValueCount > 0)
            {
                int Abs = Key.KeyBlockAbs;
                int ValueOffsets = ReadI32(Abs + 0x2C);

                int ListAbs = MainRootOffset + ValueOffsets + 4;
                EnsureInBounds(ListAbs, ValueCount * 4);

                for (int i = 0; i < ValueCount; i++)
                {
                    int RelOffset = ReadI32(ListAbs + (i * 4));
                    int VkAbs = MainRootOffset + RelOffset;

                    EnsureInBounds(VkAbs, 0x20);

                    string VkType = ReadAscii(VkAbs + 4, 2);
                    if (VkType != "vk")
                        continue;

                    short NameLen = ReadI16(VkAbs + 0x06);
                    int Size = ReadI32(VkAbs + 0x08);

                    int DataLen = Size & 0xFFFF;
                    if (DataLen > MaxValueDataBytes)
                        MaxValueDataBytes = DataLen;

                    int NameChars = NameLen;
                    if (NameChars > MaxValueNameChars)
                        MaxValueNameChars = NameChars;
                }
            }

            return true;
        }

        public bool TryEnumerateValueBasic(HiveKey Key, int Index, out string Name, out int Type, out int DataLength)
        {
            Name = null;
            Type = 0;
            DataLength = 0;

            if (Index < 0)
                return false;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            string NkType = ReadAscii(Abs + 4, 2);
            if (NkType != "nk")
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

            string VkType = ReadAscii(VkAbs + 4, 2);
            if (VkType != "vk")
                return false;

            short NameLen = ReadI16(VkAbs + 0x06);
            int Size = ReadI32(VkAbs + 0x08);
            int ValueType = ReadI32(VkAbs + 0x10);

            int NameOffset = VkAbs + 0x18;
            EnsureInBounds(NameOffset, Math.Max((short)0, NameLen));

            Name = ReadNameUtf8(NameOffset, NameLen);

            Type = ValueType;
            DataLength = Size & 0xFFFF;

            return true;
        }

        public bool TryEnumerateValueFull(HiveKey Key, int Index, out string Name, out int Type, out byte[] Data)
        {
            Name = null;
            Type = 0;
            Data = null;

            if (Index < 0)
                return false;

            int Abs = Key.KeyBlockAbs;
            EnsureInBounds(Abs, 0x60);

            string NkType = ReadAscii(Abs + 4, 2);
            if (NkType != "nk")
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

            string VkType = ReadAscii(VkAbs + 4, 2);
            if (VkType != "vk")
                return false;

            short NameLen = ReadI16(VkAbs + 0x06);
            int Size = ReadI32(VkAbs + 0x08);
            int Offset = ReadI32(VkAbs + 0x0C);
            int ValueType = ReadI32(VkAbs + 0x10);

            int NameOffset = VkAbs + 0x18;
            EnsureInBounds(NameOffset, Math.Max((short)0, NameLen));

            Name = ReadNameUtf8(NameOffset, NameLen);

            RawHiveValue Raw = new RawHiveValue
            {
                Type = ValueType,
                Name = Name,
                DataLength = Size & 0xFFFF,
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

        private HiveKey ReadKeyAtAbsolute(int Abs)
        {
            EnsureInBounds(Abs, 0x60);

            string BlockType = ReadAscii(Abs + 4, 2);
            if (BlockType != "nk")
                throw new InvalidDataException($"Expected nk at {Abs:X}, got {BlockType}");

            int SubKeyCount = ReadI32(Abs + 0x18);
            int SubKeys = ReadI32(Abs + 0x20);
            int ValueCount = ReadI32(Abs + 0x28);
            int Offsets = ReadI32(Abs + 0x2C);
            short NameLen = ReadI16(Abs + 0x4C);

            int NameOffset = Abs + 0x50;
            EnsureInBounds(NameOffset, Math.Max((ushort)0, NameLen));

            string Name = ReadNameUtf8(NameOffset, NameLen);

            return new HiveKey
            {
                KeyBlockAbs = Abs,
                Name = Name,
                SubKeyBlockOffset = SubKeys,
                SubKeyCount = SubKeyCount,
                ValueCount = ValueCount,
                ValueOffsets = Offsets,
                ValuesParsed = false,
                SubKeysParsed = false,
                Values = null,
                SubKeys = null
            };
        }

        private void EnsureValuesParsed(ref HiveKey Key)
        {
            if (Key.ValuesParsed)
                return;

            Key.ValuesParsed = true;

            Dictionary<string, RawHiveValue> Values = new(StringComparer.OrdinalIgnoreCase);

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

                string BlockType = ReadAscii(VkAbs + 4, 2);
                if (BlockType != "vk")
                    continue;

                short NameLen = ReadI16(VkAbs + 0x06);
                int Size = ReadI32(VkAbs + 0x08);
                int Offset = ReadI32(VkAbs + 0x0C);
                int ValueType = ReadI32(VkAbs + 0x10);

                int NameOffset = VkAbs + 0x18;
                EnsureInBounds(NameOffset, Math.Max((ushort)0, NameLen));

                string ValueName = ReadNameUtf8(NameOffset, NameLen);

                RawHiveValue Raw = new RawHiveValue
                {
                    Type = ValueType,
                    Name = ValueName,
                    DataLength = Size & 0xFFFF,
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

            Dictionary<string, int> SubKeys = new(StringComparer.OrdinalIgnoreCase);

            if (Key.SubKeyBlockOffset <= 0)
            {
                Key.SubKeys = SubKeys;
                return;
            }

            int ItemAbs = MainRootOffset + Key.SubKeyBlockOffset;
            EnsureInBounds(ItemAbs, 0x0C);

            string BlockType = ReadAscii(ItemAbs + 4, 2);

            if (BlockType.Length != 2 || (BlockType[1] != 'f' && BlockType[1] != 'h'))
            {
                Key.SubKeys = SubKeys;
                return;
            }

            short Count = ReadI16(ItemAbs + 0x06);
            int EntriesAbs = ItemAbs + 0x08;

            EnsureInBounds(EntriesAbs, Count * 8);

            for (int i = 0; i < Count; i++)
            {
                int EntryAbs = EntriesAbs + (i * 8);

                int Offset = ReadI32(EntryAbs);
                int SubKeyAbs = MainRootOffset + Offset;

                EnsureInBounds(SubKeyAbs, 0x60);

                string NkType = ReadAscii(SubKeyAbs + 4, 2);
                if (NkType != "nk")
                    continue;

                short NameLen = ReadI16(SubKeyAbs + 0x4C);
                int NameOffset = SubKeyAbs + 0x50;

                EnsureInBounds(NameOffset, Math.Max((ushort)0, NameLen));

                string SubKeyName = ReadNameUtf8(NameOffset, NameLen);

                if (!SubKeys.ContainsKey(SubKeyName))
                    SubKeys.Add(SubKeyName, Offset);
            }

            Key.SubKeys = SubKeys;
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
            EnsureInBounds(Abs, Raw.DataLength);

            byte[] Result = new byte[Raw.DataLength];
            ReadBytes(Abs, Result, 0, Result.Length);
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

        private string ReadNameUtf8(int Offset, int Length)
        {
            if (Length <= 0)
                return string.Empty;

            EnsureInBounds(Offset, Length);

            const int StackLimit = 256;

            if (Length <= StackLimit)
            {
                Span<byte> Buf = stackalloc byte[Length];
                ReadBytes(Offset, Buf);

                int Actual = Length;
                while (Actual > 0 && Buf[Actual - 1] == 0)
                    Actual--;

                return Actual == 0 ? string.Empty : Encoding.UTF8.GetString(Buf.Slice(0, Actual));
            }

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Length);
            try
            {
                Span<byte> Buf = Rented.AsSpan(0, Length);
                ReadBytes(Offset, Buf);

                int Actual = Length;
                while (Actual > 0 && Buf[Actual - 1] == 0)
                    Actual--;

                return Actual == 0 ? string.Empty : Encoding.UTF8.GetString(Buf.Slice(0, Actual));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
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
            Span<byte> Buf = stackalloc byte[4];
            ReadSpan(Offset, Buf);
            return BitConverter.ToInt32(Buf);
        }

        private short ReadI16(int Offset)
        {
            Span<byte> Buf = stackalloc byte[2];
            ReadSpan(Offset, Buf);
            return BitConverter.ToInt16(Buf);
        }

        private void ReadSpan(int Offset, Span<byte> Buffer)
        {
            EnsureInBounds(Offset, Buffer.Length);

            int Total = 0;

            while (Total < Buffer.Length)
            {
                int Read = RandomAccess.Read(Handle, Buffer.Slice(Total), Offset + Total);
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
                int Read = RandomAccess.Read(Handle, Buffer.AsSpan(BufferOffset + Total, Count - Total), Offset + Total);
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
                int Read = RandomAccess.Read(Handle, Buffer.Slice(Total), Offset + Total);
                if (Read <= 0)
                    throw new InvalidDataException("Failed to read hive data");

                Total += Read;
            }
        }

        public class HiveKey
        {
            internal int KeyBlockAbs;
            public string Name;
            public int SubKeyBlockOffset;
            public int SubKeyCount;
            public int ValueCount;
            public int ValueOffsets;

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

            try
            {
                Stream = new FileStream(HivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.RandomAccess);

                Hive Loaded = new Hive
                {
                    NtMountPoint = NtMountPoint.TrimEnd('\\'),
                    Stream = Stream,
                    Handle = Stream.SafeFileHandle,
                    Length = Stream.Length
                };

                Loaded.Reader = new RegistryHiveReader(Loaded.Handle, Loaded.Length);
                return Loaded;
            }
            catch
            {
                try { Stream?.Dispose(); } catch { }
                return null;
            }
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

            Path = Path.TrimEnd('\0');

            if (!Path.StartsWith("\\", StringComparison.Ordinal))
                Path = "\\" + Path;

            while (Path.Contains("\\\\", StringComparison.Ordinal))
                Path = Path.Replace("\\\\", "\\", StringComparison.Ordinal);

            if (Path.Length > 1 && Path.EndsWith("\\", StringComparison.Ordinal))
                Path = Path.TrimEnd('\\');

            return Path;
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