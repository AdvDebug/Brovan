using System;
using System.IO;
using Microsoft.Win32.SafeHandles;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Provides overlay-backed Windows file IO where writes always materialize into the Windows VFS and reads prefer the VFS before falling back to an allowed host file.
    /// </summary>
    public sealed class WindowsFileStream : Stream
    {
        private const int CopyBufferSize = 81920;
        private const FileShare ShareMode = FileShare.ReadWrite | FileShare.Delete;

        private long PositionValue;

        private readonly object HandleLock = new object();
        private SafeFileHandle CachedHandle;
        private string CachedHandlePath;
        private bool CachedHandleWritable;
        private bool CachedHandleReadable;

        // The VFS write copy only appears when this layer materializes it, so both host probes are memoized
        // per stream and dropped whenever anything reshapes the sandbox.
        private static int VfsProbeVersion;
        private int WriteProbeVersion = -1;
        private int ReadProbeVersion = -1;
        private bool WriteProbeIsFile;
        private bool WriteProbeIsDirectory;
        private FileAttributes WriteProbeAttributes;
        private bool ReadProbeIsFile;
        private bool ReadProbeIsDirectory;
        private FileAttributes ReadProbeAttributes;

        private int LookupVersion = -1;
        private GeneralHelper.IO.HostEntryKind WriteLookupKind;
        private GeneralHelper.IO.HostEntryKind ReadLookupKind;

        public string GuestPath { get; }
        public string ReadHostPath { get; }
        public string WriteHostPath { get; }

        public WindowsFileStream(string GuestPath, string ReadHostPath, string WriteHostPath)
        {
            this.GuestPath = GuestPath ?? string.Empty;
            this.ReadHostPath = ReadHostPath ?? string.Empty;
            this.WriteHostPath = WriteHostPath ?? string.Empty;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => true;

        public override long Length
        {
            get
            {
                lock (HandleLock)
                {
                    SafeFileHandle Handle = AcquireReadHandle();
                    return Handle == null ? 0 : RandomAccess.GetLength(Handle);
                }
            }
        }

        /// <summary>
        /// Reads the metadata through the host handle this stream already holds for its effective file or
        /// directory. Returns false when there is no such handle, and nothing is opened for it.
        /// </summary>
        public bool TryGetHandleMetadata(out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long Length)
        {
            lock (HandleLock)
            {
                if (CachedHandle == null || !string.Equals(CachedHandlePath, EffectiveReadHostPath, StringComparison.Ordinal))
                {
                    Attributes = 0;
                    CreationTime = 0;
                    LastAccessTime = 0;
                    LastWriteTime = 0;
                    Length = 0;
                    return false;
                }

                return GeneralHelper.IO.TryGetHandleMetadata(CachedHandle, out Attributes, out CreationTime, out LastAccessTime, out LastWriteTime, out Length);
            }
        }

        public override long Position
        {
            get => PositionValue;
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value));

                PositionValue = value;
            }
        }

        private void ProbeWriteStore()
        {
            int Version = Volatile.Read(ref VfsProbeVersion);
            if (WriteProbeVersion == Version)
                return;

            if (string.IsNullOrWhiteSpace(WriteHostPath))
            {
                WriteProbeIsFile = false;
                WriteProbeIsDirectory = false;
                WriteProbeAttributes = 0;
            }
            else
            {
                GeneralHelper.IO.ProbeHostEntry(WriteHostPath, out WriteProbeIsFile, out WriteProbeIsDirectory, out WriteProbeAttributes);
            }

            WriteProbeVersion = Version;
        }

        private void ProbeReadStore()
        {
            int Version = Volatile.Read(ref VfsProbeVersion);
            if (ReadProbeVersion == Version)
                return;

            if (string.IsNullOrWhiteSpace(ReadHostPath))
            {
                ReadProbeIsFile = false;
                ReadProbeIsDirectory = false;
                ReadProbeAttributes = 0;
            }
            else
            {
                GeneralHelper.IO.ProbeHostEntry(ReadHostPath, out ReadProbeIsFile, out ReadProbeIsDirectory, out ReadProbeAttributes);
            }

            ReadProbeVersion = Version;
        }

        // Another stream can hold a probe for the same path, so materializing a write copy has to reach all of them.
        private static void DropStoreProbes() => Interlocked.Increment(ref VfsProbeVersion);

        public string EffectiveReadHostPath
        {
            get
            {
                ProbeWriteStore();
                return WriteProbeIsFile || WriteProbeIsDirectory ? WriteHostPath : ReadHostPath;
            }
        }

        public bool ExistsAsFile
        {
            get
            {
                ProbeWriteStore();
                if (WriteProbeIsFile)
                    return true;

                if (WriteProbeIsDirectory)
                    return false;

                ProbeReadStore();
                return ReadProbeIsFile;
            }
        }

        public bool IsReadOnly
        {
            get
            {
                ProbeWriteStore();
                if (WriteProbeIsFile || WriteProbeIsDirectory)
                    return (WriteProbeAttributes & FileAttributes.ReadOnly) != 0;

                ProbeReadStore();
                return (ReadProbeAttributes & FileAttributes.ReadOnly) != 0;
            }
        }

        private const FileAttributes SettableAttributes =
            FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Archive;

        /// <summary>
        /// Stores the settable FILE_BASIC_INFORMATION attributes on the VFS copy, materializing it first so the
        /// read layer is never changed. Returns false when there is nothing to apply them to.
        /// </summary>
        public bool TryApplyAttributes(FileAttributes Attributes)
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                return false;

            FileAttributes Wanted = Attributes & SettableAttributes;

            try
            {
                string ReadPath = EffectiveReadHostPath;
                if (string.IsNullOrWhiteSpace(ReadPath))
                    return false;

                // Skip materializing the VFS copy when the entry already carries these attributes.
                if ((File.GetAttributes(ReadPath) & SettableAttributes) == Wanted)
                    return true;
            }
            catch
            {
                return false;
            }

            try
            {
                if (ExistsAsDirectory)
                {
                    Directory.CreateDirectory(WriteHostPath);
                }
                else if (ExistsAsFile)
                {
                    lock (HandleLock)
                    {
                        CloseCachedHandle();
                        EnsureWriteStore(true);
                    }
                }
                else
                {
                    return false;
                }

                FileAttributes Current = File.GetAttributes(WriteHostPath);
                File.SetAttributes(WriteHostPath, (Current & ~SettableAttributes) | Wanted);
                DropStoreProbes();
                return true;
            }
            catch
            {
                return false;
            }
        }

        // A zero field leaves that timestamp alone. -1 means "stop updating it", which the VFS cannot express.
        public bool TryApplyTimes(long CreationTime, long LastAccessTime, long LastWriteTime)
        {
            if (CreationTime <= 0 && LastAccessTime <= 0 && LastWriteTime <= 0)
                return true;

            if (string.IsNullOrWhiteSpace(WriteHostPath))
                return false;

            try
            {
                bool Directory = ExistsAsDirectory;
                if (Directory)
                {
                    System.IO.Directory.CreateDirectory(WriteHostPath);
                }
                else if (ExistsAsFile)
                {
                    lock (HandleLock)
                    {
                        CloseCachedHandle();
                        EnsureWriteStore(true);
                    }
                }
                else
                {
                    return false;
                }

                if (CreationTime > 0)
                    SetTime(Directory, WriteHostPath, CreationTime, System.IO.File.SetCreationTimeUtc, System.IO.Directory.SetCreationTimeUtc);
                if (LastAccessTime > 0)
                    SetTime(Directory, WriteHostPath, LastAccessTime, System.IO.File.SetLastAccessTimeUtc, System.IO.Directory.SetLastAccessTimeUtc);
                if (LastWriteTime > 0)
                    SetTime(Directory, WriteHostPath, LastWriteTime, System.IO.File.SetLastWriteTimeUtc, System.IO.Directory.SetLastWriteTimeUtc);

                DropStoreProbes();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void SetTime(bool Directory, string HostPath, long FileTime, Action<string, DateTime> FileSetter, Action<string, DateTime> DirectorySetter)
        {
            DateTime Value = DateTime.FromFileTimeUtc(FileTime);
            if (Directory)
                DirectorySetter(HostPath, Value);
            else
                FileSetter(HostPath, Value);
        }

        public bool ExistsAsDirectory
        {
            get
            {
                ProbeWriteStore();
                if (WriteProbeIsDirectory)
                    return true;

                if (WriteProbeIsFile)
                    return false;

                ProbeReadStore();
                return ReadProbeIsDirectory;
            }
        }

        // The overlay shadows the read layer rather than replacing it, so both have to be checked.
        public bool IsDirectoryEmpty
        {
            get
            {
                foreach (string Candidate in new[] { WriteHostPath, ReadHostPath })
                {
                    if (string.IsNullOrWhiteSpace(Candidate))
                        continue;

                    try
                    {
                        if (!Directory.Exists(Candidate))
                            continue;

                        foreach (string Unused in Directory.EnumerateFileSystemEntries(Candidate))
                            return false;
                    }
                    catch
                    {
                    }
                }

                return true;
            }
        }

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string Read, string Write)> GuestPathCache =
            new(StringComparer.OrdinalIgnoreCase);
        public static void InvalidateGuestPathCache()
        {
            GuestPathCache.Clear();
            Interlocked.Increment(ref VfsProbeVersion);
            GeneralHelper.IO.InvalidateSandboxLinkCache();
        }

        /// <summary>
        /// Invalidates what a removed or renamed host entry can change. The guest cannot create a host link, so a
        /// plain file that goes away changes no link walk and the sandbox caches stay.
        /// </summary>
        public static void InvalidateRemovedEntry(FileAttributes Attributes)
        {
            if ((Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                InvalidateGuestPathCache();
                return;
            }

            GuestPathCache.Clear();
            Interlocked.Increment(ref VfsProbeVersion);
        }

        public static WindowsFileStream FromGuestPath(string GuestPath, bool CreateWriteDirectories = false, bool NativeSystemView = false)
        {
            bool Cacheable = !CreateWriteDirectories && !NativeSystemView && GuestPath != null;
            if (Cacheable && GuestPathCache.TryGetValue(GuestPath, out var Cached))
                return new WindowsFileStream(GuestPath, Cached.Read, Cached.Write);
            string ReadHostPath = GeneralHelper.IO.ResolveHostPath(GuestPath, BinaryFormat.PE, false, false, NativeSystemView);
            string WriteHostPath = GeneralHelper.IO.ResolveVirtualHostPath(GuestPath, BinaryFormat.PE, CreateWriteDirectories);
            if (Cacheable && ReadHostPath != null && WriteHostPath != null)
            {
                if (GuestPathCache.Count >= Brovan.Core.Settings.MemoryBudget.SandboxPathCacheEntries)
                    GuestPathCache.Clear();

                GuestPathCache[GuestPath] = (ReadHostPath, WriteHostPath);
            }
            return new WindowsFileStream(GuestPath, ReadHostPath, WriteHostPath);
        }

        public byte[] ReadAllBytes()
        {
            return File.ReadAllBytes(GetReadableFilePath());
        }

        public void WriteAllBytes(byte[] Data)
        {
            ValidateBuffer(Data, 0, Data.Length);
            EnsureWriteStore(false);

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            if (Data.Length != 0)
                Stream.Write(Data, 0, Data.Length);

            Stream.Flush();
            PositionValue = Data.Length;
        }

        public void CopyFrom(WindowsFileStream Source)
        {
            if (!Source.ExistsAsFile)
            {
                WriteAllBytes(Array.Empty<byte>());
                return;
            }

            string SourcePath = Source.GetReadableFilePath();
            EnsureWriteParentExists();

            try
            {
                File.Copy(SourcePath, WriteHostPath, true);
            }
            catch
            {
                if (File.Exists(WriteHostPath))
                    File.Delete(WriteHostPath);

                throw;
            }
            finally
            {
                DropStoreProbes();
            }
        }

        public bool TryReadAllBytes(out byte[] Data)
        {
            try
            {
                Data = ReadAllBytes();
                return true;
            }
            catch
            {
                Data = null;
                return false;
            }
        }

        public override void Flush()
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                return;

            lock (HandleLock)
            {
                if (!HoldsWriteHandle)
                {
                    if (!File.Exists(WriteHostPath))
                        return;

                    AcquireWriteHandle();
                }

                RandomAccess.FlushToDisk(CachedHandle);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int BytesRead = ReadAt(PositionValue, buffer, offset, count);
            PositionValue += BytesRead;
            return BytesRead;
        }

        public int ReadAt(long position, byte[] buffer, int offset, int count)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            ValidateBuffer(buffer, offset, count);
            return ReadAt(position, buffer.AsSpan(offset, count));
        }

        public int ReadAt(long position, Span<byte> buffer)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            lock (HandleLock)
            {
                SafeFileHandle Handle = AcquireReadHandle();
                if (Handle == null)
                    throw new FileNotFoundException(GuestPath);

                return RandomAccess.Read(Handle, buffer, position);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAt(PositionValue, buffer, offset, count);
            PositionValue += count;
        }

        public void WriteAt(long position, byte[] buffer, int offset, int count)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            ValidateBuffer(buffer, offset, count);
            WriteAt(position, buffer.AsSpan(offset, count));
        }

        public void WriteAt(long position, ReadOnlySpan<byte> buffer)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            lock (HandleLock)
            {
                RandomAccess.Write(AcquireWriteHandle(), buffer, position);
            }
        }

        public void WriteAppend(byte[] buffer, int offset, int count)
        {
            ValidateBuffer(buffer, offset, count);

            lock (HandleLock)
            {
                SafeFileHandle Handle = AcquireWriteHandle();
                long End = RandomAccess.GetLength(Handle);
                RandomAccess.Write(Handle, buffer.AsSpan(offset, count), End);
                PositionValue = End + count;
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long BaseOffset = origin switch
            {
                SeekOrigin.Begin => 0,
                SeekOrigin.Current => PositionValue,
                SeekOrigin.End => Length,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };

            long NewPosition = checked(BaseOffset + offset);
            if (NewPosition < 0)
                throw new IOException("Negative seek offset.");

            PositionValue = NewPosition;
            return PositionValue;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));

            lock (HandleLock)
            {
                RandomAccess.SetLength(AcquireWriteHandle(), value);
            }

            if (PositionValue > value)
                PositionValue = value;
        }

        public void Truncate()
        {
            if (!WriteParentKnownToExist)
                EnsureWriteParentExists();

            lock (HandleLock)
            {
                CloseCachedHandle();
                SafeFileHandle Handle = File.OpenHandle(WriteHostPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, ShareMode);
                try
                {
                    RandomAccess.SetLength(Handle, 0);
                }
                catch
                {
                    Handle.Dispose();
                    throw;
                }

                CachedHandle = Handle;
                CachedHandlePath = WriteHostPath;
                CachedHandleWritable = true;
                CachedHandleReadable = true;
            }

            PositionValue = 0;
            DropStoreProbes();
        }

        public void CreateDirectory()
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                throw new UnauthorizedAccessException("No Windows VFS write path is available.");

            if (File.Exists(WriteHostPath))
                throw new IOException("The Windows VFS write path is a file.");

            Directory.CreateDirectory(WriteHostPath);
            DropStoreProbes();
        }

        private string GetReadableFilePath()
        {
            string HostPath = EffectiveReadHostPath;

            if (string.IsNullOrWhiteSpace(HostPath) || !File.Exists(HostPath))
                throw new FileNotFoundException(GuestPath);

            return HostPath;
        }

        private SafeFileHandle AcquireReadHandle()
        {
            string HostPath = EffectiveReadHostPath;
            if (string.IsNullOrWhiteSpace(HostPath))
            {
                CloseCachedHandle();
                return null;
            }

            if (CachedHandle != null && CachedHandleReadable && string.Equals(CachedHandlePath, HostPath, StringComparison.Ordinal))
                return CachedHandle;

            CloseCachedHandle();
            if (!ExistsAsFile)
                return null;

            try
            {
                CachedHandle = File.OpenHandle(HostPath, FileMode.Open, FileAccess.Read, ShareMode);
            }
            catch (Exception Ex) when (Ex is FileNotFoundException || Ex is DirectoryNotFoundException)
            {
                // The probe is memoized, and another host process can remove the file after it.
                return null;
            }

            CachedHandlePath = HostPath;
            CachedHandleWritable = false;
            CachedHandleReadable = true;
            return CachedHandle;
        }

        private bool HoldsWriteHandle =>
            CachedHandle != null && CachedHandleWritable && string.Equals(CachedHandlePath, WriteHostPath, StringComparison.Ordinal);

        private SafeFileHandle AcquireWriteHandle()
        {
            if (HoldsWriteHandle)
                return CachedHandle;

            EnsureWriteStore(true);
            CloseCachedHandle();
            CachedHandle = File.OpenHandle(WriteHostPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, ShareMode);
            CachedHandlePath = WriteHostPath;
            CachedHandleWritable = true;
            CachedHandleReadable = true;
            return CachedHandle;
        }

        /// <summary>
        /// Settles both store probes with one host open, as NT does with the open itself, and keeps the handle for
        /// the queries and reads that follow. Hosts that cannot answer this way leave the probes to run by path.
        /// </summary>
        public void OpenForLookup(bool ReadData)
        {
            lock (HandleLock)
            {
                int Version = Volatile.Read(ref VfsProbeVersion);
                WriteLookupKind = GeneralHelper.IO.HostEntryKind.Unknown;
                ReadLookupKind = GeneralHelper.IO.HostEntryKind.Unknown;
                LookupVersion = Version;

                if (!TryOpenStore(WriteHostPath, ReadData, out GeneralHelper.IO.HostEntryKind Kind, out bool IsFile, out bool IsDirectory, out FileAttributes Attributes))
                    return;

                WriteLookupKind = Kind;
                WriteProbeIsFile = IsFile;
                WriteProbeIsDirectory = IsDirectory;
                WriteProbeAttributes = Attributes;
                WriteProbeVersion = Version;
                if (IsFile || IsDirectory)
                    return;

                if (!string.Equals(ReadHostPath, WriteHostPath, StringComparison.Ordinal)
                    && !TryOpenStore(ReadHostPath, ReadData, out Kind, out IsFile, out IsDirectory, out Attributes))
                    return;

                ReadLookupKind = Kind;
                ReadProbeIsFile = IsFile;
                ReadProbeIsDirectory = IsDirectory;
                ReadProbeAttributes = Attributes;
                ReadProbeVersion = Version;
            }
        }

        /// <summary>
        /// Whether the guest path's parent directory exists, as the lookup open found it in either store. Null
        /// when that open could not tell.
        /// </summary>
        public bool? KnownParentExists
        {
            get
            {
                if (LookupVersion != Volatile.Read(ref VfsProbeVersion))
                    return null;

                if (WriteLookupKind == GeneralHelper.IO.HostEntryKind.Missing)
                    return true;

                if (WriteLookupKind != GeneralHelper.IO.HostEntryKind.MissingPath)
                    return null;

                return ReadLookupKind switch
                {
                    GeneralHelper.IO.HostEntryKind.Missing => true,
                    GeneralHelper.IO.HostEntryKind.MissingPath => false,
                    _ => null
                };
            }
        }

        private bool WriteParentKnownToExist =>
            LookupVersion == Volatile.Read(ref VfsProbeVersion)
            && (WriteLookupKind == GeneralHelper.IO.HostEntryKind.Missing || WriteLookupKind == GeneralHelper.IO.HostEntryKind.File);

        /// <summary>
        /// Returns the memoized probe of the VFS write copy while nothing has reshaped the sandbox since.
        /// </summary>
        public bool TryGetCurrentWriteProbe(out bool IsFile, out bool IsDirectory, out FileAttributes Attributes)
        {
            IsFile = WriteProbeIsFile;
            IsDirectory = WriteProbeIsDirectory;
            Attributes = WriteProbeAttributes;
            return WriteProbeVersion == Volatile.Read(ref VfsProbeVersion);
        }

        private bool TryOpenStore(string HostPath, bool ReadData, out GeneralHelper.IO.HostEntryKind Kind, out bool IsFile, out bool IsDirectory, out FileAttributes Attributes)
        {
            IsFile = false;
            IsDirectory = false;
            Attributes = 0;
            Kind = GeneralHelper.IO.HostEntryKind.Unknown;
            if (string.IsNullOrWhiteSpace(HostPath))
                return true;

            Kind = GeneralHelper.IO.TryOpenHostEntry(HostPath, ReadData, out SafeFileHandle Handle, out Attributes);
            if (Kind == GeneralHelper.IO.HostEntryKind.Unknown)
                return false;

            IsFile = Kind == GeneralHelper.IO.HostEntryKind.File;
            IsDirectory = Kind == GeneralHelper.IO.HostEntryKind.Directory;
            if (Handle != null)
            {
                CloseCachedHandle();
                CachedHandle = Handle;
                CachedHandlePath = HostPath;
                CachedHandleWritable = false;
                CachedHandleReadable = ReadData && IsFile;
            }

            return true;
        }

        private void CloseCachedHandle(bool Later = false)
        {
            if (Later)
                GeneralHelper.IO.CloseHandleLater(CachedHandle);
            else
                CachedHandle?.Dispose();

            CachedHandle = null;
            CachedHandlePath = null;
            CachedHandleWritable = false;
            CachedHandleReadable = false;
        }

        protected override void Dispose(bool disposing)
        {
            lock (HandleLock)
            {
                CloseCachedHandle(true);
            }

            base.Dispose(disposing);
        }

        private void EnsureWriteStore(bool CopyExisting)
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                throw new UnauthorizedAccessException("No Windows VFS write path is available.");

            if (File.Exists(WriteHostPath))
                return;

            if (Directory.Exists(WriteHostPath))
                throw new UnauthorizedAccessException("The Windows VFS write path is a directory.");

            EnsureWriteParentExists();

            if (CopyExisting && !IsSamePath(ReadHostPath, WriteHostPath) && !string.IsNullOrWhiteSpace(ReadHostPath) && File.Exists(ReadHostPath))
            {
                using FileStream Source = new FileStream(ReadHostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using FileStream Destination = new FileStream(WriteHostPath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                Source.CopyTo(Destination, CopyBufferSize);
                DropStoreProbes();
                return;
            }

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            DropStoreProbes();
        }

        private void EnsureWriteParentExists()
        {
            string Parent = Path.GetDirectoryName(WriteHostPath);
            if (string.IsNullOrEmpty(Parent))
                throw new DirectoryNotFoundException(WriteHostPath);

            Directory.CreateDirectory(Parent);
        }

        private static void ValidateBuffer(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            if (offset < 0 || count < 0 || offset > buffer.Length - count)
                throw new ArgumentOutOfRangeException();
        }

        private static bool IsSamePath(string A, string B)
        {
            if (string.IsNullOrWhiteSpace(A) || string.IsNullOrWhiteSpace(B))
                return false;

            try
            {
                string FullA = Path.GetFullPath(A);
                string FullB = Path.GetFullPath(B);
                return string.Equals(FullA, FullB, GeneralHelper.IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            }
            catch
            {
                return string.Equals(A, B, GeneralHelper.IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            }
        }
    }
}
